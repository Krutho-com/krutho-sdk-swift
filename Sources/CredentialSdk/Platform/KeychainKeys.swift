import Foundation
import Security
import CryptoKit
import LocalAuthentication

/// P-256 key generation + signing via the Secure Enclave (`SecKey`).
///
/// **No silent downgrade**: the `.secureEnclave` backing (the production
/// default) can only ever produce a Secure Enclave key or throw a typed
/// `KeychainKeysError`. It never falls back to a weaker key. This mirrors
/// a filed Android defect (`AndroidPlatform.kt`'s
/// `catch (e: InvalidAlgorithmParameterException) { generateKeyPairNoAuth(...) }`)
/// that mints a no-auth key still labelled high-assurance, undetectable
/// downstream — a failed hardware/auth path must throw, never re-label a
/// weaker key.
///
/// **Test fallback**: the CryptoKit in-memory fallback stays so the SPM
/// xctest bundle (no Keychain entitlements) keeps running, but it is only
/// reachable when a caller explicitly constructs
/// `KeychainKeys(tagPrefix:, backing: .insecureInMemoryTestOnly)`. Keys are
/// held in a per-prefix static dictionary of `P256.Signing.PrivateKey`
/// instances so generateKeyPair/sign still works end-to-end in tests.
/// Production app-hosted paths use the real Secure Enclave.
public final class KeychainKeys {

    private let tagPrefix: String
    private let backing: KeyBacking
    /// The keychain access group every key item is created in and looked up, updated and deleted under
    /// (`kSecAttrAccessGroup`). Nil, the default, adds no group: the keychain uses the process's first group, as before.
    /// Lets a Mac app and its passkey extension share one high-assurance key.
    private let accessGroup: String?

    /// `SecItemDelete`, replaceable so tests can drive the delete path's
    /// status handling without a keychain.
    var deleteItem: (CFDictionary) -> OSStatus = SecItemDelete

    /// `SecItemCopyMatching`, replaceable so tests can see the queries the signing lookup and the biometric-label
    /// read make.
    var copyItem: (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus = SecItemCopyMatching

    /// `SecKeyCreateRandomKey`, replaceable so tests can prove creation does
    /// not run after a failed delete.
    var createRandomKey: (CFDictionary, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey? = SecKeyCreateRandomKey

    /// Reads the enrolled biometric set (`readBiometricSet`); replaceable so tests can give a key a recorded set and
    /// then change it. In-memory backing reads nothing by default.
    var readCurrentBiometricSet: (BiometricStateSource?) -> BiometricSetRecord?

    /// Test seam: with `.insecureInMemoryTestOnly` backing, a signature through the signing door (`signRaw`)
    /// fails with the error this returns for the usage, mapped as a Secure Enclave failure would be. Nil in production.
    var inMemorySignFailure: ((String) -> CFError?)?

    /// Reads the set an evaluated context authenticated with (`readBiometricSet(evaluatedBy:)`); replaceable so tests
    /// can tell the evaluated set from today's. In-memory backing reads nothing by default.
    var readEvaluatedBiometricSet: (LAContext) -> BiometricSetRecord?

    /// Runs after each successful signature that evaluated the high-assurance key, with the
    /// three readings that bracket it and whether they agreed: the invalidation check prints it. Nil in production.
    @_spi(EnclaveHarness)
    public var didBracketBiometricSet: ((BiometricSetBracket) -> Void)?

    /// The in-memory fallback is keyed by tag prefix alone: `accessGroup` is ignored in fallback mode, so two stores
    /// with one prefix and different groups share these keys.
    private static var fallbackKeys: [String: P256.Signing.PrivateKey] = [:]
    /// The biometric set recorded with each in-memory key (the keychain label's stand-in); under `fallbackLock`.
    private static var fallbackBiometricSets: [String: BiometricSetRecord] = [:]
    private static let fallbackLock = NSLock()

    public init(
        tagPrefix: String = "com.krutho.credentialsdk.keys",
        backing: KeyBacking = .secureEnclave,
        accessGroup: String? = nil
    ) {
        self.tagPrefix = tagPrefix
        self.backing = backing
        self.accessGroup = accessGroup
        // In-memory test keys read no LocalAuthentication state unless a test supplies one.
        self.readCurrentBiometricSet = backing == .secureEnclave ? Self.readBiometricSet : { _ in nil }
        self.readEvaluatedBiometricSet = backing == .secureEnclave ? { Self.readBiometricSet(evaluatedBy: $0) } : { _ in nil }
    }

    /// What makes two `KeychainKeys` objects one key store: the same tag prefix and backing address the same
    /// keychain items (or the same in-memory dictionary). The Rust engine shares one core between SDKs whose
    /// key stores have the same identity (`RustEngine.engine`).
    var sharingIdentity: String {
        "\(backing == .insecureInMemoryTestOnly ? "memory" : "enclave"):\(tagPrefix)" + (accessGroup.map { "@\($0)" } ?? "")
    }

    /// True when this device/process can create Secure Enclave keys.
    public static var secureEnclaveAvailable: Bool { SecureEnclave.isAvailable }

    private func tag(for usage: String) -> Data {
        Data("\(tagPrefix).\(usage)".utf8)
    }

    // MARK: - Policy

    /// The access control each usage's key is created with.
    ///
    /// High-assurance is biometric-only: `.biometryCurrentSet` admits a
    /// biometric from the set enrolled when the key was created and nothing
    /// else. There is no password or passcode fallback (the earlier
    /// `.userPresence` admitted one), and a change to the
    /// enrolled set makes the key refuse to sign (`key_invalidated`). With no
    /// biometric enrolled, Apple refuses to create the key at all
    /// (`biometry_not_enrolled`).
    ///
    /// Standard-assurance carries no user-auth constraint and signs silently.
    struct KeyPolicy: Equatable {
        let accessFlags: SecAccessControlCreateFlags
        let protection: CFString
    }

    static func policy(forUsage usage: String) throws -> KeyPolicy {
        switch usage {
        case "high-assurance":
            return KeyPolicy(
                accessFlags: [.privateKeyUsage, .biometryCurrentSet],
                protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            )
        case "standard-assurance":
            return KeyPolicy(
                accessFlags: [.privateKeyUsage],
                protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            )
        default:
            throw KeychainKeysError.invalidUsage(usage)
        }
    }

    static func keyAttributes(usage: String, tag: Data, label: String? = nil,
                              accessGroup: String?) throws -> [String: Any] {
        let policy = try policy(forUsage: usage)
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, policy.protection, policy.accessFlags, &acError) else {
            throw KeychainKeysError.keyGenerationFailed(
                "SecAccessControlCreateWithFlags: \(String(describing: acError?.takeRetainedValue()))"
            )
        }
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String:    true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String:  access
        ]
        if let label { privateAttrs[kSecAttrLabel as String] = label }
        var attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String:   privateAttrs
        ]
        #if os(macOS)
        attrs[kSecUseDataProtectionKeychain as String] = true
        #endif
        if let accessGroup { attrs[kSecAttrAccessGroup as String] = accessGroup }
        return attrs
    }

    /// The query that selects this store's key item for `tag`: class, key type, tag, the data-protection keychain on
    /// macOS, and the access group when one is configured. Every lookup, update and delete starts from it.
    func keyQuery(tag: Data) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag
        ]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    // MARK: - Generate / sign

    public func generateKeyPair(usage: String) throws -> String {
        let kid = "\(tagPrefix).\(usage)"
        if case .insecureInMemoryTestOnly = backing {
            return try generateKeyPairFallback(usage: usage, kid: kid)
        }

        guard Self.secureEnclaveAvailable else {
            throw KeychainKeysError.secureEnclaveUnavailable
        }

        let keyTag = tag(for: usage)
        // Clear the slot strictly: signing selects by tag, so a key that
        // survived this delete could come back.
        // Only success or not-found lets creation run. -34018 (no keychain
        // entitlement) keeps the code integrators already handle,
        // key_generation_failed carrying -34018; any other status is
        // key_delete_failed.
        do {
            try deleteKey(tag: keyTag, usage: usage)
        } catch KeychainKeysError.keyDeleteFailed(_, let status) where status == errSecMissingEntitlement {
            throw KeychainKeysError.keyGenerationFailed(
                "delete before creation failed: Error Domain=NSOSStatusErrorDomain Code=\(status)"
            )
        }

        // The enrolled set as LocalAuthentication hashes it today, kept on the key's own keychain item (its label):
        // the evidence a later failure is judged by (`mapSignFailure`). Unreadable: no label, and that key's failures
        // are not read as invalidation until a signature that evaluates the key records the set (`rebaselineBiometricSet`).
        let biometricSet = Self.carriesBiometryCurrentSet(usage) ? readCurrentBiometricSet(nil) : nil
        let attributes = try Self.keyAttributes(usage: usage, tag: keyTag, label: biometricSet?.label,
                                                accessGroup: accessGroup)

        var error: Unmanaged<CFError>?
        guard let privateKey = createRandomKey(attributes as CFDictionary, &error) else {
            throw Self.mapCreateError(error?.takeRetainedValue(), usage: usage)
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeychainKeysError.publicKeyExportFailed("SecKeyCopyPublicKey returned nil")
        }
        return try encodePublicKeyAsJwkJson(publicKey: publicKey, kid: kid)
    }

    /// The finish attempt whose prompt may be withdrawn, and the context of the signature waiting on the
    /// person's biometric with the attempt it was registered under; both guarded by `authLock`.
    private let authLock = NSLock()
    private var activeAttempt: AuthAttempt?
    private var pending: (context: PendingAuthentication, attempt: AuthAttempt?)?

    /// The attempt signatures currently belong to, if any (tests).
    var currentAttempt: AuthAttempt? {
        authLock.lock(); defer { authLock.unlock() }
        return activeAttempt
    }

    /// Signatures from here to `endAttempt` belong to `attempt`: only its `cancel` can withdraw their prompt.
    func beginAttempt(_ attempt: AuthAttempt) {
        authLock.lock(); activeAttempt = attempt; authLock.unlock()
    }

    /// The attempt is over: its cancellation authority ends atomically (a late `cancel` does nothing).
    func endAttempt(_ attempt: AuthAttempt) {
        attempt.end()
        authLock.lock()
        if activeAttempt === attempt { activeAttempt = nil }
        authLock.unlock()
    }

    /// Withdraws `attempt`'s prompt: latches the cancellation (a signature registering later under the attempt
    /// fails before prompting) and invalidates a context already registered under it. Never touches another
    /// attempt's or an unscoped signature. Safe from any thread.
    func cancel(_ attempt: AuthAttempt) {
        guard attempt.markCancelled() else { return }
        authLock.lock()
        let context = pending.flatMap { $0.attempt === attempt ? $0.context : nil }
        authLock.unlock()
        context?.invalidate()
    }

    /// Registers the context a signature is about to prompt on, under the active attempt; refuses when that
    /// attempt is already cancelled, so the prompt never opens.
    func registerPending(_ context: PendingAuthentication) throws {
        authLock.lock(); defer { authLock.unlock() }
        if let attempt = activeAttempt, attempt.isCancelled {
            throw KeychainKeysError.userAuthenticationFailed("finish attempt cancelled before the prompt")
        }
        pending = (context, activeAttempt)
    }

    func clearPending(_ context: PendingAuthentication) {
        authLock.lock()
        if pending?.context === context { pending = nil }
        authLock.unlock()
    }

    /// The keychain signature: finds the key for `usage`, optionally raises the biometric prompt on `context` first
    /// (`evaluateWithReason`; high-assurance only), signs, and returns the raw 64-byte `r || s`. The context is
    /// registered as the pending authentication for the whole call, so `cancel(_:)` on the finish attempt can
    /// withdraw the prompt. A failure of the high-assurance key reads as `keyInvalidated` only when the enrolled
    /// biometric set corroborates it (`mapSignFailure`).
    private func signOnContext(usage: String, message: Data, context: LAContext,
                               evaluateWithReason reason: String?, capture: SignFailureCapture?) throws -> Data {
        try registerPending(context)
        defer { clearPending(context) }

        var query = keyQuery(tag: tag(for: usage))
        query[kSecReturnRef as String] = true
        query[kSecUseAuthenticationContext as String] = context
        var out: AnyObject?
        let status = copyItem(query as CFDictionary, &out)
        guard status == errSecSuccess, let ref = out else {
            capture?.lookupStatus = status
            throw KeychainKeysError.keyNotFound(usage: usage)
        }
        let privateKey = ref as! SecKey

        // The high-assurance key is biometric-only. Raise its prompt on our own context first, so
        // cancel(_:) on the finish attempt can withdraw it (invalidating a context cancels its evaluation; the
        // prompt SecKeyCreateSignature raises by itself did not close on invalidate). The
        // signature below then uses the authenticated context and shows nothing more.
        //
        // The evaluation and the signature are bracketed by three readings of the enrolled
        // set (`BiometricSetBracket`): a fresh context's immediately before the evaluation, the evaluating context's
        // straight after it, and a fresh context's immediately after the signature. Only when all three are readable
        // and identical does the set become the record (`rebaselineBiometricSet`): a change landing before the
        // evaluation, between the evaluation and its reading (were the context's state live rather than a snapshot),
        // or after the signature makes them disagree, and nothing is written.
        var bracketBefore: BiometricSetRecord?
        var bracketEvaluated: BiometricSetRecord?
        var bracketed = false
        if usage == "high-assurance", let reason,
           let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any],
           let accessControlRef = attributes[kSecAttrAccessControl as String] {
            let accessControl = accessControlRef as! SecAccessControl
            bracketBefore = readCurrentBiometricSet(nil)
            let done = DispatchSemaphore(value: 0)
            var evaluationError: Error?
            context.evaluateAccessControl(accessControl, operation: .useKeySign,
                                          localizedReason: reason) { ok, error in
                if !ok { evaluationError = error ?? LAError(.authenticationFailed) }
                done.signal()
            }
            done.wait()
            if let evaluationError {
                let platformError = unsafeBitCast(evaluationError as NSError, to: CFError.self)   // toll-free bridged
                capture?.platformError = platformError
                throw mapSignFailure(platformError, usage: usage)
            }
            bracketEvaluated = readEvaluatedBiometricSet(context)
            bracketed = true
        }

        var error: Unmanaged<CFError>?
        guard let derSig = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            let platformError = error?.takeRetainedValue()
            capture?.platformError = platformError
            throw mapSignFailure(platformError, usage: usage)
        }
        if bracketed {
            finishBracket(usage: usage, before: bracketBefore, evaluated: bracketEvaluated,
                          after: readCurrentBiometricSet(nil))
        }

        return Self.derToRawRS(derSig)
    }

    // MARK: - Scoped signing

    /// A transaction scope's live state: the one `LAContext` its signatures share. Guarded by `scopeLock`, except
    /// `signLock`, which serializes the signatures themselves.
    private final class OpenScope {
        let allowed: UInt32
        let context: LAContext
        /// Signatures claimed (started or finished); a claim past `allowed` is refused.
        var claimed: UInt32 = 0
        /// Signatures that completed. The scope is exhausted when this reaches `allowed`, never on a claim.
        var made: UInt32 = 0
        var evaluated = false
        /// Held for the whole of one signature, so a second call under the same id waits for the first (and for
        /// its prompt) instead of racing it: only one evaluation, and no finish invalidating a context under a
        /// signature still in flight.
        let signLock = NSLock()
        init(allowed: UInt32, context: LAContext) {
            self.allowed = allowed
            self.context = context
        }
    }

    private let scopeLock = NSLock()
    private var openScopes: [String: OpenScope] = [:]
    /// Scope ids that ended by `endScope`, by using every allowed signature, or by an error after a signature was
    /// made, oldest first. A signature under one of them fails: a closed scope never signs again. A scope that
    /// ended on an error with no signature made is not here, so the approval can be tried again on a fresh
    /// context (and a fresh biometric).
    ///
    /// Bounded to `closedScopeMemory` ids, oldest forgotten first. That bound is safe only because the core never
    /// reuses a scope id: it opens one id (the handle text) per approval attempt, and a retry under the same id
    /// happens only after an error with no signature made. An id older than the last 256 closed scopes is no
    /// longer remembered as closed.
    private var closedScopes: [String] = []
    private static let closedScopeMemory = 256

    /// Makes the `LAContext` a scope uses; replaceable so a test can count `invalidate()` calls.
    var makeContext: () -> LAContext = { LAContext() }

    /// Test seam: runs inside a transaction signature once it holds the scope's sign lock, before it signs, so a
    /// test can hold a signature in flight and run another call against the same id. Nil in production.
    var willSignInScope: (() -> Void)?

    /// Test seam: runs with a transaction scope's id and the words its prompt shows (the host's approval
    /// prompt text where `promptText` gives one, else the scope's reason) at the one point its prompt is decided,
    /// the first signature under the id, whether that signature is the SDK's (`sign`) or the host's
    /// (`signInHostScope`), and whatever the backing (software keys evaluate nothing, so this is where a test reads
    /// the words Face ID would show). Nil in production.
    ///
    /// Open through `@_spi(EnclaveHarness)` so a harness can count the scope's prompts.
    @_spi(EnclaveHarness)
    public var willPromptForScope: ((_ id: String, _ reason: String) -> Void)?

    /// Test seam: runs after each signature `sign(usage:data:scope:)` makes under a transaction scope, with the
    /// scope's id and allowed count and the bytes signed (the host's signature in `signInHostScope` is the host's own
    /// and does not pass here).
    var didSignInScope: ((_ id: String, _ allowedSignatures: UInt32, _ data: Data) -> Void)?

    /// Test seam: runs in `abortScope` once it has found a live scope, just before it waits on that scope's sign
    /// lock. A test uses it to know the aborting call has reached the wait. Nil in production.
    var willAbortLiveScope: (() -> Void)?

    /// Signs `data` with the key for `usage` in `scope`: ECDSA P-256 over SHA-256, the raw 64-byte `r || s`.
    ///
    /// - `.silent` is the standard-assurance key: no prompt.
    /// - `.transaction` is the high-assurance key. The first signature under an `id` opens one `LAContext`
    ///   (`localizedFallbackTitle` empty: no password fallback), evaluates the key's access control on it with
    ///   `reason`, and signs; the context then serves up to `allowedSignatures` signatures under that `id` and is
    ///   invalidated when the last one is made, on any error, or at `endScope(_:)`. A signature past the count, or
    ///   after the scope ended, throws `scope_closed` and raises no prompt. An error after at least one signature
    ///   was made closes the id for good; an error with none made lets the same id try again on a fresh context.
    ///   That holds for every error under the id, a refused call (a bad usage or count, a claim past the count)
    ///   as much as a failed signature: the existing context is invalidated before the error leaves.
    ///
    /// A usage that does not fit its scope (high-assurance with `.silent`, standard with `.transaction`) throws
    /// `invalid_input`. The count covers the signatures made through this method; a host that signs another key on
    /// the same context itself is outside it.
    ///
    /// Not host API: the raw signature sits below the core's invalidation guard. The adapter conformance
    /// lives in this module; `@_spi(EnclaveHarness)` opens it to the EnclaveCheck and InvalidationCheckiOS harnesses
    /// only (they measure the SDK's signing door on hardware).
    ///
    /// `promptText` (SDK v2: the host's approval prompt text) gives the words the prompt shows in place of the
    /// scope's reason. It is called with the scope's id and reason only where a prompt is raised (the scope's first
    /// signature), and its answer changes nothing else: not the bytes signed, not the allowed count, not the scope.
    ///
    /// Errors are `KeychainKeysError`; `credentialSdkError` maps them to the public `CredentialSdkError`.
    @_spi(EnclaveHarness)
    public func sign(usage: String, data: Data, scope: SignScope,
              promptText: ((_ id: String, _ reason: String) -> String)? = nil) throws -> Data {
        try sign(usage: usage, data: data, scope: scope, promptText: promptText, capture: nil)
    }

    /// What a failed signature saw before `mapSignFailure` typed it: the platform's own error and the key lookup's
    /// status. `MacPasskeySigner` classifies from these, because the typed error keeps only a description and its
    /// `keyInvalidated` needs a comparison this process may not be able to make.
    final class SignFailureCapture {
        var platformError: CFError?
        var lookupStatus: OSStatus?
    }

    /// `sign(usage:data:scope:promptText:)`, recording what a failure saw in `capture`.
    func sign(usage: String, data: Data, scope: SignScope,
              promptText: ((_ id: String, _ reason: String) -> String)?,
              capture: SignFailureCapture?) throws -> Data {
        switch scope {
        case .silent:
            _ = try Self.policy(forUsage: usage)
            guard usage == "standard-assurance" else {
                throw KeychainKeysError.invalidInput("a \(usage) signature needs a transaction scope")
            }
            let context = makeContext()
            defer { context.invalidate() }
            return try signRaw(usage: usage, message: data, context: context, evaluateWithReason: nil,
                               capture: capture)

        case .transaction(let id, let allowed, let reason):
            // Every error under a transaction id runs the scope's cleanup (`abortScope` before the claim,
            // `finishSignature` after it), so an error never leaves a live context behind it.
            let open: OpenScope
            do {
                _ = try Self.policy(forUsage: usage)
                guard usage == "high-assurance" else {
                    throw KeychainKeysError.invalidInput("a transaction scope signs with the high-assurance key, not \(usage)")
                }
                guard allowed > 0 else {
                    throw KeychainKeysError.invalidInput("a transaction scope permits at least one signature")
                }
                open = try claimSignature(id: id, allowed: allowed)
            } catch {
                abortScope(id: id)
                throw error
            }
            open.signLock.lock()
            defer { open.signLock.unlock() }
            // Waited for any signature ahead of us: if that one ended the scope, this one is refused.
            let evaluate = try beginSignature(id: id, open: open)
            var made = false
            defer { finishSignature(id: id, open: open, made: made) }
            let shown = evaluate ? (promptText?(id, reason) ?? reason) : reason
            if evaluate { willPromptForScope?(id, shown) }
            willSignInScope?()
            let rawRS = try signRaw(usage: usage, message: data, context: open.context,
                                    evaluateWithReason: evaluate ? shown : nil, capture: capture)
            made = true
            didSignInScope?(id, allowed, data)
            return rawRS
        }
    }

    // MARK: - The host's signature inside a transaction scope

    /// Runs `body` with the live `LAContext` of the transaction scope `scope`, as one of that scope's allowed
    /// signatures: the mdoc host callback (`CredentialSdk.issueMdoc(... hostProof:)`), where the host signs its own
    /// mdoc key on the context and the SDK's high-assurance signature that follows reuses it, so the person is
    /// prompted once.
    ///
    /// The first signature under the id evaluates the context, this one included: here with
    /// `.deviceOwnerAuthenticationWithBiometrics` and the scope's reason, the evaluation today's mdoc ceremony makes
    /// (in SDK v1 the host evaluated a context that way and lent it to the SDK). `body` therefore receives an evaluated context,
    /// and the SDK's own signature after it signs on that context without a second evaluation.
    ///
    /// `body` counts as one signature toward `allowedSignatures` when it returns, whatever it signed: what the host
    /// does with the context inside `body` is outside the count (the in-scope residual). An error
    /// from `body`, or from the evaluation, is an error with no signature made: the context is invalidated and the id
    /// left free, as `sign(usage:data:scope:)` leaves it. A scope id that is closed, or a claim past the count,
    /// throws `scope_closed` before any prompt. `body` must not sign through this `KeychainKeys` under the same id:
    /// it runs holding the scope's sign lock.
    ///
    /// With `.insecureInMemoryTestOnly` backing there is no biometric: the context is handed over unevaluated (unless
    /// a test sets `evaluatesHostScopeInMemory`).
    ///
    /// `evaluationFailed` receives the LocalAuthentication error itself when the evaluation fails, before it is mapped
    /// to `user_auth_failed`: the mdoc host tells the person's cancel from the system's by it, as it did when it
    /// evaluated its own context.
    ///
    /// `promptText` is `sign(usage:data:scope:promptText:)`'s: the prompt's words in place of the scope's reason.
    ///
    /// Not host API: `@_spi(EnclaveHarness)` opens it to the invalidation check only, which measures the SDK's
    /// signature on a pre-evaluated scope after the enrolled set changed.
    @_spi(EnclaveHarness)
    public func signInHostScope<T>(_ scope: SignScope, promptText: ((_ id: String, _ reason: String) -> String)? = nil,
                            evaluationFailed: ((Error) -> Void)? = nil,
                            _ body: (LAContext) throws -> T) throws -> T {
        guard case .transaction(let id, let allowed, let reason) = scope else {
            throw KeychainKeysError.invalidInput("the host signs inside a transaction scope")
        }
        scopeLock.lock(); hostScopeId = id; scopeLock.unlock()
        let open: OpenScope
        do {
            guard allowed > 0 else {
                throw KeychainKeysError.invalidInput("a transaction scope permits at least one signature")
            }
            open = try claimSignature(id: id, allowed: allowed)
        } catch {
            abortScope(id: id)
            throw error
        }
        open.signLock.lock()
        defer { open.signLock.unlock() }
        let evaluate = try beginSignature(id: id, open: open)
        var made = false
        defer { finishSignature(id: id, open: open, made: made) }
        let shown = evaluate ? (promptText?(id, reason) ?? reason) : reason
        if evaluate { willPromptForScope?(id, shown) }
        var evaluates = evaluatesHostScopeInMemory
        if case .secureEnclave = backing { evaluates = true }
        if evaluate, evaluates {
            try evaluateBiometric(on: open.context, reason: shown, failed: evaluationFailed)
        }
        let result = try body(open.context)
        made = true
        return result
    }

    private var hostScopeId: String?

    /// The id of the last scope `signInHostScope` joined (tests).
    var lastHostScopeId: String? {
        scopeLock.lock(); defer { scopeLock.unlock() }
        return hostScopeId
    }

    /// Test seam: `signInHostScope` evaluates its context under `.insecureInMemoryTestOnly` backing too, so a test's
    /// `makeContext` can answer the evaluation (a cancel, for instance). False in production.
    var evaluatesHostScopeInMemory = false

    /// One biometric evaluation on `context`, withdrawable through the active attempt (`cancel(_:)`). `failed` sees
    /// the evaluation's own error before it is mapped.
    private func evaluateBiometric(on context: LAContext, reason: String, failed: ((Error) -> Void)? = nil) throws {
        try registerPending(context)
        defer { clearPending(context) }
        let done = DispatchSemaphore(value: 0)
        var evaluationError: Error?
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
            if !ok { evaluationError = error ?? LAError(.authenticationFailed) }
            done.signal()
        }
        done.wait()
        if let evaluationError {
            failed?(evaluationError)
            // A policy evaluation, not the key's access control: any enrolled biometric passes it, a new one too, so
            // its failure says nothing about the key. The SDK's signature on this context afterwards (signRaw, no
            // evaluation of its own) goes through the corroborated mapping.
            throw Self.uncorroboratedSignMapping(unsafeBitCast(evaluationError as NSError, to: CFError.self),
                                                 usage: "high-assurance")
        }
    }

    /// Closes the transaction scope `id`: invalidates the context it holds, whether or not every allowed
    /// signature was made, and refuses any later signature under `id`. An id with no open scope is remembered as
    /// closed too, so a late signature under it fails rather than prompting afresh.
    ///
    /// This is `KeyCustody.end_scope`. Open to the harnesses through the same SPI as
    /// `sign(usage:data:scope:)`, so a harness can close its scope on every path. Safe from any thread.
    @_spi(EnclaveHarness)
    public func endScope(_ id: String) {
        scopeLock.lock()
        let open = openScopes.removeValue(forKey: id)
        rememberClosed(id)
        scopeLock.unlock()
        open?.context.invalidate()
    }

    /// True while a scope under `id` holds a live context (tests and harness diagnostics).
    @_spi(EnclaveHarness)
    public func isScopeOpen(_ id: String) -> Bool {
        scopeLock.lock(); defer { scopeLock.unlock() }
        return openScopes[id] != nil
    }

    private func signRaw(usage: String, message: Data, context: LAContext,
                         evaluateWithReason reason: String?, capture: SignFailureCapture? = nil) throws -> Data {
        if case .insecureInMemoryTestOnly = backing {
            // The Secure Enclave path's order, with no real evaluation: only a signature that evaluates is bracketed
            // (the reading before, the evaluating context's, the reading after the signature).
            let evaluates = reason != nil && usage == "high-assurance"
            let before = evaluates ? readCurrentBiometricSet(nil) : nil
            let evaluated = evaluates ? readEvaluatedBiometricSet(context) : nil
            if let error = inMemorySignFailure?(usage) {
                capture?.platformError = error
                throw mapSignFailure(error, usage: usage)
            }
            let signature: Data
            do {
                signature = try signFallback(usage: usage, message: message)
            } catch KeychainKeysError.keyNotFound(let missing) {
                capture?.lookupStatus = errSecItemNotFound
                throw KeychainKeysError.keyNotFound(usage: missing)
            }
            if evaluates {
                finishBracket(usage: usage, before: before, evaluated: evaluated, after: readCurrentBiometricSet(nil))
            }
            return signature
        }
        return try signOnContext(usage: usage, message: message, context: context, evaluateWithReason: reason,
                                 capture: capture)
    }

    /// Claims one signature against scope `id`, opening it (one fresh context) on the first claim.
    private func claimSignature(id: String, allowed: UInt32) throws -> OpenScope {
        scopeLock.lock(); defer { scopeLock.unlock() }
        if closedScopes.contains(id) {
            throw KeychainKeysError.scopeClosed(id: id)
        }
        let open: OpenScope
        if let existing = openScopes[id] {
            open = existing
        } else {
            let context = makeContext()
            context.localizedFallbackTitle = ""
            open = OpenScope(allowed: allowed, context: context)
            openScopes[id] = open
        }
        guard open.claimed < open.allowed else {
            throw KeychainKeysError.scopeClosed(id: id)
        }
        open.claimed += 1
        return open
    }

    /// Under `signLock`: confirms `open` is still the live scope for `id` (an earlier signature or `endScope` may
    /// have ended it while this one waited) and reports whether this signature must evaluate the key's access
    /// control, which exactly one signature per scope does.
    private func beginSignature(id: String, open: OpenScope) throws -> Bool {
        scopeLock.lock(); defer { scopeLock.unlock() }
        guard openScopes[id] === open else {
            // Gone: a claim made on a scope that ended while this one waited. Its context is already invalidated.
            throw KeychainKeysError.scopeClosed(id: id)
        }
        let evaluate = !open.evaluated
        if evaluate { open.evaluated = true }
        return evaluate
    }

    /// Run in `sign`'s `defer`. A signature that completed counts toward the scope, and the last allowed one
    /// invalidates the context and remembers the id as closed. An error invalidates the context and forgets the
    /// scope: the id is remembered as closed if any signature was already made under it (a retry would sign past
    /// the count), and not otherwise (a retry opens a new scope on a fresh context, and a fresh biometric).
    private func finishSignature(id: String, open: OpenScope, made: Bool) {
        scopeLock.lock()
        let current = openScopes[id] === open
        var invalidate = false
        if made { open.made += 1 }
        if current {
            if made && open.made >= open.allowed {
                openScopes.removeValue(forKey: id)
                rememberClosed(id)
                invalidate = true
            } else if !made {
                openScopes.removeValue(forKey: id)
                if open.made > 0 { rememberClosed(id) }
                invalidate = true
            }
        }
        scopeLock.unlock()
        if invalidate { open.context.invalidate() }
    }

    /// Cleanup for an error raised before a signature claimed its place (a usage or count that does not fit, a
    /// claim past the allowed count, a closed id). It ends the id's live scope, if there is one: waits out any
    /// signature in flight (so a context is never invalidated under a running prompt), then invalidates the
    /// context and forgets the scope, remembering the id as closed if any signature was made under it. With no
    /// signature made the id stays free to retry on a fresh context. No live scope: nothing to do. A scope the
    /// in-flight signature itself ended is already cleaned up, and is left alone.
    private func abortScope(id: String) {
        scopeLock.lock()
        let live = openScopes[id]
        scopeLock.unlock()
        guard let open = live else { return }
        willAbortLiveScope?()
        open.signLock.lock()
        defer { open.signLock.unlock() }
        scopeLock.lock()
        let current = openScopes[id] === open
        if current {
            openScopes.removeValue(forKey: id)
            if open.made > 0 { rememberClosed(id) }
        }
        scopeLock.unlock()
        if current { open.context.invalidate() }
    }

    /// Callers hold `scopeLock`.
    private func rememberClosed(_ id: String) {
        guard !closedScopes.contains(id) else { return }
        closedScopes.append(id)
        if closedScopes.count > Self.closedScopeMemory {
            closedScopes.removeFirst(closedScopes.count - Self.closedScopeMemory)
        }
    }

    // MARK: - Error mapping

    /// `CryptoTokenKit`'s error domain (`TKErrorDomain`), spelled out so the
    /// mapping stays pure and testable without importing CryptoTokenKit.
    static let cryptoTokenKitDomain = "CryptoTokenKit"

    /// The Apple Keystore (AKS) code carried in `userInfo["AKSError"]` when a
    /// `.biometryCurrentSet` key refuses because the enrolled set changed:
    /// -536362999, 0xE007C009.
    static let aksBiometrySetChanged = -536362999

    /// `TKErrorCodeCanceledByUser` (CryptoTokenKit's TKError.h, macOS 27 SDK): a withdrawal, never invalidation.
    static let cryptoTokenKitCanceledByUser = -4

    // MARK: - The biometric set behind key_invalidated

    /// The set recorded when the key for `usage` was created: its keychain label, or the in-memory stand-in. Nil for
    /// a key made before the record existed, a key with no readable set at creation, or no key. Reads attributes
    /// only, so it never prompts.
    func storedBiometricSet(usage: String) -> BiometricSetRecord? {
        let fullTag = "\(tagPrefix).\(usage)"
        if case .insecureInMemoryTestOnly = backing {
            Self.fallbackLock.lock(); defer { Self.fallbackLock.unlock() }
            return Self.fallbackBiometricSets[fullTag]
        }
        var query = keyQuery(tag: tag(for: usage))
        query[kSecReturnAttributes as String] = true
        var out: AnyObject?
        guard copyItem(query as CFDictionary, &out) == errSecSuccess,
              let attributes = out as? [String: Any],
              let label = attributes[kSecAttrLabel as String] as? String else {
            return nil
        }
        return BiometricSetRecord(label: label)
    }

    /// The recorded set for `usage` against today's, read from the recorded set's source (the newest source when
    /// nothing is recorded, for the transcript). Never prompts.
    @_spi(EnclaveHarness)
    public func biometricSetComparison(usage: String) -> BiometricSetComparison {
        let stored = storedBiometricSet(usage: usage)
        return BiometricSetComparison(stored: stored, current: readCurrentBiometricSet(stored?.source))
    }

    /// After a bracketed signature: reports the three readings to `didBracketBiometricSet` and re-baselines only when
    /// they agree (`BiometricSetBracket.agreed`).
    private func finishBracket(usage: String, before: BiometricSetRecord?, evaluated: BiometricSetRecord?,
                               after: BiometricSetRecord?) {
        let bracket = BiometricSetBracket(before: before, evaluated: evaluated, after: after)
        didBracketBiometricSet?(bracket)
        if let agreed = bracket.agreed { rebaselineBiometricSet(usage: usage, evaluated: agreed) }
    }

    /// After a signature that evaluated the `.biometryCurrentSet` key's own access
    /// control and then signed, with the three bracketing readings in agreement (`finishBracket`): `evaluated`, the
    /// set that evaluation authenticated with, unlocks the key, so it becomes the record when there is none (a key made before the record existed, or when
    /// the set could not be read) or when this app's record differs from it (a major OS update, a change of
    /// source, or a hash that moved while the key still signs, as Apple allows after adding then removing a
    /// finger). Never after a signature on a pre-evaluated scope or a silent one, which proves nothing about the set
    /// (the caller passes no `evaluated` there). A record another app wrote is left alone. Best effort: a failed
    /// write keeps the old record. Never prompts.
    func rebaselineBiometricSet(usage: String, evaluated: BiometricSetRecord) {
        guard Self.carriesBiometryCurrentSet(usage) else { return }
        if let stored = storedBiometricSet(usage: usage), stored.app != evaluated.app || stored == evaluated { return }
        let fullTag = "\(tagPrefix).\(usage)"
        if case .insecureInMemoryTestOnly = backing {
            Self.fallbackLock.lock(); defer { Self.fallbackLock.unlock() }
            if Self.fallbackKeys[fullTag] != nil { Self.fallbackBiometricSets[fullTag] = evaluated }
            return
        }
        let query = keyQuery(tag: tag(for: usage))
        _ = updateItem(query as CFDictionary, [kSecAttrLabel as String: evaluated.label] as CFDictionary)
    }

    /// `SecItemUpdate`, replaceable so tests can see the label write.
    var updateItem: (CFDictionary, CFDictionary) -> OSStatus = SecItemUpdate

    /// A signing failure as a typed error. For a `.biometryCurrentSet` key the enrolled set is compared first, and
    /// only a corroborated change reads as `keyInvalidated` (`mapSignError`).
    private func mapSignFailure(_ error: CFError?, usage: String) -> KeychainKeysError {
        guard Self.carriesBiometryCurrentSet(usage), error != nil else {
            return Self.mapSignError(error, usage: usage)
        }
        return Self.mapSignError(error, usage: usage, biometricSet: biometricSetComparison(usage: usage))
    }

    /// Maps a `SecKeyCreateSignature` failure to a typed error.
    ///
    /// **Invalidation, measured on macOS 27 (a MacBook
    /// Pro):** after a fingerprint was added, a `.biometryCurrentSet` key
    /// refused in 16ms (no sheet) with domain `CryptoTokenKit`, code -3,
    /// `userInfo["AKSError"] = -536362999`. Limits: one run, an ephemeral
    /// (non-persisted) key, macOS only. The persisted-key and iOS behavior are
    /// unmeasured, so only that exact triple maps to `keyInvalidated`; any
    /// other CryptoTokenKit error stays `signingFailed`. The same run showed
    /// that deleting the added fingerprint made the key sign again, so on
    /// macOS 27 the refusal is not permanent.
    ///
    /// **Invalidation, corroborated.**
    /// Measured on macOS 27 (a MacBook):
    /// after a fingerprint was added, the SDK's persisted high-assurance key
    /// refused its access-control evaluation in 9-13ms, no sheet, with
    /// LocalAuthentication -1 "Unsatisfiable constraint.", the key still in
    /// the keychain. An error's shape alone never authorizes the core's
    /// self-revoke (tombstone, key destroyed, unenroll): Apple documents no
    /// error that means "set changed" and nothing else. So a
    /// failure of a `.biometryCurrentSet` key maps to `keyInvalidated` only
    /// when both signals hold: the failure is one of the measured
    /// key-unusable shapes (`isKeyUnusableShape`), and `biometricSet` says the
    /// enrolled set changed: the hash recorded
    /// when the key was created (or last re-baselined after a successful
    /// signature) is readable, today's is readable by the same app from the
    /// same source on the same major OS, and they differ
    /// (`BiometricSetComparison`).
    /// Any other failure (a wrong finger, a lockout, a cancel; `isWithdrawal`)
    /// stays non-destructive whatever the hashes say. Unchanged or unknown keeps the
    /// non-destructive mapping: no record (a key made before this rule, until
    /// its next successful signature re-baselines it), no readable state
    /// (lockout, no biometric enrolled), a major OS update, another app's
    /// record. The CryptoTokenKit -3 shape then becomes `signingFailed`;
    /// everything else maps as below (`uncorroboratedSignMapping`).
    ///
    /// Measured on a MacBook (the enclave invalidation check): the label persisted and
    /// `stateHash` was readable; a failed match (-1 "Application retry limit
    /// exceeded.") and a cancel (-2) left the hash unchanged; after a finger was
    /// added, -1 "Unsatisfiable constraint." and, on a pre-evaluated scope,
    /// CryptoTokenKit -3 AKSError -536362999 came with a changed hash. iOS is
    /// unmeasured.
    ///
    /// **User-auth failures:** LocalAuthentication errors arrive with domain
    /// `com.apple.LocalAuthentication` (`LAErrorDomain`). The earlier check compared the domain against the Swift
    /// type name `"LAError"` and never matched.
    static func mapSignError(_ error: CFError?, usage: String,
                             biometricSet: BiometricSetComparison? = nil) -> KeychainKeysError {
        let shipped = uncorroboratedSignMapping(error, usage: usage)
        guard carriesBiometryCurrentSet(usage), let error else { return shipped }
        if let biometricSet, biometricSet.verdict == .changed, isKeyUnusableShape(error) {
            return .keyInvalidated(usage: usage, detail: "\(String(describing: error)); biometric set: \(biometricSet)")
        }
        // A withdrawn prompt is the person's (or the system's) cancel on every platform shape, CryptoTokenKit's -4
        // included, which the shipped mapping left as `signingFailed`.
        if isWithdrawal(error) { return .userAuthenticationFailed(String(describing: error)) }
        if case .keyInvalidated = shipped {
            let evidence = biometricSet.map { "\($0)" } ?? "not checked"
            return .signingFailed("\(String(describing: error)); not corroborated, biometric set: \(evidence)")
        }
        return shipped
    }

    /// The signing door's mapping of a platform signing error with no biometric-set evidence, for the harness's
    /// tests of its controls (a cancel, a failed match). Not host API.
    @_spi(EnclaveHarness)
    public static func signError(_ error: Error, usage: String) -> KeychainKeysError {
        mapSignError(unsafeBitCast(error as NSError, to: CFError.self), usage: usage)
    }

    /// The mapping SDK v1 shipped, by error shape alone. `mapSignError` starts from it and, for a
    /// `.biometryCurrentSet` key, never lets the shape alone say `keyInvalidated`. A biometric policy evaluation
    /// (`evaluateBiometric`) maps through it directly: its failure says nothing about the key.
    static func uncorroboratedSignMapping(_ error: CFError?, usage: String) -> KeychainKeysError {
        let description = String(describing: error)
        guard let error = error else {
            return .signingFailed(description)
        }
        let code = CFErrorGetCode(error)
        let domain = CFErrorGetDomain(error) as String
        if domain == cryptoTokenKitDomain {
            let userInfo = CFErrorCopyUserInfo(error) as? [String: Any] ?? [:]
            let aks = (userInfo["AKSError"] as? NSNumber)?.intValue
            if code == -3 && aks == aksBiometrySetChanged {
                return .keyInvalidated(usage: usage, detail: description)
            }
            return .signingFailed(description)
        }
        if domain == LAErrorDomain
            || code == Int(errSecUserCanceled)
            || code == Int(errSecAuthFailed) {
            return .userAuthenticationFailed(description)
        }
        return .signingFailed(description)
    }

    /// LocalAuthentication's `NSDebugDescription` on the key-unusable refusal after the enrolled set changed.
    static let unsatisfiableConstraintDescription = "Unsatisfiable constraint."

    /// The refusals measured as "this key cannot be used with the set enrolled now" (a MacBook, macOS 27): LocalAuthentication -1 whose `NSDebugDescription` is exactly
    /// "Unsatisfiable constraint." (the key's own evaluation, no sheet), and CryptoTokenKit -3 with AKSError
    /// -536362999, 0xE007C009 (the signature on a pre-evaluated scope; an ephemeral-key probe too).
    /// Necessary, not sufficient: `keyInvalidated` also needs the corroborated hash change. Every other failure, a
    /// wrong finger (-1 "Application retry limit exceeded."), a lockout (-8), a cancel, stays non-destructive whatever
    /// the hashes say: Apple allows the hash to differ while the key stays usable (a finger added then removed).
    static func isKeyUnusableShape(_ error: CFError) -> Bool {
        let code = CFErrorGetCode(error)
        let domain = CFErrorGetDomain(error) as String
        let userInfo = CFErrorCopyUserInfo(error) as? [String: Any] ?? [:]
        if domain == LAErrorDomain && code == LAError.authenticationFailed.rawValue {
            return userInfo[NSDebugDescriptionErrorKey] as? String == unsatisfiableConstraintDescription
        }
        if domain == cryptoTokenKitDomain && code == -3 {
            return (userInfo["AKSError"] as? NSNumber)?.intValue == aksBiometrySetChanged
        }
        return false
    }

    /// True for a usage whose key policy carries `.biometryCurrentSet` (the high-assurance key).
    static func carriesBiometryCurrentSet(_ usage: String) -> Bool {
        (try? policy(forUsage: usage))?.accessFlags.contains(.biometryCurrentSet) ?? false
    }

    /// A prompt withdrawn rather than a key refused: the person, the system or the app cancelled, or the context was
    /// invalidated. Never read as invalidation, whatever the biometric set says; always
    /// `userAuthenticationFailed`, as LocalAuthentication's own cancel is.
    static func isWithdrawal(_ error: CFError) -> Bool {
        let code = CFErrorGetCode(error)
        let domain = CFErrorGetDomain(error) as String
        if domain == LAErrorDomain {
            return [LAError.userCancel, .systemCancel, .appCancel, .invalidContext].map(\.rawValue).contains(code)
        }
        // TKErrorCodeCanceledByUser, -4 in CryptoTokenKit's TKError.h (macOS 27 SDK).
        if domain == cryptoTokenKitDomain { return code == cryptoTokenKitCanceledByUser }
        return domain == NSOSStatusErrorDomain && code == Int(errSecUserCanceled)
    }

    /// Maps a `SecKeyCreateRandomKey` failure to a typed error.
    ///
    /// **Measured on a Mac with no biometric enrolled:** creating a
    /// `.biometryCurrentSet` key refuses with `errSecAuthFailed` (-25293),
    /// underlying LocalAuthentication -1000 "Failed to get bio database
    /// hash"; `.biometryAny` refused with -25293 over LocalAuthentication -7
    /// "No identities are enrolled". Only the high-assurance key carries a
    /// biometric constraint, so only there does -25293 (or
    /// LocalAuthentication `biometryNotEnrolled`) read as
    /// `biometry_not_enrolled`. iOS creation behavior is unmeasured.
    static func mapCreateError(_ error: CFError?, usage: String) -> KeychainKeysError {
        let description = String(describing: error)
        guard let error = error, usage == "high-assurance" else {
            return .keyGenerationFailed(description)
        }
        let code = CFErrorGetCode(error)
        let domain = CFErrorGetDomain(error) as String
        if (domain == NSOSStatusErrorDomain && code == Int(errSecAuthFailed))
            || (domain == LAErrorDomain && code == LAError.biometryNotEnrolled.rawValue) {
            return .biometryNotEnrolled(description)
        }
        return .keyGenerationFailed(description)
    }

    // MARK: - Keychain helpers

    /// Deletes one key. `errSecSuccess` and `errSecItemNotFound` both mean
    /// the key is gone; any other status throws `keyDeleteFailed`, so a key
    /// that survived is never reported as destroyed.
    private func deleteKey(tag: Data, usage: String) throws {
        let query = keyQuery(tag: tag)
        let status = deleteItem(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainKeysError.keyDeleteFailed(usage: usage, status: status)
        }
    }

    /// Destroys the one key for `usage` under the configured prefix. The core
    /// SDK calls this on `key_invalidated`, before it attempts unenroll, so a
    /// person who restores their old fingerprints cannot sign with the key
    /// again (on macOS 27 the refusal lifts when the set is restored,
    /// as measured). Succeeds silently when the key is already
    /// absent; throws `keyDeleteFailed` when the keychain refuses the delete.
    public func destroy(usage: String) throws {
        if case .insecureInMemoryTestOnly = backing {
            Self.fallbackLock.lock()
            defer { Self.fallbackLock.unlock() }
            Self.fallbackKeys.removeValue(forKey: "\(tagPrefix).\(usage)")
            Self.fallbackBiometricSets.removeValue(forKey: "\(tagPrefix).\(usage)")
            return
        }
        try deleteKey(tag: tag(for: usage), usage: usage)
    }

    /// The RFC 7638 thumbprint of the public key for `usage` (`{"crv","kty","x","y"}`, SHA-256, base64url), read
    /// from the key item without using the private key, so it never prompts. A Mac passkey hold carries the
    /// high-assurance key's, the binding `resolve_mac_passkey_hold` compares with the stored JWK.
    func publicKeyThumbprint(usage: String) throws -> String {
        let x963: Data
        if case .insecureInMemoryTestOnly = backing {
            Self.fallbackLock.lock()
            let key = Self.fallbackKeys["\(tagPrefix).\(usage)"]
            Self.fallbackLock.unlock()
            guard let key else { throw KeychainKeysError.keyNotFound(usage: usage) }
            x963 = key.publicKey.x963Representation
        } else {
            var query = keyQuery(tag: tag(for: usage))
            query[kSecReturnRef as String] = true
            var out: AnyObject?
            guard copyItem(query as CFDictionary, &out) == errSecSuccess, let ref = out,
                  let publicKey = SecKeyCopyPublicKey(ref as! SecKey) else {
                throw KeychainKeysError.keyNotFound(usage: usage)
            }
            var error: Unmanaged<CFError>?
            guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
                throw KeychainKeysError.publicKeyExportFailed(String(describing: error?.takeRetainedValue()))
            }
            x963 = data
        }
        guard let thumbprint = Self.thumbprint(x963: x963) else {
            throw KeychainKeysError.publicKeyExportFailed("expected a 65-byte uncompressed P-256 point")
        }
        return thumbprint
    }

    /// The RFC 7638 thumbprint of an uncompressed P-256 point (`0x04 || x || y`), as the core computes `pkt` and the
    /// stored JWK's (`thumbprint_members`); nil for anything else.
    static func thumbprint(x963: Data) -> String? {
        guard x963.count == 65, x963.first == 0x04 else { return nil }
        let bytes = [UInt8](x963)
        let x = base64UrlNoPad(Data(bytes[1..<33])), y = base64UrlNoPad(Data(bytes[33..<65]))
        let members = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return base64UrlNoPad(Data(SHA256.hash(data: Data(members.utf8))))
    }

    /// Deletes every key under the configured prefix. Test-only, best-effort.
    func deleteAll() {
        try? destroyAll()
    }

    /// Destroys every key under the configured prefix. Invoked by the core SDK
    /// during unenroll. Deletes the high-assurance key first and
    /// stops at the first failure, throwing `keyDeleteFailed`: the
    /// standard-assurance key then stays, so an `unenroll()` retry can still
    /// sign its device JWT. An absent key is success.
    public func destroyAll() throws {
        if case .insecureInMemoryTestOnly = backing {
            Self.fallbackLock.lock()
            defer { Self.fallbackLock.unlock() }
            Self.fallbackKeys = Self.fallbackKeys.filter { !$0.key.hasPrefix(tagPrefix) }
            Self.fallbackBiometricSets = Self.fallbackBiometricSets.filter { !$0.key.hasPrefix(tagPrefix) }
            return
        }
        for usage in ["high-assurance", "standard-assurance"] {
            try deleteKey(tag: tag(for: usage), usage: usage)
        }
    }

    private func encodePublicKeyAsJwkJson(publicKey: SecKey, kid: String) throws -> String {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw KeychainKeysError.publicKeyExportFailed(
                "SecKeyCopyExternalRepresentation failed: \(String(describing: error?.takeRetainedValue()))"
            )
        }
        guard data.count == 65 else {
            throw KeychainKeysError.publicKeyExportFailed(
                "expected 65-byte uncompressed P-256 point, got \(data.count)"
            )
        }
        guard data[0] == 0x04 else {
            throw KeychainKeysError.publicKeyExportFailed("expected 0x04 uncompressed marker")
        }
        let x = data.subdata(in: 1..<33)
        let y = data.subdata(in: 33..<65)
        return try Self.jwkJson(x: x, y: y, kid: kid)
    }

    static func jwkJson(x: Data, y: Data, kid: String) throws -> String {
        let jwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x":   base64UrlNoPad(x),
            "y":   base64UrlNoPad(y),
            "kid": kid,
            "alg": "ES256",
            "use": "sig"
        ]
        let outer = ["publicJwk": jwk]
        guard let bytes = try? JSONSerialization.data(withJSONObject: outer, options: [.sortedKeys]),
              let json = String(data: bytes, encoding: .utf8) else {
            throw KeychainKeysError.publicKeyExportFailed(
                "could not encode public JWK for kid '\(kid)'"
            )
        }
        return json
    }

    static func base64UrlNoPad(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: - CryptoKit fallback

    // The group is ignored here: the fallback is keyed by tag prefix alone (see `fallbackKeys`).

    private func generateKeyPairFallback(usage: String, kid: String) throws -> String {
        let fullTag = "\(tagPrefix).\(usage)"
        let pk = P256.Signing.PrivateKey()
        let biometricSet = Self.carriesBiometryCurrentSet(usage) ? readCurrentBiometricSet(nil) : nil
        Self.fallbackLock.lock()
        Self.fallbackKeys[fullTag] = pk
        Self.fallbackBiometricSets[fullTag] = biometricSet
        Self.fallbackLock.unlock()

        // `x963Representation` is the uncompressed SEC1 form: 0x04 || X || Y,
        // exactly 65 bytes for P-256 on every iOS version. `rawRepresentation`
        // is *not* guaranteed to be x||y — on iOS 26 it is not.
        let x963 = pk.publicKey.x963Representation
        precondition(x963.count == 65, "expected 65-byte x963 P-256 public key, got \(x963.count)")
        precondition(x963[0] == 0x04, "expected 0x04 uncompressed marker")
        let x = x963.subdata(in: 1..<33)
        let y = x963.subdata(in: 33..<65)
        return try Self.jwkJson(x: x, y: y, kid: kid)
    }

    /// The software key for `usage` as its raw 32-byte scalar: `.insecureInMemoryTestOnly` backing only, nil
    /// otherwise or when there is no key (tests: the v1 snapshot keys read back unchanged). Never a Secure Enclave key.
    func softwareKeyRaw(usage: String) -> Data? {
        guard case .insecureInMemoryTestOnly = backing else { return nil }
        Self.fallbackLock.lock(); defer { Self.fallbackLock.unlock() }
        return Self.fallbackKeys["\(tagPrefix).\(usage)"]?.rawRepresentation
    }

    /// Installs a software key for `usage` from its raw scalar: tests that start from a captured v1 snapshot
    /// (`Fixtures/v1-snapshots`). `.insecureInMemoryTestOnly` backing only.
    func installSoftwareKey(usage: String, raw: Data) throws {
        guard case .insecureInMemoryTestOnly = backing else {
            throw KeychainKeysError.invalidInput("a software key can be installed only with in-memory test backing")
        }
        let key = try P256.Signing.PrivateKey(rawRepresentation: raw)
        Self.fallbackLock.lock(); defer { Self.fallbackLock.unlock() }
        Self.fallbackKeys["\(tagPrefix).\(usage)"] = key
    }

    private func signFallback(usage: String, message: Data) throws -> Data {
        let fullTag = "\(tagPrefix).\(usage)"
        Self.fallbackLock.lock()
        let pk = Self.fallbackKeys[fullTag]
        Self.fallbackLock.unlock()
        guard let pk = pk else {
            throw KeychainKeysError.keyNotFound(usage: usage)
        }
        do {
            let sig = try pk.signature(for: message)
            // rawRepresentation is already r||s (64 bytes)
            return sig.rawRepresentation
        } catch {
            throw KeychainKeysError.signingFailed(String(describing: error))
        }
    }

    // MARK: - DER <-> raw r||s

    /// Convert DER-encoded ECDSA signature to raw r||s (each 32 bytes, big-endian).
    static func derToRawRS(_ der: Data) -> Data {
        var pos = 0
        func readByte() -> UInt8 { let b = der[pos]; pos += 1; return b }

        precondition(readByte() == 0x30, "expected SEQUENCE tag")
        var seqLen = Int(readByte())
        if seqLen == 0x81 { seqLen = Int(readByte()) }
        _ = seqLen

        precondition(readByte() == 0x02, "expected INTEGER tag for r")
        var rLen = Int(readByte())
        if rLen == 0x81 { rLen = Int(readByte()) }
        let rBytes = der.subdata(in: pos..<(pos + rLen))
        pos += rLen

        precondition(readByte() == 0x02, "expected INTEGER tag for s")
        var sLen = Int(readByte())
        if sLen == 0x81 { sLen = Int(readByte()) }
        let sBytes = der.subdata(in: pos..<(pos + sLen))

        return bigIntTo32Bytes(rBytes) + bigIntTo32Bytes(sBytes)
    }

    /// Pad or trim a P-256 coordinate to exactly 32 big-endian bytes.
    static func bigIntTo32Bytes(_ bytes: Data) -> Data {
        if bytes.count == 32 { return bytes }
        if bytes.count == 33 && bytes[0] == 0x00 { return bytes.subdata(in: 1..<33) }
        if bytes.count < 32 {
            var padded = Data(count: 32 - bytes.count)
            padded.append(bytes)
            return padded
        }
        return bytes.subdata(in: (bytes.count - 32)..<bytes.count)
    }

    /// Reverse of `derToRawRS`, used only by tests.
    static func rawRStoDer(_ rawRS: Data) -> Data {
        precondition(rawRS.count == 64, "expected 64 bytes raw r||s")

        func encodeInteger(_ coord: Data) -> Data {
            var trimmed = coord
            while trimmed.count > 1 && trimmed[0] == 0x00 {
                trimmed = trimmed.subdata(in: 1..<trimmed.count)
            }
            if trimmed[0] & 0x80 != 0 {
                var prefixed = Data([0x00])
                prefixed.append(trimmed)
                trimmed = prefixed
            }
            var out = Data([0x02, UInt8(trimmed.count)])
            out.append(trimmed)
            return out
        }

        let r = encodeInteger(rawRS.subdata(in: 0..<32))
        let s = encodeInteger(rawRS.subdata(in: 32..<64))
        var seqBody = Data()
        seqBody.append(r)
        seqBody.append(s)

        var out = Data([0x30])
        if seqBody.count < 0x80 {
            out.append(UInt8(seqBody.count))
        } else {
            out.append(0x81)
            out.append(UInt8(seqBody.count))
        }
        out.append(seqBody)
        return out
    }
}

// MARK: - Backing + errors

public enum KeyBacking: Equatable {
    /// Production: keys are created inside the Secure Enclave or the call throws.
    case secureEnclave
    /// Test-only: in-memory CryptoKit keys. NOT hardware-backed, NOT persistent,
    /// NOT user-auth-gated. Never use outside test bundles.
    case insecureInMemoryTestOnly
}

public enum KeychainKeysError: Error, Equatable, LocalizedError {
    case invalidUsage(String)
    case secureEnclaveUnavailable
    case keyGenerationFailed(String)
    case keyNotFound(usage: String)
    case userAuthenticationFailed(String)
    case signingFailed(String)
    case invalidInput(String)
    case publicKeyExportFailed(String)
    /// The high-assurance key exists but the platform refuses it because the
    /// enrolled biometric set changed since the key was created.
    case keyInvalidated(usage: String, detail: String)
    /// A high-assurance key cannot be created: no biometric is enrolled.
    case biometryNotEnrolled(String)
    /// `SecItemDelete` returned a status other than `errSecSuccess` or
    /// `errSecItemNotFound`: the key may still exist. Bridge code
    /// `key_delete_failed`; the detail embeds the status as
    /// `Code=<OSStatus>` so the host's `CredentialSdkError.keyError` carries it.
    case keyDeleteFailed(usage: String, status: OSStatus)
    /// A transaction scope signed past its allowed count, or after it ended
    /// (`endScope`, or its last allowed signature). No prompt was raised and
    /// nothing was signed. Bridge code `scope_closed`.
    case scopeClosed(id: String)

    /// Stable machine-readable code carried across the JS bridge.
    public var bridgeCode: String {
        switch self {
        case .invalidUsage:              return "invalid_usage"
        case .secureEnclaveUnavailable:  return "secure_enclave_unavailable"
        case .keyGenerationFailed:       return "key_generation_failed"
        case .keyNotFound:               return "key_not_found"
        case .userAuthenticationFailed:  return "user_auth_failed"
        case .signingFailed:             return "signing_failed"
        case .invalidInput:              return "invalid_input"
        case .publicKeyExportFailed:     return "public_key_export_failed"
        case .keyInvalidated:            return "key_invalidated"
        case .biometryNotEnrolled:       return "biometry_not_enrolled"
        case .keyDeleteFailed:           return "key_delete_failed"
        case .scopeClosed:               return "scope_closed"
        }
    }

    /// The text after the code (`errorDescription` is `key_error:<code>: <detail>`).
    var detail: String {
        switch self {
        case .invalidUsage(let usage):
            return "unknown key usage '\(usage)'"
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available on this device/process"
        case .keyGenerationFailed(let msg):
            return msg
        case .keyNotFound(let usage):
            return "no private key found for usage '\(usage)'"
        case .userAuthenticationFailed(let msg):
            return msg
        case .signingFailed(let msg):
            return msg
        case .invalidInput(let msg):
            return msg
        case .publicKeyExportFailed(let msg):
            return msg
        case .keyInvalidated(let usage, let msg):
            return "key for usage '\(usage)' refused: the enrolled biometric set changed: \(msg)"
        case .biometryNotEnrolled(let msg):
            return msg
        case .keyDeleteFailed(let usage, let status):
            return "SecItemDelete failed for usage '\(usage)'; the key may still exist: Error Domain=NSOSStatusErrorDomain Code=\(status)"
        case .scopeClosed(let id):
            return "the authentication scope '\(id)' is closed: it has no signature left or it ended"
        }
    }

    public var errorDescription: String? {
        "key_error:\(bridgeCode): \(detail)"
    }

    /// The public error for this failure, mapped from the typed case: the same
    /// result `CredentialSdk.mapKeyError` reaches by parsing the core's message
    /// (`key_error:<code>: <detail>`). `keyInvalidated` carries no `revoked`/`cleanup`/
    /// `retryable` here: those are the core's self-revoke outcome, which the
    /// core adds when it throws its own `KeyInvalidated`.
    public var credentialSdkError: CredentialSdkError {
        switch self {
        case .secureEnclaveUnavailable: return .secureEnclaveUnavailable
        case .userAuthenticationFailed: return .userAuthenticationFailed
        case .biometryNotEnrolled:      return .biometryNotEnrolled
        case .keyInvalidated:           return .keyInvalidated(revoked: nil, cleanupOk: nil, retryable: nil)
        default:
            return .keyError(code: bridgeCode, detail: detail, osStatus: osStatus)
        }
    }

    /// The `OSStatus` the platform reported, when this failure carries one.
    var osStatus: Int32? {
        if case .keyDeleteFailed(_, let status) = self { return status }
        return CredentialSdk.parseKeyError(errorDescription ?? "")?.osStatus
    }
}

/// The authentication scope a signature is made in. Mirrors the
/// core's `SignScope`; the generated callback type converts to it.
///
/// Not host API, like the signing door that takes it (see `KeychainKeys.sign(usage:data:scope:)`): open to the
/// harnesses through `@_spi(EnclaveHarness)`.
@_spi(EnclaveHarness)
public enum SignScope: Equatable {
    /// The standard-assurance key: no prompt.
    case silent
    /// The high-assurance key: one biometric evaluation with `reason` as the
    /// prompt text (informational, not binding), permitting at most
    /// `allowedSignatures` signatures through `KeychainKeys.sign`, after
    /// which the context is invalidated.
    case transaction(id: String, allowedSignatures: UInt32, reason: String)
}
