import Foundation
import Security
import LocalAuthentication

/// How `MacPasskeySigner.sign` failed. Each outcome is distinct.
public enum MacPasskeySignerError: Error {
    /// The person's cancel, the system's, or `cancel()` from the sheet. No signature; the extension sends M4.
    case cancelled(LAError)
    /// A hold stood when the door read the holds, before the first signature: no scope opened, no signature, M4 only.
    case held(holdId: String)
    /// The high-assurance key is not found or not accessible in the group (`errSecItemNotFound`,
    /// `errSecInteractionNotAllowed`, `errSecMissingEntitlement`). Never reported: M4 only.
    case keyUnavailable(OSStatus)
    /// The high-assurance signature refused with a measured key-unusable shape: the extension reports it (M5).
    case keyUnusable(KeyUnusableShape)
    /// The site closure threw, or any other failure, an ordinary -1 (a wrong finger) and a lockout included.
    case hostFailed(Error)
}

/// The one public wrapper over the SDK's scoped signing door for the Mac passkey ceremony: one Touch ID, two
/// signatures on one context. `keys` is a `KeychainKeys` over the app's group; it holds no storage and no core.
/// One `sign` per instance; its scope id is fresh per instance and never reused.
public final class MacPasskeySigner {
    private let keys: KeychainKeys
    private let holds: MacPasskeyHoldStore
    private let scopeId = UUID().uuidString
    private let lock = NSLock()
    private var started = false
    private var cancelled = false
    private var finished = false

    /// Statuses that mean "the key is not here, or this process may not use it".
    static let unavailableStatuses: Set<OSStatus> = [errSecItemNotFound, errSecInteractionNotAllowed,
                                                     errSecMissingEntitlement]

    /// `holds` is the store the door reads before its first signature; the default reads every group this process
    /// may use.
    public init(keys: KeychainKeys, holds: MacPasskeyHoldStore = MacPasskeyHoldStore()) {
        self.keys = keys
        self.holds = holds
    }

    /// The scope id this signer opens (tests).
    var scope: String { scopeId }

    /// One Touch ID: reads the holds and throws `.held` if one stands; opens a fresh scope (`allowed: 2`) and evaluates
    /// it; runs `site` on its live context (with `interactionNotAllowed` set, so an uncovered signature fails rather
    /// than prompts) for the possession signature over the canonical; signs `prepared.kbSigningInput` with the
    /// high-assurance key on the same context; closes the scope on every path. `possession` is whatever `site`
    /// returns, unchanged: the host converts its DER signature to raw r||s before returning it.
    public func sign(_ prepared: MacPasskeyPrepared, site: (LAContext) throws -> Data) throws -> MacPasskeySignatures {
        lock.lock()
        guard !started else {
            lock.unlock()
            throw MacPasskeySignerError.hostFailed(KeychainKeysError.invalidInput("a MacPasskeySigner signs once"))
        }
        started = true
        let cancelledBefore = cancelled
        lock.unlock()
        defer {
            keys.endScope(scopeId)
            lock.lock(); finished = true; lock.unlock()
        }
        if cancelledBefore { throw MacPasskeySignerError.cancelled(LAError(.appCancel)) }

        // The door's guard (4.2): before the scope, its evaluation and both signatures.
        let standing: String?
        do { standing = try holds.standingHoldId() } catch { throw MacPasskeySignerError.hostFailed(error) }
        if let standing { throw MacPasskeySignerError.held(holdId: standing) }

        let scope = SignScope.transaction(id: scopeId, allowedSignatures: 2, reason: prepared.reason)
        var siteError: Error?
        var evaluationError: Error?
        let possession: Data
        do {
            possession = try keys.signInHostScope(scope, evaluationFailed: { evaluationError = $0 }) { context in
                context.interactionNotAllowed = true
                do { return try site(context) } catch { siteError = error; throw error }
            }
        } catch {
            throw classify(error, siteError: siteError, evaluationError: evaluationError, capture: nil)
        }

        let capture = KeychainKeys.SignFailureCapture()
        let kbJwt: Data
        do {
            kbJwt = try keys.sign(usage: "high-assurance", data: Data(prepared.kbSigningInput.utf8), scope: scope,
                                  promptText: nil, capture: capture)
        } catch {
            throw classify(error, siteError: nil, evaluationError: nil, capture: capture)
        }
        return MacPasskeySignatures(possession: possession, kbJwt: kbJwt)
    }

    /// Withdraws the prompt of a `sign` in flight, from any thread: `endScope` on this signer's scope id, which
    /// invalidates its context and so cancels its evaluation; `sign` then throws `.cancelled`. Before `sign`, the
    /// later `sign` throws `.cancelled` with no prompt. A second `cancel`, or one after `sign` returned, does nothing.
    public func cancel() {
        lock.lock()
        guard !cancelled, !finished else { lock.unlock(); return }
        cancelled = true
        lock.unlock()
        keys.endScope(scopeId)
    }

    private var wasCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    /// The error mapping. The destructive classification reads the platform error itself
    /// (`KeyUnusableShape(error:)`, which asks `isKeyUnusableShape`), never the SDK's typed mapping: its comparison is
    /// `unknown` in this process and would hide the shape under `signingFailed`.
    private func classify(_ error: Error, siteError: Error?, evaluationError: Error?,
                          capture: KeychainKeys.SignFailureCapture?) -> MacPasskeySignerError {
        if wasCancelled {
            if let la = evaluationError.flatMap(Self.cancelError) { return .cancelled(la) }
            return .cancelled(LAError(.appCancel))
        }
        if let siteError { return .hostFailed(siteError) }
        if let evaluationError {
            if let la = Self.cancelError(evaluationError) { return .cancelled(la) }
            return .hostFailed(evaluationError)
        }
        if let platformError = capture?.platformError {
            if let shape = KeyUnusableShape(error: platformError) { return .keyUnusable(shape) }
            if let la = Self.cancelError(platformError) { return .cancelled(la) }
            let ns = platformError as Error as NSError
            if ns.domain == NSOSStatusErrorDomain, Self.unavailableStatuses.contains(OSStatus(ns.code)) {
                return .keyUnavailable(OSStatus(ns.code))
            }
            return .hostFailed(platformError)
        }
        if case KeychainKeysError.keyNotFound = error {
            return .keyUnavailable(capture?.lookupStatus ?? errSecItemNotFound)
        }
        return .hostFailed(error)
    }

    /// A withdrawn prompt as the `LAError` the extension surfaces: LocalAuthentication's own cancel codes unchanged,
    /// the keychain's and CryptoTokenKit's user cancel as `.userCancel`. Nil for anything else.
    static func cancelError(_ error: Error) -> LAError? {
        let ns = error as NSError
        if ns.domain == LAErrorDomain {
            let codes: [LAError.Code] = [.userCancel, .systemCancel, .appCancel, .invalidContext]
            guard codes.map(\.rawValue).contains(ns.code) else { return nil }
            return error as? LAError ?? LAError(LAError.Code(rawValue: ns.code)!)
        }
        if KeychainKeys.isWithdrawal(unsafeBitCast(ns, to: CFError.self)) { return LAError(.userCancel) }
        return nil
    }
}
