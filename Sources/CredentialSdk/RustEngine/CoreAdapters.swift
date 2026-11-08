import Foundation
import LocalAuthentication
import CredentialSdkCoreBindings

// SDK v2: the native platform adapters behind the UniFFI callback
// interfaces the Rust core calls. Each wrapper is thin: it converts
// the bindings' value types to the adapter's own and the adapter's typed errors
// to `PlatformError`, and adds no behaviour of its own.
//
// Wrappers, not extensions on the adapters: `KeychainKeys` is public and the
// callback protocols are public, so a conformance declared on `KeychainKeys`
// would have to make its witnesses public, `sign` among them, and raw signing
// below the core's invalidation guard is not host API. These classes are
// internal, so their witnesses are too.
//
// The bindings declare several names this module also declares (`Usage`,
// `SignScope`, `EnrollResult`, `DeviceSummary`, ...). Inside this module the
// unqualified name is always this module's own; the bindings' types are named
// through the aliases below or `CredentialSdkCoreBindings.` in full. No public
// name changes.

typealias CoreUsage = CredentialSdkCoreBindings.Usage
typealias CoreSignScope = CredentialSdkCoreBindings.SignScope

extension CoreUsage {
    /// The usage string the key layer and storage keys use.
    var text: String {
        switch self {
        case .highAssurance:     return "high-assurance"
        case .standardAssurance: return "standard-assurance"
        }
    }
}

extension SignScope {
    /// The key layer's scope for the core's.
    init(_ scope: CoreSignScope) {
        switch scope {
        case .silent:
            self = .silent
        case .transaction(let id, let allowedSignatures, let reason):
            self = .transaction(id: id, allowedSignatures: allowedSignatures, reason: reason)
        }
    }
}

extension PlatformError {
    /// An adapter's typed error as the core receives it. A key-layer failure
    /// keeps its code and detail (`key_error:<code>: <detail>`), a storage
    /// failure its own (`storage_error:<code>: <detail>`), a transport failure
    /// is `Transport`; anything else is `Other` with its description, the text
    /// SDK v1's JavaScript bridge carried for it.
    static func from(_ error: Error) -> PlatformError {
        switch error {
        case let e as PlatformError:
            return e
        case let e as KeychainKeysError:
            return .Key(code: e.bridgeCode, detail: e.detail)
        case let e as KeychainStorageError:
            return .Storage(code: e.bridgeCode, detail: e.detail)
        case URLSessionHttpError.transport(let detail):
            return .Transport(detail: detail)
        default:
            return .Other(detail: (error as? LocalizedError)?.errorDescription ?? "\(error)")
        }
    }
}

/// Where a scope's prompt gets its words: the engine the core belongs to, which knows the approval and the calling
/// SDK's `approvalPromptText` hook (`RustEngine.promptText(scopeId:reason:)`). Set once, after the engine is built;
/// weak, so the adapters the core holds do not keep the engine alive. No engine: the scope's own reason.
final class PromptRoute: @unchecked Sendable {
    weak var engine: RustEngine?

    /// The words for the prompt of scope `id`, whose reason is `reason`.
    func text(_ id: String, _ reason: String) -> String {
        engine?.promptText(scopeId: id, reason: reason) ?? reason
    }
}

/// `KeychainKeys` as the core's `KeyCustody`.
final class KeysAdapter: KeyCustody, @unchecked Sendable {
    let keys: KeychainKeys
    let route: PromptRoute
    init(_ keys: KeychainKeys, route: PromptRoute = PromptRoute()) { self.keys = keys; self.route = route }

    /// The public JWK as the TypeScript core stored it: `generateKeyPair`'s
    /// `publicJwk` member re-serialized as `JSON.stringify` writes it (members
    /// in the order the key layer emitted them, sorted; slashes unescaped).
    func generateKeyPair(usage: CoreUsage, attestationChallenge: Data?) throws -> GeneratedKey {
        do {
            let outer = try keys.generateKeyPair(usage: usage.text)
            guard let object = (try? JSONSerialization.jsonObject(with: Data(outer.utf8))) as? [String: Any],
                  let jwk = object["publicJwk"] as? [String: Any] else {
                throw KeychainKeysError.publicKeyExportFailed("generateKeyPair did not return a publicJwk object")
            }
            let data = try JSONSerialization.data(withJSONObject: jwk, options: [.sortedKeys, .withoutEscapingSlashes])
            return GeneratedKey(publicJwk: String(decoding: data, as: UTF8.self))
        } catch {
            throw PlatformError.from(error)
        }
    }

    /// iOS has no per-key attestation.
    func attestationChain(usage: CoreUsage) throws -> [Data]? { nil }

    func sign(usage: CoreUsage, data: Data, scope: CoreSignScope) throws -> Data {
        do {
            return try keys.sign(usage: usage.text, data: data, scope: SignScope(scope), promptText: route.text)
        } catch {
            throw PlatformError.from(error)
        }
    }

    func endScope(scopeId: String) {
        keys.endScope(scopeId)
    }

    func destroy(usage: CoreUsage) throws {
        do { try keys.destroy(usage: usage.text) } catch { throw PlatformError.from(error) }
    }

    func destroyAll() throws {
        do { try keys.destroyAll() } catch { throw PlatformError.from(error) }
    }
}

/// `KeychainStorage` as the core's `Storage`.
final class StorageAdapter: CredentialSdkCoreBindings.Storage, @unchecked Sendable {
    let storage: KeychainStorage
    init(_ storage: KeychainStorage) { self.storage = storage }

    func get(key: String) throws -> String? {
        do { return try storage.get(key: key) } catch { throw PlatformError.from(error) }
    }

    func set(key: String, value: String) throws {
        do { try storage.set(key: key, value: value) } catch { throw PlatformError.from(error) }
    }

    func remove(key: String) throws {
        do { try storage.remove(key: key) } catch { throw PlatformError.from(error) }
    }
}

/// `URLSessionHttp` as the core's `Http`. One typed request serves both
/// calls: `fetch` decodes the body as UTF-8 (an undecodable body reads as
/// empty, as SDK v1's JavaScript bridge's text path did), `fetchBinary` keeps the
/// bytes. A refused redirect is the server's answer, not a transport failure:
/// it comes back as its 3xx status with no body, as the bridge reported it.
final class HttpAdapter: Http, @unchecked Sendable {
    let http: URLSessionHttp
    init(_ http: URLSessionHttp) { self.http = http }

    private func run(_ request: HttpRequest) throws -> (UInt16, [HttpHeader], Data) {
        let method: String
        switch request.method {
        case .get:  method = "GET"
        case .post: method = "POST"
        case .put:  method = "PUT"
        }
        do {
            let response = try http.fetch(method: method, url: request.url,
                                          headers: request.headers.map { (name: $0.name, value: $0.value) },
                                          body: request.body)
            guard let status = UInt16(exactly: response.status) else {
                throw PlatformError.Transport(detail: "status \(response.status) out of range")
            }
            return (status, response.headers.map { HttpHeader(name: $0.name, value: $0.value) }, response.body)
        } catch URLSessionHttpError.redirectRefused(let status, let location) {
            let headers = location.map { [HttpHeader(name: "Location", value: $0)] } ?? []
            return (UInt16(clamping: status), headers, Data())
        } catch {
            throw PlatformError.from(error)
        }
    }

    func fetch(request: HttpRequest) throws -> HttpResponse {
        let (status, headers, body) = try run(request)
        return HttpResponse(status: status, headers: headers, body: String(data: body, encoding: .utf8) ?? "")
    }

    func fetchBinary(request: HttpRequest) throws -> HttpBinaryResponse {
        let (status, headers, body) = try run(request)
        return HttpBinaryResponse(status: status, headers: headers, body: body)
    }

    func supportsBinary() -> Bool { true }
}

/// App Attest as the core's `Attestation`. `kind()` is asked once per
/// enrollment: `.appleAppAttest` where `DCAppAttestService` reports support,
/// `.none` (the older-Mac path) where it does not.
final class AttestationAdapter: CredentialSdkCoreBindings.Attestation, @unchecked Sendable {
    let runner: AppAttestRunner
    init(_ runner: AppAttestRunner) { self.runner = runner }

    func kind() -> AttestationKind {
        let supported = runner.isSupported
        NSLog("[CredentialSdk] App Attest isSupported=\(supported)")
        return supported ? .appleAppAttest : .none
    }

    func attest(challenge: Data, clientData: Data) throws -> AppAttestResult {
        do {
            let out = try runner.attestOutput(challengeBytes: challenge, clientDataBytes: clientData)
            return AppAttestResult(keyId: out.keyId,
                                   attestationObject: out.attestationObject.base64EncodedString(),
                                   assertion: out.assertion.base64EncodedString())
        } catch {
            throw PlatformError.from(error)
        }
    }
}

/// The host's mdoc proof signer (`issueMdoc(... hostProof:)`) as the core's
/// `MdocProofSigner`. The core calls `sign` exactly once, inside
/// the approval's scope; this joins that scope in the key layer
/// (`KeychainKeys.signInHostScope`), so the host receives the scope's live,
/// evaluated `LAContext` and the SDK's own high-assurance signature after it
/// reuses the same context: one prompt.
///
/// The host's closure is async; the core's callback is synchronous and runs on
/// the SDK's queue, so the closure runs in a task and the queue waits for it.
/// An error the host throws is kept and rethrown to the host unchanged once
/// the core has rolled the approval back.
final class HostProofSigner: MdocProofSigner, @unchecked Sendable {
    typealias Body = @Sendable (_ signingInput: Data, _ context: LAContext) async throws -> Data

    private let keys: KeychainKeys
    private let route: PromptRoute
    private let body: Body
    private let lock = NSLock()
    private var thrown: Error?
    private var calls = 0

    init(keys: KeychainKeys, route: PromptRoute = PromptRoute(), body: @escaping Body) {
        self.keys = keys
        self.route = route
        self.body = body
    }

    /// The error the host's closure threw, if it threw.
    var hostError: Error? { lock.lock(); defer { lock.unlock() }; return thrown }

    /// The LocalAuthentication error of the scope's Face ID, when that evaluation failed (a cancel, a mismatch).
    var evaluationError: LAError? { lock.lock(); defer { lock.unlock() }; return evaluated }
    private var evaluated: LAError?

    /// How many times the core called `sign` (tests: exactly once).
    var callCount: Int { lock.lock(); defer { lock.unlock() }; return calls }

    func sign(signingInput: Data, scope: CoreSignScope) throws -> Data {
        lock.lock(); calls += 1; lock.unlock()
        do {
            return try keys.signInHostScope(SignScope(scope), promptText: route.text, evaluationFailed: { error in
                let la = error as? LAError
                self.lock.lock(); self.evaluated = la; self.lock.unlock()
            }) { context in
                try Self.wait { try await self.body(signingInput, context) }
            }
        } catch let error as KeychainKeysError {
            throw PlatformError.from(error)
        } catch {
            lock.lock(); thrown = error; lock.unlock()
            throw PlatformError.Other(detail: "the host proof signer failed: \(error.localizedDescription)")
        }
    }

    /// Runs `work` in a task and blocks the calling thread (the SDK's queue,
    /// never the main thread or the cooperative pool) until it finishes.
    private static func wait<T>(_ work: @escaping @Sendable () async throws -> T) throws -> T {
        let done = DispatchSemaphore(value: 0)
        let box = ResultBox<T>()
        Task.detached {
            do { box.result = .success(try await work()) } catch { box.result = .failure(error) }
            done.signal()
        }
        done.wait()
        return try box.result!.get()
    }
}

/// One result handed from a task to the thread waiting for it.
private final class ResultBox<T>: @unchecked Sendable {
    var result: Result<T, Error>?
}
