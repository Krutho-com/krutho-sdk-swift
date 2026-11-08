import Foundation
import DeviceCheck
import CryptoKit

/// Thrown by `AppAttestRunner.attest` on any DeviceCheck failure or timeout.
/// The bridge surfaces this to JS as an exception via
/// `LocalizedError.errorDescription`, the same convention `KeychainKeysError`
/// and `KeychainStorageError` use (`errorDescription` carries the
/// bridge-facing prefix). Message format per the plan: `attestation_failed:
/// <DCError code>` for any DeviceCheck completion-handler failure,
/// `attestation_timeout` when the 60s bound (`AppAttestRunner.timeoutSeconds`)
/// elapses without a callback. The TS core (`enrollment/oauth2.ts`'s
/// `buildAttestation`) catches whatever crosses the bridge here and always
/// wraps it as `AttestationFailedError('attest', cause)` — never retries
/// without attestation — so the exact wording beyond the prefix is for logs,
/// not for TS control flow.
enum AppAttestError: Error, LocalizedError {
    case failed(String)
    case timeout

    var errorDescription: String? {
        switch self {
        case .failed(let detail): return "attestation_failed:\(detail)"
        case .timeout:            return "attestation_timeout"
        }
    }
}

/// Protocol over the three `DCAppAttestService` calls App Attest needs at
/// enrollment: key generation, attestation, and one assertion over the
/// enrollment's clientData. Real `DCAppAttestService.shared` calls Apple's
/// servers and needs device hardware, so every test in this tree injects a
/// stub conforming to this protocol instead — `IOSPlatform.init(appAttest:)`
/// takes `AppAttesting`, defaulting to `defaultAppAttest()`, precisely so
/// tests never reach the real service. Public (like
/// `KeychainKeys`/`URLSessionHttp`) only because `IOSPlatform`'s public
/// initializer needs its default argument's type to be at least as visible
/// as the initializer itself; a host has no reason to conform its own type
/// to this.
public protocol AppAttesting {
    var isSupported: Bool { get }
    func generateKey(completionHandler: @escaping (String?, Error?) -> Void)
    func attestKey(_ keyId: String, clientDataHash: Data, completionHandler: @escaping (Data?, Error?) -> Void)
    func generateAssertion(_ keyId: String, clientDataHash: Data, completionHandler: @escaping (Data?, Error?) -> Void)
}

/// The real `AppAttesting`, backed by `DCAppAttestService.shared`.
/// `DCAppAttestService` needs iOS 14 / macOS 11 — `Package.swift`'s
/// deployment targets stay at `.v13`/`.v13` (raising the SDK's consumer-
/// facing minimum is not part of this step), so every use of this type is
/// behind `#available`/`@available`; `defaultAppAttest()` below is the one
/// call site, gated. Internal: nothing outside this file constructs it
/// directly (tests inject `AppAttesting` stubs; production code goes
/// through `defaultAppAttest()`), so it does not need to be public.
@available(iOS 14.0, macOS 11.0, *)
final class AppAttest: AppAttesting {
    var isSupported: Bool { DCAppAttestService.shared.isSupported }

    func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
        DCAppAttestService.shared.generateKey(completionHandler: completionHandler)
    }

    func attestKey(_ keyId: String, clientDataHash: Data, completionHandler: @escaping (Data?, Error?) -> Void) {
        DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash, completionHandler: completionHandler)
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data, completionHandler: @escaping (Data?, Error?) -> Void) {
        DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash, completionHandler: completionHandler)
    }
}

/// Reports unsupported unconditionally: `IOSPlatform`'s default App Attest
/// component below `DCAppAttestService`'s floor (iOS 14 / macOS 11), since
/// `Package.swift`'s deployment targets are not raised for this step. A
/// device below the floor takes the "unsupported" path (under `.on` it
/// submits the enrollment without attestation, subject to tenant policy)
/// rather than the package failing to build or
/// calling an API the OS does not have.
final class UnavailableAppAttest: AppAttesting {
    var isSupported: Bool { false }

    private static let reason = "unavailable: DCAppAttestService needs iOS 14 / macOS 11"

    func generateKey(completionHandler: @escaping (String?, Error?) -> Void) {
        completionHandler(nil, AppAttestError.failed(Self.reason))
    }
    func attestKey(_ keyId: String, clientDataHash: Data, completionHandler: @escaping (Data?, Error?) -> Void) {
        completionHandler(nil, AppAttestError.failed(Self.reason))
    }
    func generateAssertion(_ keyId: String, clientDataHash: Data, completionHandler: @escaping (Data?, Error?) -> Void) {
        completionHandler(nil, AppAttestError.failed(Self.reason))
    }
}

/// `IOSPlatform.init(appAttest:)`'s default value. A default-argument
/// expression can't itself branch on `#available` (that's a statement-level
/// check, not an expression), so this factory function does the check and
/// the initializer calls it: the real `DCAppAttestService` wrapper where
/// available, `UnavailableAppAttest` (isSupported == false) below it.
public func defaultAppAttest() -> AppAttesting {
    if #available(iOS 14.0, macOS 11.0, *) {
        return AppAttest()
    } else {
        return UnavailableAppAttest()
    }
}

/// Runs one enrollment's App Attest round trip against an injected
/// `AppAttesting`. Synchronous, as the Rust core's
/// platform callbacks are (each blocks the calling thread): the three
/// DeviceCheck completion-handler calls are dispatched on a background queue
/// and awaited with a `DispatchSemaphore`, bounded by `timeoutSeconds` (60s in
/// production; tests inject a short bound) so a hung callback becomes a typed
/// `AppAttestError.timeout` instead of blocking the core's call forever.
final class AppAttestRunner {
    private let service: AppAttesting
    private let timeoutSeconds: TimeInterval

    init(service: AppAttesting, timeoutSeconds: TimeInterval = 60) {
        self.service = service
        self.timeoutSeconds = timeoutSeconds
    }

    var isSupported: Bool { service.isSupported }

    private let instanceId = UUID().uuidString

    /// What makes two runners one attestation capability: the default `DCAppAttestService` path (or the stand-in
    /// below its OS floor) is the same everywhere; an injected service is the same only as itself (a value-type
    /// service has no identity to compare, so it is only its own runner). The Rust engine shares one core between
    /// SDKs only when this matches under `.on` or `.required` (`RustEngine.engine`): the shared core would
    /// otherwise attest, or fail to, through the first SDK's service.
    var sharingIdentity: String {
        let bound = "timeout=\(timeoutSeconds)"
        if #available(iOS 14.0, macOS 11.0, *), service is AppAttest { return "dcappattest:\(bound)" }
        if service is UnavailableAppAttest { return "unavailable:\(bound)" }
        if type(of: service) is AnyClass { return "injected:\(ObjectIdentifier(service as AnyObject).hashValue):\(bound)" }
        return "value:\(instanceId)"
    }

    /// `challengeBytes` are the exact bytes the attestation's clientDataHash
    /// covers (UTF-8 of the challenge string); `clientDataBytes` are the
    /// exact bytes the assertion's clientDataHash covers (UTF-8 JSON,
    /// sorted keys). Both are hashed here with SHA-256 — the caller
    /// (`IOSPlatform.attest`) passes the raw bytes decoded from the base64
    /// the TS core sent, unhashed, mirroring `Platform.attestation.attest`'s
    /// documented contract ("the native side hashes these bytes").
    ///
    /// Returns JSON `{ keyId, attestationObject, assertion }` with
    /// `attestationObject`/`assertion` as standard base64 — the exact shape
    /// `Platform.attestation.attest`'s TS return type documents.
    func attest(challengeBytes: Data, clientDataBytes: Data) throws -> String {
        let output = try attestOutput(challengeBytes: challengeBytes, clientDataBytes: clientDataBytes)
        let result: [String: String] = [
            "keyId": output.keyId,
            "attestationObject": output.attestationObject.base64EncodedString(),
            "assertion": output.assertion.base64EncodedString(),
        ]
        let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        return String(data: data, encoding: .utf8)!
    }

    /// One enrollment's App Attest output, the bytes unencoded.
    struct Output {
        let keyId: String
        let attestationObject: Data
        let assertion: Data
    }

    /// The typed form of `attest`, for the native adapter interface: the same round trip, the
    /// attestation and the assertion as bytes. `attest` encodes this; they cannot disagree.
    func attestOutput(challengeBytes: Data, clientDataBytes: Data) throws -> Output {
        let keyId = try await1 { self.service.generateKey(completionHandler: $0) }
        let attestChallengeHash = Data(SHA256.hash(data: challengeBytes))
        let attestationObject = try await1 { cb in
            self.service.attestKey(keyId, clientDataHash: attestChallengeHash, completionHandler: cb)
        }
        let assertionHash = Data(SHA256.hash(data: clientDataBytes))
        let assertion = try await1 { cb in
            self.service.generateAssertion(keyId, clientDataHash: assertionHash, completionHandler: cb)
        }
        return Output(keyId: keyId, attestationObject: attestationObject, assertion: assertion)
    }

    // MARK: - Private

    /// Runs one DeviceCheck completion-handler call on a background queue
    /// and blocks the caller until it completes or `timeoutSeconds` elapses.
    private func await1<T>(_ operation: @escaping (@escaping (T?, Error?) -> Void) -> Void) throws -> T {
        let semaphore = DispatchSemaphore(value: 0)
        var result: T?
        var opError: Error?
        DispatchQueue.global(qos: .userInitiated).async {
            operation { value, error in
                result = value
                opError = error
                semaphore.signal()
            }
        }
        if semaphore.wait(timeout: .now() + timeoutSeconds) == .timedOut {
            throw AppAttestError.timeout
        }
        if let opError = opError {
            throw AppAttestError.failed(Self.describe(opError))
        }
        guard let result = result else {
            throw AppAttestError.failed("no result and no error")
        }
        return result
    }

    /// The numeric code off a DeviceCheck completion-handler error, bridged
    /// through `NSError` rather than matched against `DCError`'s Swift-side
    /// shape directly — every `Error` (including `DCError`) supports `as
    /// NSError`, and the bridge preserves `DCError`'s underlying code, so
    /// this needs no assumption about `DCError`'s exact Swift declaration.
    private static func describe(_ error: Error) -> String {
        "\((error as NSError).code)"
    }
}
