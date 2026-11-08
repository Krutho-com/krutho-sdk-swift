import Foundation
import CryptoKit
import LocalAuthentication
import CredentialSdkCoreBindings

// The public door a Mac credential provider extension and the Mac app use to make a
// Safari passkey with one Touch ID. The extension holds no postable body: it checks what the app's core prepared,
// makes the two signatures (`MacPasskeySigner`) and hands them back. The app's core builds and verifies everything it
// posts (`CredentialSdk.prepareMacPasskey`, `sendMacPasskey`).

// MARK: - M1's request and answer

/// M1 as the extension sends it (4.2): the site, the handle, the credential id the extension drew, the new site key's
/// coordinates and the provider request's client data hash, each base64url (no padding).
public struct MacPasskeyRequest: Equatable, Sendable {
    public let rpId: String
    /// `userHandle`, base64url, 22 characters.
    public let handleRef: String
    /// The credential id the extension drew (16 random bytes), base64url.
    public let credentialId: String
    /// The new site key's `x` and `y`, 43 base64url characters each.
    public let x: String
    public let y: String
    /// SHA-256 of the client data, base64url, 43 characters.
    public let clientDataHash: String

    public init(rpId: String, handleRef: String, credentialId: String, x: String, y: String, clientDataHash: String) {
        self.rpId = rpId
        self.handleRef = handleRef
        self.credentialId = credentialId
        self.x = x
        self.y = y
        self.clientDataHash = clientDataHash
    }
}

/// M1's answer, as the extension received it.
public struct MacPasskeyPrepared: Equatable, Sendable {
    /// Names this preparation in the app's core memory (single use).
    public let token: String
    /// The `krutho-mac-passkey/1` statement the site key signs (its UTF-8 bytes).
    public let canonical: String
    /// The KB-JWT `base64url(header).base64url(payload)` the high-assurance key signs.
    public let kbSigningInput: String
    /// The RFC 7638 thumbprint of the new site key, as the core computed it.
    public let pkt: String
    /// The prompt's words (the core's summary line).
    public let reason: String
    /// The statement's `exp`, Unix seconds.
    public let exp: UInt64
    /// The core API URL the app's core posts to: a hold's persisted binding names it (5.1).
    public let server: String

    public init(token: String, canonical: String, kbSigningInput: String, pkt: String, reason: String, exp: UInt64,
                server: String) {
        self.token = token
        self.canonical = canonical
        self.kbSigningInput = kbSigningInput
        self.pkt = pkt
        self.reason = reason
        self.exp = exp
        self.server = server
    }

    init(_ core: CredentialSdkCoreBindings.MacPasskeyPrepared) {
        self.init(token: core.token, canonical: core.canonical, kbSigningInput: core.kbSigningInput, pkt: core.pkt,
                  reason: core.reason, exp: core.exp, server: core.server)
    }

    /// The statement's lifetime: `exp - iat`, exactly.
    public static let lifetime: Int64 = 300
    /// The largest `iat` or `exp` a statement carries: 2^53 - 1, the JSON-safe integer bound the core emits within.
    static let maxSafeInteger: Int64 = 9_007_199_254_740_991
    /// The path the canonical's `aud` and the KB-JWT's `aud` end in.
    public static let audiencePath = "/v1/core/passkeys/mac"
    static let version = "krutho-mac-passkey/1"

    /// Parses (never builds) `canonical` and `kbSigningInput` and binds them to the request the extension sent (4.2),
    /// before any key use or prompt. Refuses, naming the first field that does not hold:
    /// `canonical` is a `krutho-mac-passkey/1` JSON object whose `rp_id`, `handle_ref`, `credential_id` and
    /// `client_data_hash` (base64url of `clientDataHash`) equal what was sent, whose `pkt` and this answer's `pkt` equal
    /// the RFC 7638 thumbprint of `sitePublicKeyX963` (`0x04 || x || y`), whose `aud` ends in `/v1/core/passkeys/mac`,
    /// whose `iat` and `exp` are integers in 0 ... 2^53 - 1 and whose `exp - iat` is exactly 300 with `exp` this
    /// answer's (no arithmetic before the bounds hold, and none that can overflow); `kbSigningInput` is two base64url parts, the
    /// header exactly `{"typ":"kb+jwt","alg":"ES256"}` and the payload's `nonce` base64url(SHA-256(canonical)) and its
    /// `aud` the canonical's.
    public func check(rpId: String, handleRef: String, credentialId: String, clientDataHash: Data,
                      sitePublicKeyX963: Data) throws {
        guard let statement = Self.object(Data(canonical.utf8)) else {
            throw MacPasskeyCheckError.malformed(field: "canonical")
        }
        func field(_ name: String) -> String? { statement[name] as? String }
        guard field("v") == Self.version else { throw MacPasskeyCheckError.mismatch(field: "v") }
        guard field("rp_id") == rpId else { throw MacPasskeyCheckError.mismatch(field: "rp_id") }
        guard field("handle_ref") == handleRef else { throw MacPasskeyCheckError.mismatch(field: "handle_ref") }
        guard field("credential_id") == credentialId else { throw MacPasskeyCheckError.mismatch(field: "credential_id") }
        guard field("client_data_hash") == KeychainKeys.base64UrlNoPad(clientDataHash) else {
            throw MacPasskeyCheckError.mismatch(field: "client_data_hash")
        }
        guard let sitePkt = KeychainKeys.thumbprint(x963: sitePublicKeyX963) else {
            throw MacPasskeyCheckError.malformed(field: "sitePublicKeyX963")
        }
        guard field("pkt") == sitePkt, pkt == sitePkt else { throw MacPasskeyCheckError.mismatch(field: "pkt") }
        guard let aud = field("aud"), aud.hasSuffix(Self.audiencePath) else {
            throw MacPasskeyCheckError.mismatch(field: "aud")
        }
        guard let iat = Self.safeInteger(statement["iat"]) else { throw MacPasskeyCheckError.malformed(field: "iat") }
        guard let statementExp = Self.safeInteger(statement["exp"]) else {
            throw MacPasskeyCheckError.malformed(field: "exp")
        }
        let (gap, overflow) = statementExp.subtractingReportingOverflow(iat)
        guard !overflow, gap == Self.lifetime, UInt64(statementExp) == exp else {
            throw MacPasskeyCheckError.mismatch(field: "exp")
        }

        let parts = kbSigningInput.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let headerBytes = Self.base64UrlDecode(String(parts[0])), let header = Self.object(headerBytes),
              let payloadBytes = Self.base64UrlDecode(String(parts[1])), let payload = Self.object(payloadBytes) else {
            throw MacPasskeyCheckError.malformed(field: "kb_signing_input")
        }
        guard header.count == 2, header["typ"] as? String == "kb+jwt", header["alg"] as? String == "ES256" else {
            throw MacPasskeyCheckError.mismatch(field: "typ")
        }
        let digest = KeychainKeys.base64UrlNoPad(Data(SHA256.hash(data: Data(canonical.utf8))))
        guard payload["nonce"] as? String == digest else { throw MacPasskeyCheckError.mismatch(field: "nonce") }
        guard payload["aud"] as? String == aud else { throw MacPasskeyCheckError.mismatch(field: "aud") }
    }

    private static func object(_ data: Data) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    /// A JSON integer in 0 ... 2^53 - 1 (never a boolean, a fraction, a negative or an unsafe integer); nil otherwise.
    private static func safeInteger(_ value: Any?) -> Int64? {
        guard let int = integer(value), (0...maxSafeInteger).contains(int) else { return nil }
        return int
    }

    /// A JSON integer (never a boolean or a fraction).
    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let int = number.int64Value
        return Double(int) == number.doubleValue ? int : nil
    }

    static func base64UrlDecode(_ text: String) -> Data? {
        guard text.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else {
            return nil
        }
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }
}

/// `MacPasskeyPrepared.check` refused: the extension cancels with no key use and sends M4.
public enum MacPasskeyCheckError: Error, Equatable, Sendable {
    /// The named part does not parse.
    case malformed(field: String)
    /// The named field does not bind to what the extension sent.
    case mismatch(field: String)
}

/// The two signatures, raw `r || s`, 64 bytes each.
public struct MacPasskeySignatures: Equatable, Sendable {
    /// The new site key over the canonical's UTF-8 bytes.
    public let possession: Data
    /// The high-assurance key over `kbSigningInput`'s UTF-8 bytes.
    public let kbJwt: Data

    public init(possession: Data, kbJwt: Data) {
        self.possession = possession
        self.kbJwt = kbJwt
    }
}

/// Phase A accepted: core-api's 202 (s2 2.2).
public struct MacPasskeyPending: Equatable, Sendable {
    public let handleRef: String
    public let pendingExpiresAt: String

    public init(handleRef: String, pendingExpiresAt: String) {
        self.handleRef = handleRef
        self.pendingExpiresAt = pendingExpiresAt
    }
}

// MARK: - The key-unusable shape

/// Closed: exactly the refusals `KeychainKeys.isKeyUnusableShape` admits. Carries the evidence that rule reads, so the
/// app can re-validate a shape without the original `CFError`. Only `init?(error:)` builds one from an error, and it
/// asks `isKeyUnusableShape`; a decoded value is re-validated with `isAdmitted`, which asks the same rule of the error
/// the value describes.
public enum KeyUnusableShape: Codable, Equatable, Sendable {
    /// LocalAuthentication -1 whose `NSDebugDescription` is exactly "Unsatisfiable constraint.".
    case unsatisfiableConstraint(debugDescription: String)
    /// CryptoTokenKit -3 with `AKSError` -536362999.
    case biometrySetChanged(aksError: Int)

    /// The shape of `error`, or nil for anything `isKeyUnusableShape` refuses: a wrong finger's -1, a -1 with no or
    /// another description, a lockout, a cancel, CryptoTokenKit -3 with another `AKSError`.
    public init?(error: Error) {
        let platformError = unsafeBitCast(error as NSError, to: CFError.self)   // toll-free bridged
        guard KeychainKeys.isKeyUnusableShape(platformError) else { return nil }
        let nsError = error as NSError
        if nsError.domain == KeychainKeys.cryptoTokenKitDomain,
           let aks = (nsError.userInfo["AKSError"] as? NSNumber)?.intValue {
            self = .biometrySetChanged(aksError: aks)
        } else if let description = nsError.userInfo[NSDebugDescriptionErrorKey] as? String {
            self = .unsatisfiableConstraint(debugDescription: description)
        } else {
            return nil
        }
    }

    /// The platform error this value describes.
    var platformError: NSError {
        switch self {
        case .unsatisfiableConstraint(let description):
            return NSError(domain: LAErrorDomain, code: LAError.authenticationFailed.rawValue,
                           userInfo: [NSDebugDescriptionErrorKey: description])
        case .biometrySetChanged(let aks):
            return NSError(domain: KeychainKeys.cryptoTokenKitDomain, code: -3,
                           userInfo: ["AKSError": NSNumber(value: aks)])
        }
    }

    /// `isKeyUnusableShape`'s rule on the values this carries: false for a forged description or `AKSError`.
    public var isAdmitted: Bool {
        KeychainKeys.isKeyUnusableShape(unsafeBitCast(platformError, to: CFError.self))
    }

    var core: CredentialSdkCoreBindings.KeyUnusableShape {
        switch self {
        case .unsatisfiableConstraint(let description): return .unsatisfiableConstraint(debugDescription: description)
        case .biometrySetChanged(let aks): return .biometrySetChanged(aksError: Int64(aks))
        }
    }

    private enum CodingKeys: String, CodingKey { case kind, debugDescription = "debug_description", aksError = "aks_error" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "unsatisfiable_constraint":
            self = .unsatisfiableConstraint(debugDescription: try c.decode(String.self, forKey: .debugDescription))
        case "biometry_set_changed":
            self = .biometrySetChanged(aksError: try c.decode(Int.self, forKey: .aksError))
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c, debugDescription: "unknown shape \(other)")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .unsatisfiableConstraint(let description):
            try c.encode("unsatisfiable_constraint", forKey: .kind)
            try c.encode(description, forKey: .debugDescription)
        case .biometrySetChanged(let aks):
            try c.encode("biometry_set_changed", forKey: .kind)
            try c.encode(aks, forKey: .aksError)
        }
    }
}

// MARK: - The app's answers

/// The self-revoke ran: `key_invalidated`'s triple.
public struct MacPasskeyRevocation: Equatable, Sendable {
    /// The server accepted the unenrollment.
    public let revoked: Bool
    /// Local cleanup completed.
    public let cleanupOk: Bool
    public let retryable: Bool

    public init(revoked: Bool, cleanupOk: Bool, retryable: Bool) {
        self.revoked = revoked
        self.cleanupOk = cleanupOk
        self.retryable = retryable
    }

    init(_ core: KeyInvalidatedOutcome) {
        self.init(revoked: core.revoked, cleanupOk: core.cleanup == .ok, retryable: core.retryable)
    }
}

/// M5's answer (4.2). The extension deletes the site key and cancels in every case.
public enum KeyUnusableVerdict: Equatable, Sendable {
    /// The app's own comparison said `changed`: the enrollment was revoked.
    case revoked(MacPasskeyRevocation)
    /// `unchanged` or `unknown`: nothing destroyed, the token spent.
    case notCorroborated
    /// The shape is not one the rule admits: nothing destroyed, the token spent.
    case notAShape
    /// The token is unknown, spent, or of an enrollment that is gone: nothing destroyed.
    case staleReport

    /// The wire name.
    public var reason: String {
        switch self {
        case .revoked: return "revoked"
        case .notCorroborated: return "not_corroborated"
        case .notAShape: return "not_a_shape"
        case .staleReport: return "stale_report"
        }
    }
}

/// What `CredentialSdk.resolveMacPasskeyHolds()` decided for one hold item.
public struct HoldVerdict: Equatable, Sendable {
    public enum Outcome: Equatable, Sendable {
        /// Bound, the comparison said `changed`: the enrollment was revoked. Deleted.
        case revoked(MacPasskeyRevocation)
        /// Bound, the comparison said `unchanged`: the key signs again. Deleted.
        case unchanged
        /// Not this enrollment, another server, or older than the expiry. Deleted, nothing destroyed.
        case staleHold
        /// The item does not decode to a hold, or its shape is not one the rule admits. Deleted, nothing destroyed.
        case notAShape
        /// Bound, but the enrolled set cannot be read (a lockout, no biometric): left standing.
        case unknown
        /// The core or the keychain failed while deciding: left standing, decided on the next pass.
        case failed(String)
    }

    /// The item's id (its account is `hold.<holdId>`).
    public let holdId: String
    public let outcome: Outcome
    /// True when the item was deleted by its id: every definite outcome deletes it, unless the delete itself failed.
    public let deleted: Bool

    /// True for the outcomes that delete the item: `revoked`, `unchanged`, `staleHold`, `notAShape`.
    public var isDefinite: Bool {
        switch outcome {
        case .revoked, .unchanged, .staleHold, .notAShape: return true
        case .unknown, .failed: return false
        }
    }

    public init(holdId: String, outcome: Outcome, deleted: Bool) {
        self.holdId = holdId
        self.outcome = outcome
        self.deleted = deleted
    }
}

/// A Mac passkey door refused or failed (`CredentialSdk.prepareMacPasskey`, `sendMacPasskey`,
/// `reportMacPasskeyKeyUnusable`).
public enum MacPasskeyDoorError: Error, Equatable, Sendable {
    /// The core refused; nothing sent, nothing destroyed. `reason` is the wire name (`not_enrolled`,
    /// `key_invalidated`, `invalid_input`, `no_credential`, `unknown_token`, `statement_expired`, `stale_token`,
    /// `possession_signature_invalid`, `host_proof_invalid`, `stale_report`, `stale_hold`, `not_a_shape`); `field`
    /// names the refused field for `invalid_input`.
    case refused(reason: String, field: String?, detail: String)
    /// A hold stands that this app could not resolve: no ceremony is admitted (4.5).
    case hold(holdId: String)
    /// core-api refused phase A: its reason and detail.
    case serverRefused(status: Int, reason: String, detail: String?)
    /// The request did not complete.
    case networkUnreachable(operation: String)
    /// A storage failure.
    case storageFailed(code: String, detail: String)
    /// A key-layer failure (the device JWT's signature).
    case keyFailed(code: String, detail: String)
    /// Anything else.
    case failed(String)

    /// The wire name the bridge sends the extension.
    public var reason: String {
        switch self {
        case .refused(let reason, _, _): return reason
        case .hold: return "hold"
        case .serverRefused(_, let reason, _): return reason
        case .networkUnreachable: return "network_unreachable"
        case .storageFailed: return "storage_error"
        case .keyFailed: return "key_error"
        case .failed: return "failed"
        }
    }

    static func from(_ error: Error) -> Error {
        guard let core = error as? CredentialSdkCoreBindings.MacPasskeyError else { return error }
        switch core {
        case .Refused(let refusal, let fieldName, let text):
            return MacPasskeyDoorError.refused(reason: wireName(refusal), field: fieldName, detail: text)
        case .ServerRefused(let status, let reason, let detail, _):
            return MacPasskeyDoorError.serverRefused(status: Int(status), reason: reason, detail: detail)
        case .NetworkUnreachable(let operation, _):
            return MacPasskeyDoorError.networkUnreachable(operation: operation)
        case .StorageError(let code, let detail, _):
            return MacPasskeyDoorError.storageFailed(code: code, detail: detail)
        case .KeyError(let code, let detail, _):
            return MacPasskeyDoorError.keyFailed(code: code, detail: detail)
        case .Protocol(let text):
            return MacPasskeyDoorError.failed(text)
        }
    }

    static func wireName(_ refusal: MacPasskeyRefusal) -> String {
        switch refusal {
        case .notEnrolled: return "not_enrolled"
        case .keyInvalidated: return "key_invalidated"
        case .invalidInput: return "invalid_input"
        case .noCredential: return "no_credential"
        case .unknownToken: return "unknown_token"
        case .statementExpired: return "statement_expired"
        case .staleToken: return "stale_token"
        case .possessionSignatureInvalid: return "possession_signature_invalid"
        case .hostProofInvalid: return "host_proof_invalid"
        case .staleReport: return "stale_report"
        case .staleHold: return "stale_hold"
        case .notAShape: return "not_a_shape"
        }
    }
}
