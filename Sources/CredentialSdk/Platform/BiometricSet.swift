import Foundation
import LocalAuthentication
import Security

// The enrolled biometric set as LocalAuthentication hashes it: the evidence the Rust engine's door needs before it
// reports `key_invalidated`, which makes the core destroy the high-assurance key and unenroll. The hash is recorded
// on the key's keychain item (its label) when the key is created and compared with today's when a signature fails
// (`KeychainKeys.mapSignFailure`). It is an opaque hash, not a secret.
//
// Apple: the hash changes when fingers or faces are added or removed, "can change exceptionally between major OS
// versions even if the state of biometry has not changed" (LAContext.h, LADomainState.h), and differs between apps.
// So a record names the app that read it, its source and the major OS, and a comparison across any of them reads as
// unknown, never as changed. Adding then removing a finger may also leave a different hash; a successful signature
// that evaluated the key's own access control re-baselines the record, only when three readings bracketing it agree
// (`BiometricSetBracket`), so a set that still unlocks the key is never later read as a change, and a change landing
// before, during or after the signature cannot overwrite the evidence.

/// Which LocalAuthentication value a record holds.
@_spi(EnclaveHarness)
public enum BiometricStateSource: String, Equatable {
    /// `LAContext.domainState.biometry.stateHash` (iOS 18, macOS 15 and later).
    case stateHash
    /// `LAContext.evaluatedPolicyDomainState`, the older API it replaces.
    case policyDomainState
}

/// One reading of the enrolled biometric set.
@_spi(EnclaveHarness)
public struct BiometricSetRecord: Equatable {
    /// The app that read the hash (`KeychainKeys.currentAppIdentity`): `<team prefix or ->/<bundle id>`.
    public let app: String
    public let source: BiometricStateSource
    public let osMajor: Int
    public let hash: Data

    public init(app: String, source: BiometricStateSource, osMajor: Int, hash: Data) {
        self.app = app
        self.source = source
        self.osMajor = osMajor
        self.hash = hash
    }

    static let labelPrefix = "krutho.biometry-set.v2"

    /// The keychain label the record is kept in:
    /// `krutho.biometry-set.v2;app=<team>/<bundle>;src=<source>;os=<major>;hash=<base64>`.
    var label: String {
        "\(Self.labelPrefix);app=\(app);src=\(source.rawValue);os=\(osMajor);hash=\(hash.base64EncodedString())"
    }

    /// Parses a label written by `label`; anything else (no label, a v1 label without the app, another app's own
    /// label format, a malformed one) is nil.
    init?(label: String) {
        let parts = label.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 5, parts[0] == Self.labelPrefix,
              parts[1].hasPrefix("app="), parts[2].hasPrefix("src="), parts[3].hasPrefix("os="),
              parts[4].hasPrefix("hash="),
              case let app = String(parts[1].dropFirst(4)), !app.isEmpty,
              let source = BiometricStateSource(rawValue: String(parts[2].dropFirst(4))),
              let os = Int(parts[3].dropFirst(3)),
              let hash = Data(base64Encoded: String(parts[4].dropFirst(5))), !hash.isEmpty else {
            return nil
        }
        self.init(app: app, source: source, osMajor: os, hash: hash)
    }

    /// The first eight hex digits of the hash: enough to compare two readings in a transcript.
    public var shortHash: String {
        hash.prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    public var summary: String { "\(app)/\(source.rawValue)/os\(osMajor)/\(shortHash)" }
}

/// The recorded set against today's, and what that says about the key.
@_spi(EnclaveHarness)
public struct BiometricSetComparison: Equatable, CustomStringConvertible {
    public enum Verdict: String, Equatable {
        /// Both readable, same app, source and major OS, different hashes: the enrolled set changed since the record.
        case changed
        /// Both readable, same app, source and major OS, same hash.
        case unchanged
        /// Either missing or unreadable, or the app, source or major OS differs: no evidence either way.
        case unknown
    }

    public let stored: BiometricSetRecord?
    public let current: BiometricSetRecord?

    public init(stored: BiometricSetRecord?, current: BiometricSetRecord?) {
        self.stored = stored
        self.current = current
    }

    public var verdict: Verdict {
        guard let stored, let current, stored.app == current.app, stored.source == current.source,
              stored.osMajor == current.osMajor else {
            return .unknown
        }
        return stored.hash == current.hash ? .unchanged : .changed
    }

    public var description: String {
        "stored=\(stored?.summary ?? "none") current=\(current?.summary ?? "unreadable") verdict=\(verdict.rawValue)"
    }
}

/// The three readings that bracket a signature which evaluated the key's own access control: a fresh context's
/// immediately before the evaluation, the evaluating context's straight after it, a fresh context's immediately
/// after the signature. The set is re-baselined only when all three are readable and identical (same app, source,
/// major OS and hash): a change landing anywhere in between makes them disagree.
@_spi(EnclaveHarness)
public struct BiometricSetBracket: Equatable, CustomStringConvertible {
    public let before: BiometricSetRecord?
    public let evaluated: BiometricSetRecord?
    public let after: BiometricSetRecord?

    public init(before: BiometricSetRecord?, evaluated: BiometricSetRecord?, after: BiometricSetRecord?) {
        self.before = before
        self.evaluated = evaluated
        self.after = after
    }

    /// The set all three readings agree on, or nil.
    public var agreed: BiometricSetRecord? {
        guard let before, let evaluated, let after, before == evaluated, evaluated == after else { return nil }
        return evaluated
    }

    /// Why the readings do not agree, or `agree`.
    public var verdict: String {
        let unreadable = [("before", before), ("evaluated", evaluated), ("after", after)].filter { $0.1 == nil }
        if !unreadable.isEmpty { return "unreadable: " + unreadable.map(\.0).joined(separator: ", ") }
        if before != evaluated { return "disagree: before != evaluated" }
        if evaluated != after { return "disagree: evaluated != after" }
        return "agree"
    }

    public var description: String {
        "before=\(before?.summary ?? "unreadable") evaluated=\(evaluated?.summary ?? "unreadable") after=\(after?.summary ?? "unreadable") -> \(verdict)"
    }
}

extension KeychainKeys {
    /// Reads the enrolled biometric set from LocalAuthentication, from `source` (nil: the newest the OS has). Nil
    /// when biometrics cannot be evaluated (none enrolled, lockout, no hardware) or the source is not available here.
    /// Never prompts: `canEvaluatePolicy` only.
    static func readBiometricSet(_ source: BiometricStateSource?) -> BiometricSetRecord? {
        let app = currentAppIdentity()
        let context = LAContext()
        defer { context.invalidate() }
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return nil }
        let os = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        if source != .policyDomainState, #available(iOS 18.0, macOS 15.0, *) {
            guard let hash = context.domainState.biometry.stateHash, !hash.isEmpty else { return nil }
            return BiometricSetRecord(app: app, source: .stateHash, osMajor: os, hash: hash)
        }
        guard source != .stateHash else { return nil }
        guard let hash = context.evaluatedPolicyDomainState, !hash.isEmpty else { return nil }
        return BiometricSetRecord(app: app, source: .policyDomainState, osMajor: os, hash: hash)
    }

    /// The set `context` authenticated with, read from `context` itself after a successful evaluation:
    /// `domainState.biometry.stateHash` on iOS 18 / macOS 15 and later, `evaluatedPolicyDomainState` before. Nil when
    /// that context reports none (whether an access-control evaluation fills it is measured by the invalidation
    /// check, not assumed), in which case nothing is re-baselined.
    static func readBiometricSet(evaluatedBy context: LAContext) -> BiometricSetRecord? {
        let app = currentAppIdentity()
        let os = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        if #available(iOS 18.0, macOS 15.0, *) {
            guard let hash = context.domainState.biometry.stateHash, !hash.isEmpty else { return nil }
            return BiometricSetRecord(app: app, source: .stateHash, osMajor: os, hash: hash)
        }
        guard let hash = context.evaluatedPolicyDomainState, !hash.isEmpty else { return nil }
        return BiometricSetRecord(app: app, source: .policyDomainState, osMajor: os, hash: hash)
    }

    /// This process's app identity for a record: `<team prefix>/<bundle id>`. The bundle id is the main bundle's
    /// (the process name when there is none). The team prefix comes from the `com.apple.application-identifier`
    /// entitlement on macOS (`SecTask`); iOS has no public API that reads it without writing a keychain item, so it
    /// is `-` there. Keychain sharing is team-scoped, so every app that can read the key has the same team and a
    /// different bundle id: the bundle id is what separates them. `;` never appears (the label's separator).
    static func currentAppIdentity() -> String {
        var team = "-"
        #if os(macOS)
        if let task = SecTaskCreateFromSelf(nil),
           let value = SecTaskCopyValueForEntitlement(task, "com.apple.application-identifier" as CFString, nil) as? String,
           let prefix = value.split(separator: ".").first, !prefix.isEmpty {
            team = String(prefix)
        }
        #endif
        let bundle = Bundle.main.bundleIdentifier ?? ProcessInfo.processInfo.processName
        return "\(team)/\(bundle)".replacingOccurrences(of: ";", with: "_")
    }
}
