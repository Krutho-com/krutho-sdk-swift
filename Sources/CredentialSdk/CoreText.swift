import Foundation
import CredentialSdkCoreBindings

/// A failure the core reported that `CredentialSdk` does not type further: `jsException` carries the core's message
/// verbatim (`RustEngine.bridged`), the text whose prefix (`key_error:`, `endorsement_refused:`,
/// `network_unreachable:`, ...) `CredentialSdk`'s per-call mapping reads to choose a `CredentialSdkError` case
/// (the error-code table pins every code's message prefix and detail rule). A failure the mapping leaves untyped (a
/// refused transaction, a protocol refusal, a storage failure) reaches the host as this error.
///
/// The name and the case are those of SDK v1, whose JavaScript core threw this text across a JavaScript bridge; SDK
/// v2 removed that engine and kept the type, so hosts that match on it need no change.
public enum JsBridgeError: Error, Equatable, LocalizedError {
    /// Unused since SDK v2: SDK v1's JavaScript context could not be created. Kept so hosts that match on it
    /// still compile; the SDK never throws it.
    case contextCreationFailed
    /// Unused since SDK v2: SDK v1 called a function its JavaScript core did not define. Kept for source
    /// compatibility; the SDK never throws it.
    case unknownFunction(String)
    /// A failure the core reported, with its message (see above). The one case the SDK throws.
    case jsException(String)
    /// Unused since SDK v2: SDK v1's JavaScript core returned a value that was not a string. Kept for source
    /// compatibility; the SDK never throws it.
    case returnNotString(String)

    public var errorDescription: String? {
        switch self {
        case .contextCreationFailed:     return "JS context creation failed"
        case .unknownFunction(let name): return "JS function not defined on globalThis: \(name)"
        case .jsException(let msg):      return "JS exception: \(msg)"
        case .returnNotString(let name): return "JS function \(name) returned non-string value"
        }
    }
}

extension CredentialSdk {
    /// The linked Rust core's build version. Calling it also runs the
    /// bindings' one-time check that they were generated from the linked
    /// library (a mismatch stops the process: it is a build error, never a
    /// runtime state).
    static func rustCoreVersion() -> String {
        CredentialSdkCoreBindings.coreVersion()
    }

    /// Every host string bound for the Rust core passes through here
    /// (`RustEngine` calls it for each string argument and the configuration). The generated bindings encode a
    /// `String` with `utf8CString`, which turns an unpaired UTF-16 surrogate
    /// into U+FFFD without a word; this refuses it instead, typed, so the core
    /// never signs text the caller did not give it. Surrogate pairs (astral
    /// characters) and a literal U+FFFD pass unchanged.
    static func hostString(_ value: String, argument: String) throws -> String {
        let units = value as NSString
        let count = units.length
        var i = 0
        while i < count {
            let unit = units.character(at: i)
            switch unit {
            case 0xD800...0xDBFF:
                guard i + 1 < count, (0xDC00...0xDFFF).contains(units.character(at: i + 1)) else {
                    throw CredentialSdkError.invalidHostString(argument: argument)
                }
                i += 2
            case 0xDC00...0xDFFF:
                throw CredentialSdkError.invalidHostString(argument: argument)
            default:
                i += 1
            }
        }
        return value
    }
}
