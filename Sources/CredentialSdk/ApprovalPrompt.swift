import Foundation
import CredentialSdkCoreBindings

/// The approval a Face ID / Touch ID prompt is about to ask for, as the host's `approvalPromptText` hook receives it
/// (`CredentialSdk.init(... approvalPromptText:)`). The hook returns the words the system prompt shows instead of
/// `defaultText`, in the app's own voice and language.
///
/// The fields are what the public API already hands the host for the same approval (the invitation an inspection
/// returned, or the argument the host passed): nothing new, nothing secret. A field is nil for a kind that does not
/// carry it; each field's comment names the kinds that set it.
///
/// The text changes only what the system prompt shows. What is signed, how many signatures the approval allows, the
/// transaction and its facts are the core's, with or without the hook.
public struct ApprovalPrompt: Equatable, Sendable {

    /// The kind of approval: one per approval door of the core.
    public enum Kind: String, Equatable, Sendable, CaseIterable {
        /// `endorse(transactionId:)`: approve a new device for this identity.
        case endorsement
        /// `signInPresent(_:)`: sign in to a site with a passkey this device holds.
        case siteSignIn
        /// `revokeDevice(targetDeviceId:)`: remove a device.
        case deviceRevoke
        /// `containDevice(targetDeviceId:since:)`: mark a device compromised and revoke what it approved.
        case deviceContain
        /// `cancelRecovery(transactionId:)`: cancel a recovery in progress.
        case recoveryCancel
        /// `revokePasskey(targetJti:)`: revoke a passkey.
        case passkeyRevoke
        /// `issueMdoc(... hostProof:)`: issue an mdoc to a key the host holds.
        case mdocIssue
    }

    /// The longest text the prompt shows, in characters (`Character`, so an emoji or an accented letter counts as
    /// one). A longer text from the hook is cut to this length. The system prompt has room for a short sentence; 160
    /// characters is more than any localization of one should need.
    public static let maximumTextLength = 160

    public let kind: Kind
    /// The words the prompt shows when the hook returns nil, an empty or whitespace-only text, or is not set: the
    /// core's summary line for this approval.
    public let defaultText: String
    /// `.endorsement`: the new device's origin (`EndorsementInvitation.origin`). `.siteSignIn`: the site's origin
    /// (`SiteSignInInvitation.origin`).
    public let origin: String?
    /// `.siteSignIn`: the site's relying-party id (`SiteSignInInvitation.rpId`).
    public let rpId: String?
    /// `.siteSignIn`: the site's label for the key (`SiteSignInInvitation.label`).
    public let label: String?
    /// `.endorsement`: the endorsement transaction (`EndorsementInvitation.transactionId`). `.recoveryCancel`: the
    /// recovery being cancelled (`cancelRecovery(transactionId:)`).
    public let transactionId: String?
    /// `.endorsement`: the device the new one replaces, when it re-keys one (`EndorsementInvitation.replaces`).
    public let replaces: String?
    /// `.deviceRevoke`, `.deviceContain`: the device the call names (`targetDeviceId`).
    public let targetDeviceId: String?
    /// `.passkeyRevoke`: the passkey credential the call names (`targetJti`).
    public let targetJti: String?

    public init(kind: Kind, defaultText: String, origin: String? = nil, rpId: String? = nil, label: String? = nil,
                transactionId: String? = nil, replaces: String? = nil, targetDeviceId: String? = nil,
                targetJti: String? = nil) {
        self.kind = kind
        self.defaultText = defaultText
        self.origin = origin
        self.rpId = rpId
        self.label = label
        self.transactionId = transactionId
        self.replaces = replaces
        self.targetDeviceId = targetDeviceId
        self.targetJti = targetJti
    }
}

/// The host's approval prompt hook (`CredentialSdk.init(... approvalPromptText:)`): the words for one approval's
/// Face ID / Touch ID prompt, or nil for `defaultText`.
public typealias ApprovalPromptText = @Sendable (ApprovalPrompt) -> String?

extension ApprovalPrompt {
    /// The prompt for the core's transaction `facts`, `defaultText` the scope's reason.
    init(facts: CredentialSdkCoreBindings.Facts, defaultText: String) {
        switch facts.detail {
        case .endorsement(let inv):
            self.init(kind: .endorsement, defaultText: defaultText, origin: inv.origin,
                      transactionId: inv.transactionId, replaces: inv.replaces)
        case .siteSignin(_, _, let rpId, let origin, let label, _, _):
            self.init(kind: .siteSignIn, defaultText: defaultText, origin: origin, rpId: rpId, label: label)
        case .deviceRevoke(let target):
            self.init(kind: .deviceRevoke, defaultText: defaultText, targetDeviceId: target)
        case .deviceContain(let target, _):
            self.init(kind: .deviceContain, defaultText: defaultText, targetDeviceId: target)
        case .recoveryCancel(let transactionId, _):
            self.init(kind: .recoveryCancel, defaultText: defaultText, transactionId: transactionId)
        case .passkeyRevoke(let jti):
            self.init(kind: .passkeyRevoke, defaultText: defaultText, targetJti: jti)
        case .mdocIssue:
            self.init(kind: .mdocIssue, defaultText: defaultText)
        }
    }

    /// The text the prompt shows for the hook's answer `text`: `defaultText` for nil, empty or whitespace-only; else
    /// `text` trimmed of surrounding whitespace and cut to `maximumTextLength` characters.
    static func shown(_ text: String?, defaultText: String) -> String {
        guard let trimmed = text?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return defaultText
        }
        return trimmed.count > maximumTextLength ? String(trimmed.prefix(maximumTextLength)) : trimmed
    }
}
