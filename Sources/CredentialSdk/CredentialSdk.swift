import Foundation
import LocalAuthentication

public struct EnrollResult {
    public let deviceId:    String
    public let externalId:  String
    public let credentials: [[String: Any]]
    /// Whether this enrollment attested with App Attest, and if not, why.
    /// `nil` means "not reported" (SDK v1 with an older core), not
    /// "unattested" — a host reads `result.attestation?.attested`.
    public let attestation: AttestationOutcome?
    /// The device pattern the server froze for this endorsed device, copied
    /// from the finish reply. `nil` for an OAuth2 enrollment, for a tenant
    /// with no pattern secret, and for a server older than this field.
    public let pattern:     DevicePattern?
}

/// A device's pattern: the (version, entry) pair the server derived from the
/// device's key and froze at approval. Recognition only; the entry names one
/// drawing in the v1 sett list. Draw it with `SettPatternView`.
public struct DevicePattern: Equatable, Hashable {
    public let patternVersion: Int
    public let patternEntry:   Int
    public init(patternVersion: Int, patternEntry: Int) {
        self.patternVersion = patternVersion
        self.patternEntry   = patternEntry
    }
}

/// What the server knows about how a device attested. `platform` is
/// `"iphoneos"` or `"macosx"`.
public struct DeviceAttestationFacts: Equatable {
    public let platform: String
    public init(platform: String) { self.platform = platform }
}

public struct PresentationResult {
    public let vpToken:                String
    public let presentationSubmission: String
}

/// The tenant's current
/// signed CRLite revocation snapshot, as fetched by `fetchRevocationSnapshot()`.
///
/// This SDK does NOT verify `metadataJws` — it has no trust anchor and no
/// verifier here. `version` and `builtAt` are read from the server's
/// plaintext JSON, unverified, and exist only so a caller can log or pair;
/// they must not drive any security decision. The caller MUST pass
/// `metadataJws` and `filterBytes` to `krutho_apply_revocation_list` (piece
/// B — packages/verifier-distribution, out of scope for this PR) and adopt
/// the result only on `KRUTHO_OK`.
public struct RevocationSnapshot {
    /// The server's `signature` field verbatim: an ES256 compact JWS over
    /// `{version, type, sha256, maxRevocationSeq, built_at}`.
    public let metadataJws:  String
    /// The raw CRLite filter bytes. A zero-length array is a legitimate
    /// snapshot in which nothing is revoked, not a fetch failure.
    public let filterBytes:  Data
    /// Unverified; the tenant's build counter (see the type's doc comment).
    public let version:      Int
    /// Unverified; unix seconds (see the type's doc comment).
    public let builtAt:      Int
}

/// What `endorsementOpen(...)` opens. `.endorsement`, the
/// default, pairs a device under an approver (the Mac's pairing). `.rootProof`
/// opens a recovery on a fresh iPhone, which the operator authorizes; the
/// server refuses `replaces` with it.
public enum EndorsementKind: String {
    case endorsement
    case rootProof = "root-proof"
}

/// The enrolling device's `endorsementOpen(...)` result:
/// what the host shows while it waits for the phone (the optical pattern of
/// `opticalPayload`) plus the transaction's deadline.
public struct EndorsementOpened {
    public let transactionId: String
    /// The JSON string `{"transactionId","origin"}` for the backup QR (C3). The pattern is the pairing channel;
    /// the QR is off in the UI unless the host opts in (`MacPairingFlowScreen(qrFallbackPayload:)`).
    public let qrPayload:     String
    /// The digest's first eight characters as `XXXX XXXX`. Nothing in the SDK shows it.
    public let pairingCode:   String
    /// Payload A, 24 bytes: what this device shows as the optical pattern
    /// (transaction id, a 48-bit commitment to the endorsement digest
    /// computed from this device's own keys, a 16-bit origin tag). Empty only
    /// from SDK v1 with an older core.
    public let opticalPayload: Data
    public let expiresAt:     String
    /// Whether the attach attested with App Attest, and if not, why.
    /// `nil` means "not reported" (SDK v1 with an older core), never "unattested".
    public let attestation:   AttestationOutcome?
}

/// The phone's `endorsementInspectOptical(payload:)` (or the backup QR's
/// `endorsementInspect(qrPayload:)`) result: the transaction
/// row's display fields, computed from what the server answered for the
/// scanned transaction, never from the scan itself.
public struct EndorsementInvitation {
    public let transactionId: String
    public let origin:        String
    public let replaces:      String?
    public let expiresAt:     String
    /// When the new device asked, from the server's row (ISO 8601). Empty
    /// when the server's reply carries no such field (an older server).
    public let createdAt:     String
    /// How the new device attested, from the server's row. `nil` is an
    /// unattested attach: show "type unknown, not attested".
    public let attestation:   DeviceAttestationFacts?
}

/// The phone's `signInInspectOptical(payload:)` result (optical payload version 2): the sign-in
/// Krutho issued for the scanned ring, from the fields Krutho returned and checked against the ring's commitment,
/// never from the scan alone. Nothing has been signed.
public struct SiteSignInInvitation: Equatable {
    /// 8 base64url characters, from the ring.
    public let handle:       String
    public let tenant:       String
    public let rpId:         String
    /// The site's origin: the presentation audience (the ask shows its host).
    public let origin:       String
    public let responseUri:  String
    /// The site's label for the key (1 to 64 printable ASCII).
    public let label:        String
    /// RFC 7638 thumbprint of the passkey public key, 43 characters; the ask shows the first 8.
    public let pkt:          String
    public let siteNonce:    String
    public let credentialId: String
    /// The authorization request the phone answers, as JSON text (built by the core from the checked fields).
    public let authRequest:  String
    /// The digest the phone signs, recomputed by the core from the fields.
    public let digest:       String
    /// ISO 8601.
    public let expiresAt:    String
}

/// The site's answer to `signInPresent(_:)`: `status` is `"signed_in"`.
public struct SiteSignInResult: Equatable {
    public let status: String
}

/// The server's answer to `endSiteSignIn(handle:)`: when Krutho recorded the end (a repeat returns the first time).
public struct SiteSignInEnded: Equatable {
    public let endedAt: String
    public init(endedAt: String) { self.endedAt = endedAt }
}

/// The phone's `endorse(transactionId:)` result: the pattern the server
/// froze at approval (`nil` when the tenant has no pattern secret).
public struct EndorsementApproved {
    public let transactionId: String
    public let pattern:       DevicePattern?
}

/// The phone's `endorsementCancel(transactionId:)` result. `.consumed` means
/// the new device already finished: it exists, and the way out is
/// `revokeDevice(targetDeviceId:)` with the returned `deviceId`.
public enum EndorsementCancelled {
    case cancelled
    case consumed(deviceId: String, pattern: DevicePattern?)
}

/// One row of `devicesList()`. `role` is `"root"`, `"endorsed"` or `nil`;
/// `status` is `"active"` or `"revoked"`.
public struct DeviceSummary {
    public let deviceId:           String
    public let status:             String
    public let role:               String?
    public let createdAt:          String
    public let attestation:        DeviceAttestationFacts?
    public let pattern:            DevicePattern?
    public let endorsedByDeviceId: String?
    public let isCaller:           Bool
    public init(deviceId: String, status: String, role: String?, createdAt: String,
                attestation: DeviceAttestationFacts?, pattern: DevicePattern?,
                endorsedByDeviceId: String?, isCaller: Bool) {
        self.deviceId = deviceId; self.status = status; self.role = role
        self.createdAt = createdAt; self.attestation = attestation; self.pattern = pattern
        self.endorsedByDeviceId = endorsedByDeviceId; self.isCaller = isCaller
    }
}

// MARK: - Identity graph (`identityGraph()`, GET /v1/core/identity-graph)

/// One grant. On `IdentityNode.grants` `claim` names the `grant_*` claim; on
/// agent and session grant maps the key is the name and `claim` is `nil`.
public struct GrantEntry: Equatable {
    public let claim:  String?
    public let action: String
    public let scope:  String
}

/// The caller's own identity row. `claims` holds raw JSON values
/// (`[String: Any]` from `JSONSerialization`; this codebase has no JSON
/// value enum), so the struct is not `Equatable`.
public struct IdentityNode {
    public let identityId:  String
    public let status:      String
    public let version:     Int
    public let createdAt:   String
    public let claims:      [String: Any]
    public let grants:      [GrantEntry]
    public let grantsValid: Bool
}

/// A device node. `role` is `"root"`, `"endorsed"` or `nil`; `status` is
/// `"active"` or `"revoked"`; `platform` is `"iphoneos"`, `"macosx"` or `nil`.
public struct GraphDeviceNode {
    public let deviceId:            String
    public let isCaller:            Bool
    public let role:                String?
    public let status:              String
    public let platform:            String?
    public let enrollmentMethod:    String?
    public let attestedAt:          String?
    public let pattern:             DevicePattern?
    public let createdAt:           String
    public let revokedAt:           String?
    public let revocationSeq:       Int?
    public let endorsedByDeviceId:  String?
    public let replacesDeviceId:    String?
    public let replacedByDeviceId:  String?
    /// Device ids the server would revoke along with this one.
    public let cascade:             [String]
    /// The non-secret attestation fields the server stored. `nil` when the device has
    /// no attestation evidence or the server predates the field.
    public let attestation:         GraphAttestation?
    /// Credential count and dates. `nil` only when the server predates the field.
    public let credentials:         GraphCredentials?
    /// Sign-in key (passkey) `jti`s that fall with this device; only a root carries any. Empty when none, or when
    /// the server predates the field. Separate from `cascade`, which holds device ids.
    public let cascadePasskeys:     [String]
}

/// A sign-in key (a passkey) a site holds under this identity. `status` is `"active"` or `"revoked"`. The graph
/// carries no credential id and no public key. Absent from servers that predate it.
public struct PasskeyNode: Equatable {
    public let jti:                       String
    public let rpId:                      String
    public let label:                     String
    public let status:                    String
    public let authorizerDeviceId:        String
    public let humanAuthorizationJti:     String
    public let identityVersionAtIssuance: Int
    public let issuedAt:                  String
    public let expiresAt:                 String
    public let revokedAt:                 String?
    public let revocationSeq:             Int?
    /// The sett Krutho drew for this key, or nil when the server predates the field or holds none for it.
    public let pattern:                   DevicePattern?
}

/// An mdoc Krutho issued under this identity (A4). `status` is `"active"`, `"revoked"`, or `"unknown"` for a status
/// this SDK does not know (treat it as not ended); `deviceId` is
/// the phone that holds it. Ids and dates only: no device key or thumbprint. The caller's own newest
/// mdoc is always listed when it has one, so the holder finds the mdoc it holds by `jti` and drops it
/// when the node says `"revoked"`. Absent from servers that predate it.
public struct MdocNode: Equatable {
    public let jti:                       String
    public let deviceId:                  String
    public let status:                    String
    public let humanAuthorizationJti:     String
    public let identityVersionAtIssuance: Int
    public let issuedAt:                  String
    public let expiresAt:                 String
    public let revokedAt:                 String?
    public let revocationSeq:             Int?
}

/// What a device attested, field by field; each is `nil` when the server holds
/// none. `bundleVersion` is an iPhone's, `codeHash` a Mac's. Never a raw blob.
public struct GraphAttestation: Equatable {
    public let environment:        String?
    public let validationCategory: Int?
    public let appId:              String?
    public let bundleVersion:      String?
    public let codeHash:           String?
}

/// Credentials valid at the snapshot (not revoked, not expired). `issuedAt` and
/// `expiresAt` belong to the newest of them and are `nil` when none is active.
public struct GraphCredentials: Equatable {
    public let active:    Int
    public let issuedAt:  String?
    public let expiresAt: String?
}

public struct AgentNode {
    public let jti:                       String
    public let agentId:                   String
    /// The approving credential's id. `nil` only when the server predates the field.
    public let humanAuthorizationJti:     String?
    public let status:                    String
    public let grants:                    [String: GrantEntry]?
    public let authorizerDeviceId:        String
    public let identityVersionAtIssuance: Int
    public let issuedAt:                  String
    public let expiresAt:                 String
    public let revokedAt:                 String?
    public let revocationSeq:             Int?
}

public struct SessionNode {
    public let sessionId:                 String
    public let status:                    String
    public let grants:                    [String: GrantEntry]
    public let identityVersionAtIssuance: Int
    public let createdAt:                 String
    public let expiresAt:                 String
    public let closedAt:                  String?
}

public struct AlertNode {
    public let alertId:            String
    public let endorsedDeviceId:   String
    public let approvedByDeviceId: String?
    public let createdAt:          String
    public let acknowledgedAt:     String?
    public let resolvedAt:         String?
}

public struct IdentityGraph {
    public let schemaVersion:      Int
    public let generatedAt:        String
    public let identity:           IdentityNode
    public let devices:            [GraphDeviceNode]
    public let agents:             [AgentNode]
    public let sessions:           [SessionNode]
    public let alerts:             [AlertNode]
    public let devicesTruncated:   Bool
    public let agentsTruncated:    Bool
    public let sessionsTruncated:  Bool
    public let alertsTruncated:    Bool
    /// Sign-in keys, active first. Empty when the server predates the field.
    public let passkeys:           [PasskeyNode]
    public let passkeysTruncated:  Bool
    /// Mdocs, active first, the caller's own newest always included. Empty when the server predates the field.
    public let mdocs:              [MdocNode]
    public let mdocsTruncated:     Bool
}

/// An open alert: a new device was endorsed on this person's identity.
/// `deviceId` is the new device; `approvedByDeviceId` the phone that approved.
public struct EndorsementAlert {
    public let alertId:            String
    public let deviceId:          String
    public let createdAt:         String
    public let approvedByDeviceId: String?
    public let pattern:           DevicePattern?
    public let attestation:       DeviceAttestationFacts?
    /// "active" or "revoked": the endorsed device's status in the same listing. "active" when the reply does not decide it.
    public let deviceStatus:      String
    public init(alertId: String, deviceId: String, createdAt: String, approvedByDeviceId: String?,
                pattern: DevicePattern?, attestation: DeviceAttestationFacts?, deviceStatus: String = "active") {
        self.alertId = alertId; self.deviceId = deviceId; self.createdAt = createdAt
        self.approvedByDeviceId = approvedByDeviceId; self.pattern = pattern
        self.attestation = attestation; self.deviceStatus = deviceStatus
    }
}

/// An open "new sign-in key" alert: a passkey was recorded
/// under this person's identity. "This is mine" is `acknowledgeAlert(alertId:)`;
/// removing the key is `revokePasskey(targetJti: jti)`, which resolves the alert
/// on every phone. `origin` is the origin the phone approved, scheme included;
/// `label` is the site's own word for the key.
public struct PasskeyAlert: Equatable {
    public let alertId:            String
    public let jti:                String
    public let origin:             String
    public let rpId:               String
    public let label:              String
    public let createdAt:          String
    public let approvedByDeviceId: String
    /// The key's sett, or nil when the server predates the field or holds none for it.
    public let pattern:            DevicePattern?
    public init(alertId: String, jti: String, origin: String, rpId: String, label: String,
                createdAt: String, approvedByDeviceId: String, pattern: DevicePattern? = nil) {
        self.alertId = alertId; self.jti = jti; self.origin = origin; self.rpId = rpId
        self.label = label; self.createdAt = createdAt; self.approvedByDeviceId = approvedByDeviceId
        self.pattern = pattern
    }
}

/// An open identity alert (A8): a device was removed (`device_retired`), a
/// recovery started (`recovery_started`) or completed (`recovery_completed`),
/// or (A5 batch B) a site signed someone in by ring (`ring_signin`).
/// Every active device of the person gets one, a Mac included. `subject` is
/// the removed or new device id, or for `recovery_started` the recovery's
/// transaction id, which `cancelRecovery(transactionId:)` takes, or for
/// `ring_signin` the sign-in's handle, which `endSiteSignIn(handle:)` takes.
/// `siteName` is the site's display name, set on `ring_signin` only. The row
/// carries no platform for its subject. Acknowledge it with
/// `acknowledgeAlert(alertId:)`; the alert id space is shared.
public struct IdentityAlert: Equatable {
    public let alertId:   String
    public let kind:      String
    public let subject:   String
    public let pattern:   DevicePattern?
    public let createdAt: String
    public let siteName:  String?
    public init(alertId: String, kind: String, subject: String, pattern: DevicePattern?, createdAt: String,
                siteName: String? = nil) {
        self.alertId = alertId; self.kind = kind; self.subject = subject
        self.pattern = pattern; self.createdAt = createdAt; self.siteName = siteName
    }
}

public struct DeviceListing {
    public let devices: [DeviceSummary]
    public let alerts:  [EndorsementAlert]
    /// Open "new sign-in key" alerts. Empty when the server predates them.
    public let passkeyAlerts: [PasskeyAlert]
    /// Open identity alerts (A8). Empty when the server predates them.
    public let identityAlerts: [IdentityAlert]
    public init(devices: [DeviceSummary], alerts: [EndorsementAlert], passkeyAlerts: [PasskeyAlert],
                identityAlerts: [IdentityAlert] = []) {
        self.devices = devices; self.alerts = alerts
        self.passkeyAlerts = passkeyAlerts; self.identityAlerts = identityAlerts
    }
}

/// `deviceAlerts()`: this device's own open alerts from the three tables,
/// for any active device, a Mac included. The server sends no
/// `deviceStatus` here, so each `EndorsementAlert.deviceStatus` reads
/// `"active"`.
public struct DeviceAlerts {
    public let alerts:         [EndorsementAlert]
    public let passkeyAlerts:  [PasskeyAlert]
    public let identityAlerts: [IdentityAlert]
    public init(alerts: [EndorsementAlert], passkeyAlerts: [PasskeyAlert], identityAlerts: [IdentityAlert]) {
        self.alerts = alerts; self.passkeyAlerts = passkeyAlerts; self.identityAlerts = identityAlerts
    }
}

public struct DeviceRevocation {
    public let deviceId:       String
    public let alreadyRevoked: Bool
    public init(deviceId: String, alreadyRevoked: Bool) {
        self.deviceId = deviceId; self.alreadyRevoked = alreadyRevoked
    }
}

/// One thing the identity approved (`approvals(since:target:)`). `kind` is
/// `"device"`, `"passkey"`, `"agent"`, `"mdoc"` or `"session"`;
/// `approvedByDeviceId` is `nil` when none is recorded. `pattern` comes on
/// device rows, `rpId` and `label` on sign-in keys, `agentId` on agents,
/// `origin` where the server records one.
public struct ApprovalRow: Equatable {
    public let kind:               String
    public let id:                 String
    public let approvedByDeviceId: String?
    public let createdAt:          String
    public let status:             String
    public let pattern:            DevicePattern?
    public let rpId:               String?
    public let label:              String?
    public let agentId:            String?
    public let origin:             String?
    public init(kind: String, id: String, approvedByDeviceId: String?, createdAt: String, status: String,
                pattern: DevicePattern? = nil, rpId: String? = nil, label: String? = nil,
                agentId: String? = nil, origin: String? = nil) {
        self.kind = kind; self.id = id; self.approvedByDeviceId = approvedByDeviceId
        self.createdAt = createdAt; self.status = status; self.pattern = pattern
        self.rpId = rpId; self.label = label; self.agentId = agentId; self.origin = origin
    }
}

/// `approvals(since:target:)`: the window start the server used (Unix
/// seconds), the rows newest first (at most 200), and whether more matched.
/// With `target`, the rows are what `containDevice(targetDeviceId:since:)`
/// on that device with the same `since` would end.
public struct Approvals: Equatable {
    public let since:     Int
    public let approvals: [ApprovalRow]
    public let truncated: Bool
    public init(since: Int, approvals: [ApprovalRow], truncated: Bool) {
        self.since = since; self.approvals = approvals; self.truncated = truncated
    }
}

/// `cancelRecovery(transactionId:)`: the held recovery was stopped, or the new
/// iPhone finished first (`completed`, with its device id and pattern).
public enum RecoveryCancelResult: Equatable {
    case cancelled
    case completed(deviceId: String, pattern: DevicePattern?)
}

/// Reply of `revokePasskey(targetJti:)`: the passkey's `jti` and whether it
/// was revoked earlier.
public struct PasskeyRevocation {
    public let jti:            String
    public let alreadyRevoked: Bool
}

/// Step 1 of `issueMdoc`: the single-use challenge (300 s), its tenant, and
/// the audience the host's `openid4vci-proof+jwt` must name
/// (`<audience>/v1/core/mdoc-credentials`).
public struct MdocIssueChallenge: Equatable {
    public let challenge: String
    public let tenant:    String
    public let audience:  String
}

/// core-api's 201 for `POST /v1/core/mdoc-credentials`, as sent. The host
/// decodes `issuerSigned` (base64url CBOR) and checks it before storing it.
public struct MdocIssued: Equatable {
    public let jti:          String
    public let docType:      String
    public let namespace:    String
    public let issuerSigned: String
    public let validFrom:    String
    public let validUntil:   String
    /// The device's earlier mdoc `jti`s this issue ended.
    public let replacedJtis: [String]
}

public enum Usage: String {
    case highAssurance     = "high-assurance"
    case standardAssurance = "standard-assurance"
}

/// The host enablement contract for App Attest at enrollment.
/// `.off` (the default, matching `SdkConfig.attestation`'s TS default): the
/// core never fetches a challenge and never sends `attestation`. `.on`: if
/// `IOSPlatform`'s App Attest component reports unsupported (an older Mac),
/// submit the enrollment without it, and the tenant's policy decides
/// (`attestation_required` when it sets `required: true`); if supported,
/// attest and send — any failure throws `.attestationFailed` and the core
/// never retries without attestation. A host turns this on only once Krutho
/// has told it the tenant is configured for App Attest (see the iOS README).
public enum AttestationMode: String {
    case off
    case on
    /// `.on`'s failure-intolerant sibling: an absent
    /// `platform.attestation` or `isSupported()` resolving `false` throws
    /// `.attestationFailed(detail:)` — `detail` starting `unsupported` —
    /// before any request is sent, instead of enrolling unattested. Opt in
    /// only once Krutho has confirmed the tenant's App Attest configuration
    /// is current; supported devices behave exactly as `.on`.
    case required
}

/// Whether an enrollment or an endorsement attach attested with App Attest,
/// and if not, why. The three reasons are the skips `.on` (and
/// `.required`, when supported) can report: attestation was turned `off`,
/// `platform.attestation` was `absent`, or App Attest's `isSupported()`
/// resolved `unsupported`. A failed challenge fetch or `attest()` call is not
/// a reason — it throws `.attestationFailed`.
public enum AttestationSkipReason: String {
    case off
    case absent
    case unsupported
}

/// Nested and optional so a host reads `result.attestation?.attested`: an
/// absent object means "not reported" (an older stored transaction), never
/// "unattested".
public struct AttestationOutcome {
    public let attested: Bool
    public let reason:   AttestationSkipReason?
}

public enum CredentialSdkError: Error, LocalizedError {
    case notInitialized
    case jsBridgeError(String)
    case jsonError(String)
    case networkUnreachable(operation: String)
    case secureEnclaveUnavailable
    case userAuthenticationFailed
    /// The high-assurance key exists but the platform refuses it because the
    /// enrolled biometric set changed since enrollment (`key_invalidated`).
    /// When the core SDK self-revoked, the high-assurance key is already
    /// destroyed and `revoked` says whether the server revocation succeeded:
    /// `true`, the device is revoked; `false`, the revocation failed (offline,
    /// for instance). `nil` when the message carried no `revoked=` field (no
    /// self-revoke ran, e.g. an unenrolled sign). `cleanupOk` reports local
    /// cleanup separately (`nil` without a `cleanup=` field). `retryable`
    /// alone says whether to retry `unenroll()`: `true`, retry; `false`, the
    /// local keys are gone and the device must re-enroll; `nil`, the core
    /// said neither. Either way the device must enroll afresh.
    case keyInvalidated(revoked: Bool?, cleanupOk: Bool?, retryable: Bool?)
    /// `unenroll()` reached the server and the server revoked this device,
    /// but deleting the local keys failed. Local state is kept; retry
    /// `unenroll()`. `detail` is the core's message.
    /// `retryable` (the core's `retryable=` token): `true`, local state was
    /// kept and `unenroll()` can be retried; `false`, keys are gone and a
    /// storage removal failed, so re-enroll instead; `nil` if absent.
    case unenrollCleanupFailed(detail: String, retryable: Bool?)
    /// The core SDK's `AlreadyEnrolledError`: `generateKeyPairs()` or
    /// `endorsementOpen(...)` was called on a device that already holds an
    /// enrollment (`device.id` set). Not retryable — the way out is
    /// `unenroll()` first, or `resetLocalState()` when the server enrollment
    /// is already gone.
    case alreadyEnrolled
    /// A high-assurance key cannot be created because no biometric is
    /// enrolled on the device (`biometry_not_enrolled`). High-assurance is
    /// biometric-only: there is no password fallback.
    case biometryNotEnrolled
    /// Any other failure in the key layer, typed. `code` is the stable
    /// machine-readable code the key layer stamps on the bridge message
    /// (`KeychainKeysError.bridgeCode`, e.g. `key_generation_failed`,
    /// `key_not_found`, `signing_failed`); `detail` is the platform's own
    /// text; `osStatus` is the `OSStatus` parsed out of that text when the
    /// platform reported one (`-34018` for a missing keychain entitlement,
    /// `-25308` for a locked screen). Hosts no longer parse the message.
    case keyError(code: String, detail: String, osStatus: Int32?)
    /// The core SDK's `AttestationFailedError`: the
    /// enrollment-challenge fetch or the native `attest()` call failed
    /// before the enroll request was ever sent. The core does not retry
    /// without attestation on this path. `detail` is the core's message
    /// (`attestation_failed: <stage>[: <cause>]`) verbatim.
    case attestationFailed(detail: String)
    /// The enroll POST itself was refused with one of core-api's
    /// attestation refusal codes (`attestation_invalid`,
    /// `attestation_refused`, `attestation_required`,
    /// `attestation_not_configured`) — distinct from `attestationFailed`,
    /// which covers the two client-side stages before the request is ever
    /// sent. `reason` is core-api's `error.message` detail when present.
    case attestationRefused(code: String, reason: String?)
    /// The core SDK's `DeviceExistsError`: `enrollWithOAuth2`
    /// was refused `409 device_exists` because the identity already has a
    /// device. Terminal — this identity's next device joins by endorsement,
    /// never a retry of the same call.
    case deviceExists
    /// One of the endorsement transaction routes refused with a `4xx` code:
    /// `code` is core-api's error code (or the
    /// endorse route's kernel refusal reason), `reason` the detail when
    /// present. Terminal — the SDK never retries on it.
    case endorsementRefused(code: String, reason: String?)
    /// The core SDK's `ResetCleanupError`: `resetLocalState()` wrote the
    /// tombstone but the cleanup did not finish. `retryable` mirrors
    /// `unenrollCleanupFailed`'s two meanings: `true`, a key destroy failed
    /// and storage is left in place; `false`, the keys are gone but a
    /// storage removal failed after every removal was attempted. Either way,
    /// retry `resetLocalState()`. `detail` is the core's message.
    case resetCleanupFailed(detail: String, retryable: Bool?)
    /// `fetchRevocationSnapshot()` got a 401 from either GET: the request
    /// was not authenticated. The status alone does not say why — a revoked
    /// device, a suspended or deleted identity, an expired or invalid
    /// device JWT, and a replayed/out-of-order jti all answer 401
    /// identically; this case does not guess which. `detail` is the
    /// server's own error body, preserved verbatim.
    case revocationSnapshotUnauthorized(detail: String)
    /// `fetchRevocationSnapshot()` found no snapshot for this tenant, or the
    /// paired data fetch's version was pruned on every retry the SDK
    /// attempts (the snapshot and its data are fetched as a pair).
    case revocationSnapshotNotFound(detail: String)
    /// `fetchRevocationSnapshot()` got a 503 from either GET: the snapshot
    /// is unavailable or stale. This covers more than age — the resolved
    /// row may be older than the server's maximum build age, or it may
    /// simply have no stored signature/digest yet (core-api prerequisite
    /// 1's migration). Either way, retry later; do not discard a filter
    /// already held. `detail` is the server's own error body, preserved
    /// verbatim.
    case revocationSnapshotStale(detail: String)
    /// The core does not perform this call: a second `CredentialSdk` over a
    /// storage whose Rust core runs with another configuration, key store or
    /// HTTP transport; or any call on an instance after `dispose()`.
    case unsupported(detail: String)
    /// A string argument holds an unpaired UTF-16 surrogate (an `NSString`
    /// can; a Swift `String` built from one keeps it underneath). Refused
    /// before the Rust core is called: the generated bindings would otherwise
    /// replace it with U+FFFD, and the core would sign text the caller never
    /// gave it. `argument` names the parameter.
    case invalidHostString(argument: String)

    public var errorDescription: String? {
        switch self {
        case .notInitialized:         return "CredentialSdk not initialized"
        case .jsBridgeError(let msg): return "CredentialSdk bridge error: \(msg)"
        case .jsonError(let msg):     return "CredentialSdk JSON error: \(msg)"
        case .networkUnreachable(let op):
            return "Online connection required to \(op). Please reconnect and try again."
        case .secureEnclaveUnavailable:
            return "Hardware-backed (Secure Enclave) key storage is unavailable; high-assurance keys cannot be created on this device."
        case .userAuthenticationFailed:
            return "User authentication for the high-assurance key was cancelled or failed."
        case .keyInvalidated(let revoked, let cleanupOk, let retryable):
            var tail = ""
            switch revoked {
            case .some(true):  tail += " The device has been revoked."
            case .some(false): tail += " Device revocation did not complete."
            case .none:        break
            }
            if cleanupOk == false { tail += " Local cleanup did not complete." }
            tail += Self.retryAdvice(retryable)
            return "The high-assurance key was invalidated because the enrolled biometrics changed; this device must enroll again.\(tail)"
        case .unenrollCleanupFailed(_, let retryable):
            // The core's detail is on the case, not echoed here: the advice
            // below is decided by `retryable` alone.
            return "The server revoked this device, but local cleanup did not complete.\(Self.retryAdvice(retryable))"
        case .alreadyEnrolled:
            return "This device already holds an enrollment; call unenroll() first, or resetLocalState() when the server enrollment is already gone."
        case .biometryNotEnrolled:
            return "No biometric is enrolled on this device; high-assurance keys require Touch ID or Face ID."
        case .keyError(let code, let detail, let osStatus):
            let status = osStatus.map { " (OSStatus \($0))" } ?? ""
            return "Key operation failed: \(code)\(status): \(detail)"
        case .attestationFailed(let detail):
            return "App Attest enrollment failed: \(detail)"
        case .attestationRefused(let code, let reason):
            let tail = reason.map { ": \($0)" } ?? ""
            return "Enrollment was refused by App Attest policy (\(code))\(tail)."
        case .deviceExists:
            return "This identity already has a device. Add this device by endorsement instead."
        case .endorsementRefused(let code, let reason):
            let tail = reason.map { ": \($0)" } ?? ""
            return "The endorsement request was refused (\(code))\(tail)."
        case .resetCleanupFailed(_, let retryable):
            // Same discipline as .unenrollCleanupFailed: the core's detail is
            // on the case, not echoed here.
            switch retryable {
            case .some(true):
                return "resetLocalState() could not finish clearing local state; the high-assurance key stays refused. Retry resetLocalState()."
            case .some(false):
                return "resetLocalState() destroyed the local keys, but residual local state could not be cleared. Retry resetLocalState() or recover app state."
            case .none:
                return "resetLocalState() could not finish clearing local state."
            }
        case .revocationSnapshotUnauthorized(let detail):
            return "Revocation snapshot request authentication failed: \(detail)"
        case .revocationSnapshotNotFound(let detail):
            return "No revocation snapshot is available: \(detail)"
        case .revocationSnapshotStale(let detail):
            return "Revocation snapshot unavailable or stale; retry later, do not discard a filter already held: \(detail)"
        case .unsupported(let detail):
            return "Not supported by the core: \(detail)"
        case .invalidHostString(let argument):
            return "\(argument) contains an unpaired UTF-16 surrogate and cannot be passed to the core."
        }
    }

    /// Advice keyed on the core's `retryable=`: retry only when `true`.
    private static func retryAdvice(_ retryable: Bool?) -> String {
        switch retryable {
        case .some(true):  return " Retry unenroll()."
        case .some(false): return " The local keys are gone; this device must re-enroll."
        case .none:        return ""
        }
    }
}

/// Swift mirror of `CredentialSdk.kt`. Every call runs on the Rust core (`credential-sdk-rs`, linked from
/// `CredentialSdkCore.xcframework` through its UniFFI bindings; `RustEngine`), on a serial `DispatchQueue` that
/// serializes this instance's calls. SDK v2 removed the JavaScript core that ran here before.
///
/// A one-shot `initTask` is fired at construction; every public method does
/// `try await initTask.value` before its own work so callers never observe
/// a pre-init SDK. `initialize()` is retained as an optional explicit
/// readiness signal (handy for splash screens) but is no longer required
/// before other calls.
public final class CredentialSdk {

    private let coreApiUrl: URL
    private let audience:   URL
    let platform:   IOSPlatform
    private let queue:      DispatchQueue
    let initTask:   Task<Void, Error>

    private let attestation: AttestationMode
    private let appBuild:    Int?

    /// The host's words for each approval's Face ID / Touch ID prompt (`init(... approvalPromptText:)`), or nil.
    private let approvalPromptText: ApprovalPromptText?

    /// Holds the Rust engine once `initTask` built it; read only on `queue`, after `initTask`.
    private final class RustSlot: @unchecked Sendable {
        var engine: RustEngine?
        /// Set by `dispose()`; every later call is refused (`runOnQueue`).
        var disposed = false
    }
    private let rustSlot = RustSlot()
    /// Test seams for the Mac passkey door (`CredentialSdk+MacPasskey.swift`); empty in production.
    let macPasskeySeams = MacPasskeySeams()
    /// The Rust engine once initialized; nil before `initTask` finishes and after `dispose()`.
    var rust: RustEngine? { rustSlot.engine }

    /// `appBuild`: the host app's integer `CFBundleVersion`, sent as `X-Krutho-App-Build` on the ring handle lookup
    /// (core-api's build gate). Nil sends no header, and the server then refuses that lookup.
    ///
    /// `approvalPromptText`: the words the Face ID / Touch ID prompt shows for each approval, in the app's own voice
    /// and language. The SDK calls it once per approval, just before the prompt, with the approval's `ApprovalPrompt`
    /// (its kind, the core's `defaultText` and the details the public API already gave the host). It returns the
    /// text, or nil for `defaultText`; an empty or whitespace-only text also falls back to `defaultText`, and a text
    /// longer than `ApprovalPrompt.maximumTextLength` characters is cut to it. Nil (the default): every prompt says
    /// `defaultText`.
    ///
    /// The text changes only what the system prompt shows: never the bytes signed, the approval's allowed signature
    /// count, the transaction or its facts.
    ///
    /// Threading: it runs synchronously on the SDK's own serial queue (never the main thread), while the person waits
    /// for the prompt and while the SDK holds its core's gate and the approval's signing scope: until it returns the
    /// prompt does not appear and a cancel of the approval waits for it. Return quickly from state the closure already
    /// holds (a snapshot of names, a localized format). Never block waiting on an SDK call: one on this SDK waits on
    /// its serial queue, which the hook occupies, and one on any `CredentialSdk` sharing the core waits on the gate
    /// the approval holds; either deadlocks. Do not block on the main thread. A crash in it is a crash of the app.
    ///
    /// iOS and macOS only; Android follows.
    public init(
        coreApiUrl: URL,
        audience:   URL? = nil,
        platform:   IOSPlatform = IOSPlatform(),
        attestation: AttestationMode = .off,
        appBuild: Int? = nil,
        approvalPromptText: ApprovalPromptText? = nil
    ) {
        self.coreApiUrl  = coreApiUrl
        self.audience    = audience ?? coreApiUrl
        self.platform    = platform
        self.attestation = attestation
        self.appBuild    = appBuild
        self.approvalPromptText = approvalPromptText
        self.queue       = DispatchQueue(label: "com.krutho.credentialsdk.core")

        // Every public call awaits `initTask` first. It builds the one Rust core for this storage
        // (RustEngine.engine), after checking the keychain is usable: initialization fails, typed, rather than run on
        // storage that forgets the invalidation tombstone at the next launch.
        let queue = self.queue
        let slot = self.rustSlot
        let platform = self.platform
        let coreApiUrl = self.coreApiUrl, audience = self.audience
        let attestation = self.attestation, appBuild = self.appBuild
        self.initTask = Task {
            try await Self.enqueue(on: queue) {
                try platform.storage.checkAvailable()
                let config = try RustEngine.config(coreApiUrl: coreApiUrl, audience: audience,
                                                   attestation: attestation, appBuild: appBuild)
                do {
                    slot.engine = try RustEngine.engine(platform: platform, config: config)
                } catch {
                    throw RustEngine.bridged(error)
                }
                NSLog("[CredentialSdk] Rust core \(Self.rustCoreVersion()) initialized (coreApiUrl=\(config.coreApiUrl))")
            }
        }
    }

    /// True when this device/process can create Secure Enclave keys.
    public static var secureEnclaveAvailable: Bool { KeychainKeys.secureEnclaveAvailable }

    /// Optional explicit readiness wait. Every public method already awaits
    /// the same one-shot `initTask` internally — you do not need to call
    /// this before other methods. Useful only if the caller wants to block
    /// on init completion explicitly (e.g. to time a splash screen).
    public func initialize() async throws {
        try await initTask.value
    }

    /// Releases this instance's reference to the Rust engine, so the shared core (and the pending approval it holds)
    /// goes when the last live instance over that storage disposes, and another configuration can then be built over
    /// the storage; instances still live keep working. Later calls on the disposed instance throw
    /// `CredentialSdkError.unsupported`; a second `dispose()` is a no-op.
    public func dispose() async throws {
        try await initTask.value
        let slot = rustSlot
        try await Self.enqueue(on: queue) {
            slot.engine = nil
            slot.disposed = true
        }
    }

    public func getState() async throws -> String {
        try await initTask.value
        return try await runOnQueue { rust in
            return try rust.getStateJson()
        }
    }

    public func generateKeyPairs() async throws {
        try await initTask.value
        try await runOnQueue { rust in
            do {
                return try rust.generateKeyPairs()
            } catch {
                if let alreadyEnrolled = Self.mapAlreadyEnrolledError(error) {
                    throw alreadyEnrolled
                }
                throw Self.mapKeyError(error)
            }
        }
    }

    public func enrollWithOAuth2(accessToken: String) async throws -> EnrollResult {
        try await initTask.value
        return try await runOnQueue { rust in
            NSLog("[CredentialSdk] enrollWithOAuth2 starting (accessToken length=\(accessToken.count))")
            do {
                return try rust.enroll(accessToken: accessToken)
            } catch {
                NSLog("[CredentialSdk] enrollWithOAuth2 failed: \(error.localizedDescription)")
                if let attestationError = Self.mapAttestationError(error) {
                    throw attestationError
                }
                if Self.isNetworkUnreachable(error) {
                    throw CredentialSdkError.networkUnreachable(operation: "enroll")
                }
                throw Self.mapKeyError(error)
            }
        }
    }

    public func sync() async throws -> String {
        try await initTask.value
        return try await runOnQueue { rust in
            return try rust.syncJson()
        }
    }

    /// Fetch the tenant's current signed CRLite revocation
    /// snapshot. See
    /// `RevocationSnapshot`'s doc comment for what is and is not verified.
    public func fetchRevocationSnapshot() async throws -> RevocationSnapshot {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.fetchRevocationSnapshot()
            } catch {
                throw Self.mapRevocationSnapshotError(error)
            }
        }
    }

    public func unenroll() async throws {
        try await initTask.value
        try await runOnQueue { rust in
            do {
                return try rust.unenroll()
            } catch {
                throw Self.mapUnenrollError(error)
            }
        }
    }

    /// Clear every trace of an enrollment from this device without contacting
    /// the server. It revokes nothing. Use it only when the server
    /// enrollment is already gone or revoked — the identity was deleted, an
    /// operator revoked the device, or `sync()` answered revoked and
    /// `unenroll()` cannot reach the server. On an active enrollment it
    /// leaves a server row with live credentials that no device can use; the
    /// operator revokes that row. `unenroll()` first, always, is the
    /// documented sequence.
    public func resetLocalState() async throws {
        try await initTask.value
        try await runOnQueue { rust in
            do {
                return try rust.resetLocalState()
            } catch {
                throw Self.mapResetError(error)
            }
        }
    }

    public func createPresentation(authRequest: String) async throws -> PresentationResult {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.createPresentation(authRequest: authRequest)
            } catch {
                throw Self.mapKeyError(error)
            }
        }
    }

    // MARK: - Endorsement

    /// The enrolling device's first step: generate keys, open the
    /// transaction, attest with the transaction nonce when the host
    /// opted in, attach both public keys, and return what the host shows
    /// while it waits for the phone. Refuses on an already-enrolled device
    /// (the core SDK's own check). `kind` is `.endorsement` for a pairing (the
    /// default) and `.rootProof` for a recovery on a fresh iPhone.
    public func endorsementOpen(tenant: String, origin: String, replaces: String? = nil,
                                kind: EndorsementKind = .endorsement) async throws -> EndorsementOpened {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.endorsementOpen(tenant: tenant, origin: origin, replaces: replaces, kind: kind)
            } catch {
                if let endorsementError = Self.mapEndorsementError(error) {
                    throw endorsementError
                }
                if Self.isNetworkUnreachable(error) {
                    throw CredentialSdkError.networkUnreachable(operation: "enroll")
                }
                throw Self.mapKeyError(error)
            }
        }
    }

    /// `GET /enroll/transaction/:id/status` under the stored capability.
    /// Returns the raw JSON body (`{"status","expiresAt"}`), the `getState()`
    /// convention — the host parses what it needs.
    public func endorsementStatus() async throws -> String {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.endorsementStatusJson()
            } catch {
                if let endorsementError = Self.mapEndorsementError(error) {
                    throw endorsementError
                }
                if Self.isNetworkUnreachable(error) {
                    throw CredentialSdkError.networkUnreachable(operation: "enroll")
                }
                throw Self.mapKeyError(error)
            }
        }
    }

    /// The enrolling device's last step: two fresh proofs, `POST
    /// /enroll/transaction/finish` under the stored capability, then the
    /// result stored exactly as `enrollWithOAuth2` stores it. Lost delivery:
    /// a thrown transport error or a native `status: 0` response
    /// throws `.networkUnreachable(operation: "finish")` and leaves the
    /// transaction stored, so calling `endorsementFinish()` again signs fresh
    /// proofs over the same keys and receives the server's retained response.
    public func endorsementFinish() async throws -> EnrollResult {
        try await initTask.value
        let hook = finishTurnHook
        let attemptHook = finishAttemptHook
        return try await runOnQueue { rust in
            // One uninterrupted queue turn: the status request, the watcher, the attempt and
            // the finish all read the same stored transaction, so no endorsementOpen() can land between them.
            // While finish waits on Touch ID the core cannot poll, so the native watcher does: if the phone
            // cancels or the row expires, the prompt is withdrawn and finish throws the refusal the server would.
            // The attempt and the watcher bind to the keys the signature is made through: a shared core signs
            // through the first SDK's keys, whichever SDK's finish this is.
            let keys = rust.keys
            // The core's gate (`RustEngine.gate`), held across the whole finish: the attempt lives on the shared keys,
            // and no other SDK sharing the core may sign under it. Declared before the attempt's defer below, so it is released after the attempt ends.
            rust.gate.lock()
            defer { rust.gate.unlock() }
            let requestJson: String? = rust.endorsementStatusRequest().flatMap { request in
                (try? JSONSerialization.data(withJSONObject: ["url": request.url, "authorization": request.authorization],
                                             options: [.sortedKeys, .withoutEscapingSlashes]))
                    .map { String(decoding: $0, as: UTF8.self) }
            }
            hook?("request \(requestJson ?? "none")")
            let attempt = AuthAttempt()
            let watcher = requestJson.flatMap { FinishWatcher.forStatusRequest($0, http: rust.http) { keys.cancel(attempt) } }
            keys.beginAttempt(attempt)
            attemptHook?(keys, attempt)
            watcher?.start()
            defer {
                keys.endAttempt(attempt)   // the watcher's authority ends before anything else can sign
                watcher?.stop()
                hook?("finish done")
            }
            do {
                return try rust.endorsementFinish()
            } catch {
                if let ended = watcher?.endedState {
                    throw CredentialSdkError.endorsementRefused(code: "transaction_state", reason: "not finishable (\(ended))")
                }
                if let endorsementError = Self.mapEndorsementError(error) {
                    throw endorsementError
                }
                if Self.isNetworkUnreachable(error) {
                    throw CredentialSdkError.networkUnreachable(operation: "finish")
                }
                throw Self.mapKeyError(error)
            }
        }
    }

    /// Tests only: called inside `endorsementFinish()`'s queue turn ("request …" once the watcher's request is
    /// read, "finish done" as the turn ends), so a test can try to slip another call in between.
    var finishTurnHook: ((String) -> Void)?

    /// Tests only: called inside `endorsementFinish()` right after the attempt begins, with the keys it is bound to.
    var finishAttemptHook: ((KeychainKeys, AuthAttempt) -> Void)?

    /// The phone's first step: `GET /enroll/transaction/:id` for the
    /// transaction the scanned QR names, and approve the server's fields for
    /// `endorse(transactionId:)`. The reply carries the facts screen 2 shows
    /// (when the new device asked, how it attested), from the server's row,
    /// never from the QR. The backup to `endorsementInspectOptical(payload:)`: the QR carries no commitment, so
    /// only the pattern binds the phone to the keys this Mac holds; pass `QRPairingLink.qrPayload(fromScanned:)`.
    public func endorsementInspect(qrPayload: String) async throws -> EndorsementInvitation {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.endorsementInspect(qrPayload: qrPayload)
            } catch {
                if let endorsementError = Self.mapEndorsementError(error) {
                    throw endorsementError
                }
                if Self.isNetworkUnreachable(error) {
                    throw CredentialSdkError.networkUnreachable(operation: "enroll")
                }
                throw Self.mapKeyError(error)
            }
        }
    }

    /// The phone's first step from the camera: the 24 bytes
    /// `OpticalPairingReader` collected (transaction id, commitment, origin
    /// tag). The core checks the commitment and the origin tag against the
    /// server's row before it approves anything, and throws if either does
    /// not match; a refusal leaves nothing `endorse(transactionId:)` will sign.
    public func endorsementInspectOptical(payload: Data) async throws -> EndorsementInvitation {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.endorsementInspectOptical(payload: payload)
            } catch {
                if let endorsementError = Self.mapEndorsementError(error) {
                    throw endorsementError
                }
                if Self.isNetworkUnreachable(error) {
                    throw CredentialSdkError.networkUnreachable(operation: "enroll")
                }
                throw Self.mapKeyError(error)
            }
        }
    }

    // MARK: - Site sign-in (optical payload version 2)

    /// The phone's first step from a sign-in ring: the 12 bytes `OpticalPairingReader` collected (6 handle bytes,
    /// then the first 6 bytes of the sign-in digest). Any other length is refused by the core before a request
    /// leaves. The core looks the handle up under this device's auth (an active root only), recomputes the digest
    /// from the fields Krutho returns, and throws if its first 6 bytes differ from the ring's commitment. Nothing is
    /// signed. A pairing payload (24 bytes) goes to `endorsementInspectOptical(payload:)`, never here.
    public func signInInspectOptical(payload: Data) async throws -> SiteSignInInvitation {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.signInInspectOptical(payload: payload)
            } catch {
                throw Self.mapDeviceCallError(error)
            }
        }
    }

    /// The phone's answer: present the high-assurance identity credential over the invitation's digest (one Face ID,
    /// the key's own policy) and post it to the site's response URI. Requires `signInInspectOptical(payload:)` for
    /// this handle through this `CredentialSdk` instance; the core signs from what it checked then, never from fields
    /// the caller holds. The site's refusal comes back as `.endorsementRefused(code:reason:)` with the site's
    /// `reason` as `code`, verbatim.
    @discardableResult
    public func signInPresent(_ invitation: SiteSignInInvitation) async throws -> SiteSignInResult {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.signInPresent(invitation, prompt: self.approvalPromptText)
            } catch {
                throw Self.mapDeviceCallError(error)
            }
        }
    }

    /// "End it" on a `ring_signin` alert (A5 batch B): end the browser session a ring sign-in opened, by the alert's
    /// `subject` (the sign-in's handle). Device auth, no Face ID: ending only removes access. Idempotent. Any active
    /// device of the identity may end it, a Mac included; a handle that is not this identity's is refused
    /// `.endorsementRefused(code: "not_found", ...)`.
    @discardableResult
    public func endSiteSignIn(handle: String) async throws -> SiteSignInEnded {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.endSiteSignIn(handle: handle)
            } catch {
                throw Self.mapDeviceCallError(error)
            }
        }
    }

    /// The phone's authorization: present the high-assurance identity
    /// credential over the canonical digest and post it with the phone's
    /// everyday key. Requires a prior `endorsementInspectOptical(payload:)`
    /// (or the backup QR's `endorsementInspect(qrPayload:)`) for this
    /// `transactionId` through this `CredentialSdk` instance. One Face ID per
    /// approval: a second call on the same approval refuses before it
    /// prompts, and a failed send spends the approval (rescan while the new
    /// device still shows the pattern). Returns the pattern the server froze
    /// for the new device (`pattern` is `nil` when the tenant has none): show
    /// it on the confirm-after screen.
    @discardableResult
    public func endorse(transactionId: String) async throws -> EndorsementApproved {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.endorse(transactionId: transactionId, prompt: self.approvalPromptText)
            } catch {
                throw Self.mapDeviceCallError(error)
            }
        }
    }

    /// The phone's "No, remove it" on the confirm-after screen: cancel the
    /// transaction while it is still authorized. When the new device already
    /// finished, the answer is `.consumed(deviceId:pattern:)` and the caller
    /// goes on to `revokeDevice(targetDeviceId:)`.
    public func endorsementCancel(transactionId: String) async throws -> EndorsementCancelled {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.endorsementCancel(transactionId: transactionId)
            } catch {
                throw Self.mapDeviceCallError(error, operation: "cancel")
            }
        }
    }

    // MARK: - Devices (root phone only)

    /// This identity's devices and this device's open alerts. Refused
    /// `.endorsementRefused(code: "forbidden", ...)` unless this device is an
    /// active root. Showing the list never acknowledges an alert.
    public func devicesList() async throws -> DeviceListing {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.devicesList()
            } catch {
                throw Self.mapDeviceCallError(error, operation: "devicesList")
            }
        }
    }

    // MARK: - Identity graph (root phone only)

    /// The caller's identity and everything under it, one snapshot. Refused
    /// `.endorsementRefused(code: "forbidden", ...)` unless this device is an
    /// active root.
    public func identityGraph() async throws -> IdentityGraph {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.identityGraph()
            } catch {
                throw Self.mapDeviceCallError(error, operation: "identityGraph")
            }
        }
    }

    /// "That was me": acknowledge one alert. Idempotent.
    public func acknowledgeAlert(alertId: String) async throws {
        try await initTask.value
        try await runOnQueue { rust in
            do {
                return try rust.acknowledgeAlert(alertId: alertId)
            } catch {
                throw Self.mapDeviceCallError(error, operation: "acknowledgeAlert")
            }
        }
    }

    /// "Not me" / "No, remove it" after finish: ask the server to revoke one
    /// of this identity's non-root devices, with a Face ID presentation of the
    /// high-assurance credential (raised inside this call, not by a screen).
    /// A device that was already revoked answers `alreadyRevoked: true`.
    public func revokeDevice(targetDeviceId: String) async throws -> DeviceRevocation {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.revokeDevice(targetDeviceId: targetDeviceId, prompt: self.approvalPromptText)
            } catch {
                throw Self.mapDeviceCallError(error, operation: "revokeDevice")
            }
        }
    }

    /// Mark a device of this identity compromised (A8): a challenge, a Face ID
    /// presentation of the high-assurance credential over
    /// `krutho-device-contain/1` (raised inside this call), then the revoke with
    /// `mode: "compromised"`. Ends the target and what it approved since `since`
    /// (Unix seconds, `0` for everything). Root phone only; the target may be
    /// any device of the identity, active or removed, this phone included. A
    /// negative `since` throws `.jsonError` before anything is sent.
    public func containDevice(targetDeviceId: String, since: Int) async throws -> DeviceRevocation {
        guard since >= 0 else {
            throw CredentialSdkError.jsonError("containDevice: since must be 0 or more, got \(since)")
        }
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.containDevice(targetDeviceId: targetDeviceId, since: since, prompt: self.approvalPromptText)
            } catch {
                throw Self.mapDeviceCallError(error, operation: "containDevice")
            }
        }
    }

    /// This device's own open alerts from the three tables (A8), for any active
    /// device, a Mac included. Reading never acknowledges.
    public func deviceAlerts() async throws -> DeviceAlerts {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.deviceAlerts()
            } catch {
                throw Self.mapDeviceCallError(error, operation: "deviceAlerts")
            }
        }
    }

    /// What this identity approved (A8): devices, sign-in keys, agents, mdocs
    /// and sessions since `since` (Unix seconds; `nil` is the server's 30 days),
    /// newest first, at most 200. With `target`, only what
    /// `containDevice(targetDeviceId: target, since: since)` would end. Root
    /// phone only; anything else is `.endorsementRefused(code: "forbidden", ...)`.
    public func approvals(since: Int? = nil, target: String? = nil) async throws -> Approvals {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.approvals(since: since, target: target)
            } catch {
                throw Self.mapDeviceCallError(error, operation: "approvals")
            }
        }
    }

    /// Stop a held recovery from a surviving device, a Mac included (A8): a
    /// challenge naming the held recovery, a Face ID or Touch ID presentation
    /// over `krutho-recovery-cancel/1` (raised inside this call), then the
    /// cancel. `transactionId` is a `recovery_started` alert's `subject`; when
    /// the held recovery is another one the call throws before any prompt.
    /// `.completed` means the new iPhone finished first.
    public func cancelRecovery(transactionId: String) async throws -> RecoveryCancelResult {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.cancelRecovery(transactionId: transactionId, prompt: self.approvalPromptText)
            } catch {
                throw Self.mapDeviceCallError(error, operation: "cancelRecovery")
            }
        }
    }

    /// Remove one of the person's passkeys: a challenge from
    /// the shared revoke-challenge route, a Face ID presentation of the
    /// high-assurance credential over `krutho-passkey-revoke/1` (raised inside
    /// this call, as `revokeDevice` does), then the passkey revoke. A passkey
    /// that was already revoked answers `alreadyRevoked: true`.
    public func revokePasskey(targetJti: String) async throws -> PasskeyRevocation {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.revokePasskey(targetJti: targetJti, prompt: self.approvalPromptText)
            } catch {
                throw Self.mapDeviceCallError(error, operation: "revokePasskey")
            }
        }
    }

    /// Root iPhone, the mdoc port: a single-use challenge from the shared
    /// challenge route, its tenant and the proof audience. Signs only the
    /// everyday device JWT (no prompt).
    public func mdocIssueChallenge() async throws -> MdocIssueChallenge {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.mdocIssueChallenge()
            } catch {
                throw Self.mapDeviceCallError(error, operation: "mdocIssueChallenge")
            }
        }
    }

    /// Root iPhone, the mdoc port (SDK v2): issue an mdoc over the host's new mdoc key in one approval.
    /// `deviceKeyX`/`deviceKeyY` are the key's base64url coordinates.
    ///
    /// The SDK builds the key's `openid4vci-proof+jwt` signing input itself (header `jwk` the key, `aud` the mdoc
    /// audience, `iat` now, a fresh `jti`, `nonce` the challenge), opens one authentication scope (one Face ID), and
    /// calls `hostProof` **exactly once** inside it with that input and the scope's live, evaluated `LAContext`.
    /// `hostProof` answers the raw 64-byte `r || s` ES256 signature of `signingInput` by the new key, signed on that
    /// context (`KruthoSecureArea.signProof(storage:id:data:context:)`); it must not keep the context. The SDK verifies
    /// the signature with the key over its own input (a wrong key or other bytes: nothing is sent, and the approval
    /// is spent), assembles the proof, makes its own high-assurance presentation over `krutho-mdoc-issue/1` on the
    /// same context, invalidates the context and sends `POST /v1/core/mdoc-credentials`.
    ///
    /// When `hostProof` throws, nothing is signed or sent, the approval rolls back, and its own error is rethrown
    /// unchanged. When the scope's Face ID fails or is cancelled, nothing is signed or sent either, and the call throws
    /// that evaluation's `LAError` unchanged (`.userCancel`, `.systemCancel`, `.appCancel`, ...), as the host's own
    /// evaluation surfaced it before SDK v2, not `CredentialSdkError.userAuthenticationFailed`. Inside `hostProof` the host holds a live context and could sign other keys it can reach; the SDK
    /// cannot count that. After this call returns the context cannot sign.

    public func issueMdoc(challenge: String, tenant: String, deviceKeyX: String, deviceKeyY: String,
                          hostProof: @escaping @Sendable (_ signingInput: Data, _ context: LAContext) async throws -> Data)
        async throws -> MdocIssued {
        try await initTask.value
        return try await runOnQueue { rust in
            do {
                return try rust.issueMdoc(challenge: challenge, tenant: tenant, deviceKeyX: deviceKeyX,
                                          deviceKeyY: deviceKeyY, prompt: self.approvalPromptText, hostProof: hostProof)
            } catch let error as JsBridgeError {
                throw Self.mapDeviceCallError(error, operation: "issueMdoc")
            }
        }
    }

    /// True when this SDK can draw the pattern: version 1 and
    /// `0 <= entry < N` for the v1 list it ships. Matches the core's
    /// `patternKnown`.
    public static func patternKnown(_ p: DevicePattern?) -> Bool {
        guard let p else { return false }
        return SettGeometry.entry(p) != nil
    }

    // MARK: - Private

    /// Runs `work` on this instance's queue with its Rust engine; refused once `dispose()` released it.
    func runOnQueue<T>(_ work: @escaping (RustEngine) throws -> T) async throws -> T {
        let slot = rustSlot
        return try await Self.enqueue(on: queue) {
            guard !slot.disposed, let rust = slot.engine else {
                throw CredentialSdkError.unsupported(detail: "this CredentialSdk was disposed; build a new one")
            }
            return try work(rust)
        }
    }

    private static func enqueue<T>(on queue: DispatchQueue, _ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    continuation.resume(returning: try work())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// The error mapping every endorsement-family call shares: the typed
    /// endorsement prefixes, then a network failure, then the key layer.
    static func mapDeviceCallError(_ error: Error, operation: String = "enroll") -> Error {
        if let endorsementError = mapEndorsementError(error) {
            return endorsementError
        }
        if isNetworkUnreachable(error) {
            return CredentialSdkError.networkUnreachable(operation: operation)
        }
        return mapKeyError(error)
    }

    /// Detect whether a thrown error carries the core SDK's
    /// `network_unreachable:` prefix. The core embeds the code in its error
    /// message (`JsBridgeError.jsException`, `RustEngine.bridged`).
    static func isNetworkUnreachable(_ error: Error) -> Bool {
        if let bridgeError = error as? JsBridgeError,
           case .jsException(let msg) = bridgeError {
            return msg.contains("network_unreachable")
        }
        return error.localizedDescription.contains("network_unreachable")
    }

    /// Detect the core SDK's two item-J attestation errors and map them to
    /// typed `CredentialSdkError` cases, or `nil` when `error` is neither.
    /// Checked ahead of `mapKeyError`/`isNetworkUnreachable` in
    /// `enrollWithOAuth2` — a bare `attestation_failed:`/`attestation_refused:`
    /// message never shares a prefix with `key_error:` or
    /// `network_unreachable`, so ordering only matters for readability here,
    /// not correctness.
    ///
    /// `AttestationFailedError`'s message (`enrollment/oauth2.ts`):
    /// `attestation_failed: <stage>[: <cause>]`. `AttestationRefusedError`'s
    /// message: `attestation_refused: <status> <code>[: <reason>]` — the
    /// `<status> <code>` pair is core-api's HTTP status and refusal code,
    /// not read further here since `.attestationRefused` only carries `code`
    /// and `reason`, the fields a host acts on.
    static func mapAttestationError(_ error: Error) -> CredentialSdkError? {
        let msg = (error as? JsBridgeError).flatMap { if case .jsException(let m) = $0 { return m } else { return nil } }
                  ?? error.localizedDescription
        if msg.hasPrefix("attestation_failed:") {
            let detail = msg.dropFirst("attestation_failed:".count).trimmingCharacters(in: .whitespaces)
            return .attestationFailed(detail: detail)
        }
        guard msg.hasPrefix("attestation_refused:") else { return nil }
        let rest = msg.dropFirst("attestation_refused:".count).trimmingCharacters(in: .whitespaces)
        // rest = "<status> <code>[: <reason>]"
        guard let firstSpace = rest.firstIndex(of: " ") else {
            return .attestationRefused(code: rest.isEmpty ? "unknown" : String(rest), reason: nil)
        }
        let codeAndReason = rest[rest.index(after: firstSpace)...]
        if let colonRange = codeAndReason.range(of: ": ") {
            let code = String(codeAndReason[..<colonRange.lowerBound])
            let reason = String(codeAndReason[colonRange.upperBound...])
            return .attestationRefused(code: code, reason: reason)
        }
        return .attestationRefused(code: String(codeAndReason), reason: nil)
    }

    /// Detect the core SDK's `device_exists:` and `endorsement_refused:`
    /// prefixes and map them to typed `CredentialSdkError`
    /// cases, or `nil` when `error` is neither. Checked ahead of
    /// `mapKeyError`/`isNetworkUnreachable` in every endorsement method — the
    /// `mapAttestationError` pattern (339-359), since neither prefix shares
    /// a substring with `key_error:` or `network_unreachable`.
    static func mapEndorsementError(_ error: Error) -> CredentialSdkError? {
        if let alreadyEnrolled = mapAlreadyEnrolledError(error) {
            return alreadyEnrolled
        }
        let msg = (error as? JsBridgeError).flatMap { if case .jsException(let m) = $0 { return m } else { return nil } }
                  ?? error.localizedDescription
        if msg.hasPrefix("device_exists:") {
            return .deviceExists
        }
        guard msg.hasPrefix("endorsement_refused:") else { return nil }
        let rest = msg.dropFirst("endorsement_refused:".count).trimmingCharacters(in: .whitespaces)
        // rest = "<status> <code>[: <reason>]"
        guard let firstSpace = rest.firstIndex(of: " ") else {
            return .endorsementRefused(code: rest.isEmpty ? "unknown" : String(rest), reason: nil)
        }
        let codeAndReason = rest[rest.index(after: firstSpace)...]
        if let colonRange = codeAndReason.range(of: ": ") {
            let code = String(codeAndReason[..<colonRange.lowerBound])
            let reason = String(codeAndReason[colonRange.upperBound...])
            return .endorsementRefused(code: code, reason: reason)
        }
        return .endorsementRefused(code: String(codeAndReason), reason: nil)
    }

    /// Detect whether a thrown error carries the key layer's `key_error:<code>:`
    /// prefix and, if so, map it to a typed `CredentialSdkError`. The core
    /// embeds the code in its error message (same substring technique as
    /// `isNetworkUnreachable`).
    static func mapKeyError(_ error: Error) -> Error {
        let msg = (error as? JsBridgeError).flatMap { if case .jsException(let m) = $0 { return m } else { return nil } }
                  ?? error.localizedDescription
        // Classify on the code token only: a detail that
        // mentions another code must not change the classification.
        switch parseKeyErrorCode(msg) {
        case "secure_enclave_unavailable": return CredentialSdkError.secureEnclaveUnavailable
        case "user_auth_failed":           return CredentialSdkError.userAuthenticationFailed
        case "biometry_not_enrolled":      return CredentialSdkError.biometryNotEnrolled
        case "key_invalidated":
            let tokens = keyInvalidatedTokens(msg)
            return CredentialSdkError.keyInvalidated(revoked: tokens.revoked, cleanupOk: tokens.cleanupOk,
                                                     retryable: tokens.retryable)
        default: break
        }
        if let parsed = parseKeyError(msg) {
            return CredentialSdkError.keyError(code: parsed.code, detail: parsed.detail, osStatus: parsed.osStatus)
        }
        return error
    }

    /// The key-error code token, by the same rule as credential-sdk-core's
    /// `parseKeyErrorCode`: the text after the FIRST `key_error:` up to the
    /// next `:`, taken exactly. `nil` when there is no `key_error:`, no
    /// terminating `:`, or the token is empty.
    static func parseKeyErrorCode(_ message: String) -> String? {
        guard let range = message.range(of: "key_error:") else { return nil }
        let rest = message[range.upperBound...]
        guard let colon = rest.firstIndex(of: ":") else { return nil }
        let code = String(rest[..<colon])
        return code.isEmpty ? nil : code
    }

    /// The core's `KeyInvalidatedError` detail:
    /// `revoked=<true|false> cleanup=<ok|failed> retryable=<true|false> <text>`.
    /// Each is read only at its position (first, second, third); anything
    /// else is `nil`.
    static func keyInvalidatedTokens(_ message: String) -> (revoked: Bool?, cleanupOk: Bool?, retryable: Bool?) {
        guard let parsed = splitKeyError(message) else { return (nil, nil, nil) }
        let tokens = parsed.detail.split(separator: " ", maxSplits: 3).map(String.init)
        let revoked: Bool?
        switch tokens.first {
        case "revoked=true":  revoked = true
        case "revoked=false": revoked = false
        default:              return (nil, nil, nil)
        }
        let cleanupOk: Bool?
        switch tokens.count > 1 ? tokens[1] : "" {
        case "cleanup=ok":     cleanupOk = true
        case "cleanup=failed": cleanupOk = false
        default:               cleanupOk = nil
        }
        // retryable= only as the third token, and only after a cleanup= token.
        let retryable: Bool?
        switch cleanupOk != nil && tokens.count > 2 ? tokens[2] : "" {
        case "retryable=true":  retryable = true
        case "retryable=false": retryable = false
        default:                retryable = nil
        }
        return (revoked, cleanupOk, retryable)
    }

    /// Detect the core SDK's `already_enrolled:` prefix and map it to
    /// `.alreadyEnrolled`, or `nil` when `error` carries no such prefix — a
    /// `key_error:` or `network_unreachable` message returns `nil` here.
    /// Checked ahead of `mapKeyError` in `generateKeyPairs()` and ahead of
    /// every other prefix in `mapEndorsementError`, so `endorsementOpen(...)`
    /// maps it too.
    static func mapAlreadyEnrolledError(_ error: Error) -> CredentialSdkError? {
        let msg = (error as? JsBridgeError).flatMap { if case .jsException(let m) = $0 { return m } else { return nil } }
                  ?? error.localizedDescription
        guard msg.hasPrefix("already_enrolled:") else { return nil }
        return .alreadyEnrolled
    }

    /// `resetLocalState()`'s errors: the core's `ResetCleanupError` (message
    /// starts with `reset_cleanup_failed:`) is typed first; anything else
    /// passes through unchanged. Reset contacts no server, so there is no
    /// `network_unreachable` check here (the `mapUnenrollError` shape, minus
    /// that check).
    static func mapResetError(_ error: Error) -> Error {
        let msg = (error as? JsBridgeError).flatMap { if case .jsException(let m) = $0 { return m } else { return nil } }
                  ?? error.localizedDescription
        if msg.hasPrefix("reset_cleanup_failed:") {
            let first = msg.dropFirst("reset_cleanup_failed:".count)
                .trimmingCharacters(in: .whitespaces)
                .split(separator: " ", maxSplits: 1).first.map(String.init)
            let retryable: Bool? = first == "retryable=true" ? true : first == "retryable=false" ? false : nil
            return CredentialSdkError.resetCleanupFailed(detail: msg, retryable: retryable)
        }
        return error
    }

    /// `unenroll()`'s errors: the core's `UnenrollCleanupError` (message
    /// starts with `unenroll_cleanup_failed:`) is typed first, then a network
    /// failure; anything else passes through unchanged.
    static func mapUnenrollError(_ error: Error) -> Error {
        let msg = (error as? JsBridgeError).flatMap { if case .jsException(let m) = $0 { return m } else { return nil } }
                  ?? error.localizedDescription
        if msg.hasPrefix("unenroll_cleanup_failed:") {
            let first = msg.dropFirst("unenroll_cleanup_failed:".count)
                .trimmingCharacters(in: .whitespaces)
                .split(separator: " ", maxSplits: 1).first.map(String.init)
            let retryable: Bool? = first == "retryable=true" ? true : first == "retryable=false" ? false : nil
            return CredentialSdkError.unenrollCleanupFailed(detail: msg, retryable: retryable)
        }
        if isNetworkUnreachable(error) {
            return CredentialSdkError.networkUnreachable(operation: "unenroll")
        }
        return error
    }

    /// `fetchRevocationSnapshot()`'s errors: the core's three typed prefixes
    /// (`revocation_snapshot_unauthorized:`, `revocation_snapshot_not_found:`,
    /// `revocation_snapshot_stale:`, `revocation-snapshot.ts`) map first, then
    /// a network failure; anything else (including the "no byte-safe
    /// transport" refusal — not expected in production, since IOSPlatform
    /// always registers one) passes through unchanged: still the original
    /// `JsBridgeError.jsException`, not converted to `CredentialSdkError`.
    static func mapRevocationSnapshotError(_ error: Error) -> Error {
        let msg = (error as? JsBridgeError).flatMap { if case .jsException(let m) = $0 { return m } else { return nil } }
                  ?? error.localizedDescription
        if msg.hasPrefix("revocation_snapshot_unauthorized:") {
            return CredentialSdkError.revocationSnapshotUnauthorized(detail: msg)
        }
        if msg.hasPrefix("revocation_snapshot_not_found:") {
            return CredentialSdkError.revocationSnapshotNotFound(detail: msg)
        }
        if msg.hasPrefix("revocation_snapshot_stale:") {
            return CredentialSdkError.revocationSnapshotStale(detail: msg)
        }
        if isNetworkUnreachable(error) {
            return CredentialSdkError.networkUnreachable(operation: "fetchRevocationSnapshot")
        }
        return error
    }

    static func parseRevocationSnapshot(_ json: String) throws -> RevocationSnapshot {
        guard let data = json.data(using: .utf8),
              let obj  = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw CredentialSdkError.jsonError("fetchRevocationSnapshot response not JSON: \(json)")
        }
        guard let metadataJws = obj["metadataJws"] as? String, !metadataJws.isEmpty else {
            throw CredentialSdkError.jsonError("fetchRevocationSnapshot response missing metadataJws: \(json)")
        }
        guard let filterBytesBase64 = obj["filterBytesBase64"] as? String else {
            throw CredentialSdkError.jsonError("fetchRevocationSnapshot response missing filterBytesBase64: \(json)")
        }
        // A zero-length filter is legitimate (nothing revoked): an empty
        // base64 string decodes to Data(), not a parse failure.
        let decodedFilterBytes: Data? = filterBytesBase64.isEmpty ? Data() : Data(base64Encoded: filterBytesBase64)
        guard let filterBytes = decodedFilterBytes else {
            throw CredentialSdkError.jsonError("fetchRevocationSnapshot response filterBytesBase64 is not valid base64: \(json)")
        }
        guard let versionNumber = obj["version"] as? NSNumber else {
            throw CredentialSdkError.jsonError("fetchRevocationSnapshot response missing version: \(json)")
        }
        guard let builtAtNumber = obj["builtAt"] as? NSNumber else {
            throw CredentialSdkError.jsonError("fetchRevocationSnapshot response missing builtAt: \(json)")
        }
        return RevocationSnapshot(
            metadataJws: metadataJws,
            filterBytes: filterBytes,
            version: versionNumber.intValue,
            builtAt: builtAtNumber.intValue
        )
    }

    private static func splitKeyError(_ message: String) -> (code: String, detail: String)? {
        guard let code = parseKeyErrorCode(message),
              let range = message.range(of: "key_error:") else { return nil }
        let rest = message[range.upperBound...]
        let afterCode = rest.index(rest.startIndex, offsetBy: code.count + 1)
        return (code, rest[afterCode...].trimmingCharacters(in: .whitespaces))
    }

    /// `key_error:<code>: <detail>` in a bridge message (code located by
    /// `parseKeyErrorCode`), with the OSStatus pulled out of the detail when
    /// the platform embedded one
    /// (`Error Domain=NSOSStatusErrorDomain Code=-34018 ...`).
    static func parseKeyError(_ message: String) -> (code: String, detail: String, osStatus: Int32?)? {
        guard let split = splitKeyError(message) else { return nil }
        let (code, detail) = split
        guard code.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" }) else { return nil }
        var osStatus: Int32? = nil
        if let codeRange = detail.range(of: "Code=") {
            let digits = detail[codeRange.upperBound...].prefix { $0 == "-" || $0.isNumber }
            osStatus = Int32(digits)
        }
        return (code, String(detail), osStatus)
    }

    static func jsonString(_ value: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        return String(data: data, encoding: .utf8)!
    }

    /// A strict parse of the `attestation` field shared by `EnrollResult`
    /// and `EndorsementOpened`: the key absent means "not reported" (`nil`);
    /// present, it must be a JSON object whose `attested` is a JSON boolean
    /// checked on the raw value (`CFGetTypeID(...) == CFBooleanGetTypeID()`,
    /// never `as? Bool`, which also accepts an `NSNumber` built from JSON
    /// `1`), and whose `reason` is absent when `attested` is `true` and one
    /// of the three `AttestationSkipReason` strings when it is `false`.
    /// Anything else throws `.jsonError`, the same as a body missing
    /// `deviceId`. A loose parse (`as? Bool ?? false`) would read a malformed
    /// object as "unattested" — the one reading this fix exists to prevent.
    static func parseAttestationOutcome(_ obj: [String: Any]) throws -> AttestationOutcome? {
        guard let raw = obj["attestation"] else { return nil }
        guard let attestationObj = raw as? [String: Any] else {
            throw CredentialSdkError.jsonError("attestation not an object: \(raw)")
        }
        guard let attestedNumber = attestationObj["attested"] as? NSNumber,
              CFGetTypeID(attestedNumber as CFTypeRef) == CFBooleanGetTypeID()
        else {
            throw CredentialSdkError.jsonError(
                "attestation.attested not a JSON boolean: \(String(describing: attestationObj["attested"]))")
        }
        let attested = attestedNumber.boolValue
        let reasonValue = attestationObj["reason"]
        if attested {
            guard reasonValue == nil else {
                throw CredentialSdkError.jsonError("attestation.reason present when attested is true")
            }
            return AttestationOutcome(attested: true, reason: nil)
        }
        guard let reasonString = reasonValue as? String,
              let reason = AttestationSkipReason(rawValue: reasonString)
        else {
            throw CredentialSdkError.jsonError(
                "attestation.reason missing or invalid: \(String(describing: reasonValue))")
        }
        return AttestationOutcome(attested: false, reason: reason)
    }

    static func parseEnrollResult(_ json: String) throws -> EnrollResult {
        guard let data = json.data(using: .utf8),
              let obj  = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw CredentialSdkError.jsonError("enroll response not JSON: \(json)")
        }
        let deviceId    = obj["deviceId"]    as? String ?? ""
        let externalId  = obj["externalId"]  as? String ?? ""
        let credentials = obj["credentials"] as? [[String: Any]] ?? []
        let attestation = try parseAttestationOutcome(obj)
        let pattern     = try parseDevicePattern(obj["pattern"])
        return EnrollResult(deviceId: deviceId, externalId: externalId, credentials: credentials,
                            attestation: attestation, pattern: pattern)
    }

    static func parsePresentationResult(_ json: String) throws -> PresentationResult {
        guard let data = json.data(using: .utf8),
              let obj  = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw CredentialSdkError.jsonError("createPresentation response not JSON: \(json)")
        }
        let vpToken = obj["vpToken"] as? String ?? ""
        // `presentationSubmission` may be a string (already-JSON) or an object;
        // re-serialize if it's an object so callers get a stable string shape.
        let submissionAny = obj["presentationSubmission"]
        let submission: String
        if let s = submissionAny as? String {
            submission = s
        } else if let dict = submissionAny {
            let data = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
            submission = String(data: data, encoding: .utf8) ?? ""
        } else {
            submission = ""
        }
        return PresentationResult(vpToken: vpToken, presentationSubmission: submission)
    }

    static func parseEndorsementOpened(_ json: String) throws -> EndorsementOpened {
        guard let data = json.data(using: .utf8),
              let obj  = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw CredentialSdkError.jsonError("endorsement open response not JSON: \(json)")
        }
        let transactionId = obj["transactionId"] as? String ?? ""
        let qrPayload      = obj["qrPayload"]     as? String ?? ""
        let pairingCode    = obj["pairingCode"]   as? String ?? ""
        // Absent (an older reply) or not base64: empty, so the host has nothing to draw.
        let opticalPayload = (obj["opticalPayload"] as? String).flatMap { Data(base64Encoded: $0) } ?? Data()
        let expiresAt      = obj["expiresAt"]     as? String ?? ""
        let attestation    = try parseAttestationOutcome(obj)
        return EndorsementOpened(transactionId: transactionId, qrPayload: qrPayload,
                                  pairingCode: pairingCode, opticalPayload: opticalPayload,
                                  expiresAt: expiresAt, attestation: attestation)
    }

    static func parseEndorsementInvitation(_ json: String) throws -> EndorsementInvitation {
        guard let data = json.data(using: .utf8),
              let obj  = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw CredentialSdkError.jsonError("endorsement inspect response not JSON: \(json)")
        }
        let transactionId = obj["transactionId"] as? String ?? ""
        let origin         = obj["origin"]       as? String ?? ""
        let replaces       = obj["replaces"]     as? String
        let expiresAt      = obj["expiresAt"]    as? String ?? ""
        let createdAt      = obj["createdAt"]    as? String ?? ""
        let attestation    = try parseAttestationFacts(obj["attestation"])
        return EndorsementInvitation(transactionId: transactionId, origin: origin, replaces: replaces,
                                      expiresAt: expiresAt, createdAt: createdAt, attestation: attestation)
    }

    static func parseSiteSignInInvitation(_ json: String) throws -> SiteSignInInvitation {
        let obj = try parseObject(json, what: "sign-in inspect")
        func field(_ name: String) throws -> String {
            guard let v = obj[name] as? String, !v.isEmpty else {
                throw CredentialSdkError.jsonError("sign-in inspect response missing \(name): \(json)")
            }
            return v
        }
        return SiteSignInInvitation(
            handle: try field("handle"), tenant: try field("tenant"), rpId: try field("rpId"),
            origin: try field("origin"), responseUri: try field("responseUri"), label: try field("label"),
            pkt: try field("pkt"), siteNonce: try field("siteNonce"), credentialId: try field("credentialId"),
            authRequest: try field("authRequest"), digest: try field("digest"), expiresAt: try field("expiresAt"))
    }

    static func parseSiteSignInResult(_ json: String) throws -> SiteSignInResult {
        let obj = try parseObject(json, what: "sign-in present")
        guard let status = obj["status"] as? String, !status.isEmpty else {
            throw CredentialSdkError.jsonError("sign-in present response missing status: \(json)")
        }
        return SiteSignInResult(status: status)
    }

    static func parseSiteSignInEnded(_ json: String) throws -> SiteSignInEnded {
        let obj = try parseObject(json, what: "sign-in end")
        guard let endedAt = obj["endedAt"] as? String, !endedAt.isEmpty else {
            throw CredentialSdkError.jsonError("sign-in end response missing endedAt: \(json)")
        }
        return SiteSignInEnded(endedAt: endedAt)
    }

    /// An integer field of a JSON object. Rejects a JSON boolean and a
    /// fractional number: a pattern entry that is not a whole number is a
    /// malformed reply, not entry 0 or 42.
    private static func jsonInt(_ raw: Any?) -> Int? {
        guard let number = raw as? NSNumber,
              CFGetTypeID(number as CFTypeRef) != CFBooleanGetTypeID()
        else { return nil }
        let value = number.doubleValue
        guard value == value.rounded(), abs(value) < 9_007_199_254_740_992 else { return nil }
        return number.intValue
    }

    /// `pattern`: absent or JSON `null` is `nil`; an object must hold two
    /// whole numbers, anything else throws `.jsonError`.
    static func parseDevicePattern(_ raw: Any?) throws -> DevicePattern? {
        guard let raw, !(raw is NSNull) else { return nil }
        guard let obj = raw as? [String: Any],
              let version = jsonInt(obj["patternVersion"]),
              let entry   = jsonInt(obj["patternEntry"])
        else {
            throw CredentialSdkError.jsonError("pattern malformed: \(raw)")
        }
        return DevicePattern(patternVersion: version, patternEntry: entry)
    }

    /// `attestation` as the pairing routes report it: `{"platform": ...}` or
    /// `null`/absent.
    static func parseAttestationFacts(_ raw: Any?) throws -> DeviceAttestationFacts? {
        guard let raw, !(raw is NSNull) else { return nil }
        guard let obj = raw as? [String: Any], let platform = obj["platform"] as? String else {
            throw CredentialSdkError.jsonError("attestation facts malformed: \(raw)")
        }
        return DeviceAttestationFacts(platform: platform)
    }

    private static func parseObject(_ json: String, what: String) throws -> [String: Any] {
        guard let data = json.data(using: .utf8),
              let obj  = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw CredentialSdkError.jsonError("\(what) response not JSON: \(json)")
        }
        return obj
    }

    static func parseEndorsementApproved(_ json: String, fallbackTransactionId: String) throws -> EndorsementApproved {
        let obj = try parseObject(json, what: "endorse")
        // A reply older than the pattern is `{ok:true}`: no pattern.
        // An answer naming a different transaction is refused, never relabelled.
        if let answered = obj["transactionId"] as? String, answered != fallbackTransactionId {
            throw CredentialSdkError.jsonError("endorse: the answer names a different transaction than the one approved")
        }
        return EndorsementApproved(transactionId: fallbackTransactionId,
                                    pattern: try parseDevicePattern(obj["pattern"]))
    }

    static func parseEndorsementCancelled(_ json: String) throws -> EndorsementCancelled {
        let obj = try parseObject(json, what: "endorsement cancel")
        switch obj["status"] as? String {
        case "cancelled":
            return .cancelled
        case "consumed":
            guard let deviceId = obj["deviceId"] as? String, !deviceId.isEmpty else {
                throw CredentialSdkError.jsonError("endorsement cancel 'consumed' reply missing deviceId: \(json)")
            }
            return .consumed(deviceId: deviceId, pattern: try parseDevicePattern(obj["pattern"]))
        default:
            throw CredentialSdkError.jsonError("endorsement cancel reply has unknown status: \(json)")
        }
    }

    static func parseDeviceListing(_ json: String) throws -> DeviceListing {
        let obj = try parseObject(json, what: "devices list")
        guard let devicesRaw = obj["devices"] as? [[String: Any]],
              let alertsRaw  = obj["alerts"]  as? [[String: Any]]
        else {
            throw CredentialSdkError.jsonError("devices list reply needs devices and alerts arrays: \(json)")
        }
        let devices: [DeviceSummary] = try devicesRaw.map { d in
            guard let deviceId = d["deviceId"] as? String, let status = d["status"] as? String else {
                throw CredentialSdkError.jsonError("device row missing deviceId or status: \(d)")
            }
            return DeviceSummary(
                deviceId: deviceId, status: status, role: d["role"] as? String,
                createdAt: d["createdAt"] as? String ?? "",
                attestation: try parseAttestationFacts(d["attestation"]),
                pattern: try parseDevicePattern(d["pattern"]),
                endorsedByDeviceId: d["endorsedByDeviceId"] as? String,
                isCaller: (d["isCaller"] as? NSNumber)?.boolValue ?? false)
        }
        let alerts: [EndorsementAlert] = try alertsRaw.map(parseEndorsementAlertRow)
        // Optional: a server that predates the field sends none.
        let passkeyAlerts: [PasskeyAlert] = try ((obj["passkeyAlerts"] as? [[String: Any]]) ?? []).map(parsePasskeyAlertRow)
        // A8: optional by the same rule.
        let identityAlerts: [IdentityAlert] = try ((obj["identityAlerts"] as? [[String: Any]]) ?? []).map(parseIdentityAlertRow)
        return DeviceListing(devices: devices, alerts: alerts, passkeyAlerts: passkeyAlerts, identityAlerts: identityAlerts)
    }

    /// An endorsement alert row. `deviceStatus` is absent from `deviceAlerts()`, so it reads `"active"`.
    static func parseEndorsementAlertRow(_ a: [String: Any]) throws -> EndorsementAlert {
        guard let alertId = a["alertId"] as? String, let deviceId = a["deviceId"] as? String else {
            throw CredentialSdkError.jsonError("alert row missing alertId or deviceId: \(a)")
        }
        return EndorsementAlert(
            alertId: alertId, deviceId: deviceId, createdAt: a["createdAt"] as? String ?? "",
            approvedByDeviceId: a["approvedByDeviceId"] as? String,
            pattern: try parseDevicePattern(a["pattern"]),
            attestation: try parseAttestationFacts(a["attestation"]),
            deviceStatus: a["deviceStatus"] as? String ?? "active")
    }

    static func parsePasskeyAlertRow(_ a: [String: Any]) throws -> PasskeyAlert {
        guard let alertId = a["alertId"] as? String, let jti = a["jti"] as? String,
              let origin = a["origin"] as? String, let label = a["label"] as? String
        else {
            throw CredentialSdkError.jsonError("passkey alert row missing alertId, jti, origin or label: \(a)")
        }
        return PasskeyAlert(alertId: alertId, jti: jti, origin: origin, rpId: a["rpId"] as? String ?? "",
                            label: label, createdAt: a["createdAt"] as? String ?? "",
                            approvedByDeviceId: a["approvedByDeviceId"] as? String ?? "",
                            pattern: try parseDevicePattern(a["pattern"]))
    }

    /// An identity alert row: `alertId`, `kind` and `subject` required, as the passkey rows' fields are.
    static func parseIdentityAlertRow(_ a: [String: Any]) throws -> IdentityAlert {
        guard let alertId = a["alertId"] as? String, let kind = a["kind"] as? String,
              let subject = a["subject"] as? String
        else {
            throw CredentialSdkError.jsonError("identity alert row missing alertId, kind or subject: \(a)")
        }
        let siteName = a["siteName"] as? String
        if kind == "ring_signin", siteName?.isEmpty != false {
            throw CredentialSdkError.jsonError("ring_signin alert row missing siteName: \(a)")
        }
        return IdentityAlert(alertId: alertId, kind: kind, subject: subject,
                             pattern: try parseDevicePattern(a["pattern"]),
                             createdAt: a["createdAt"] as? String ?? "", siteName: siteName)
    }

    /// `deviceAlerts()`: `alerts` required, the other two tables optional (absent is empty).
    static func parseDeviceAlerts(_ json: String) throws -> DeviceAlerts {
        let obj = try parseObject(json, what: "device alerts")
        guard let alertsRaw = obj["alerts"] as? [[String: Any]] else {
            throw CredentialSdkError.jsonError("device alerts reply needs an alerts array: \(json)")
        }
        return DeviceAlerts(
            alerts: try alertsRaw.map(parseEndorsementAlertRow),
            passkeyAlerts: try ((obj["passkeyAlerts"] as? [[String: Any]]) ?? []).map(parsePasskeyAlertRow),
            identityAlerts: try ((obj["identityAlerts"] as? [[String: Any]]) ?? []).map(parseIdentityAlertRow))
    }

    static let approvalKinds: Set<String> = ["device", "passkey", "agent", "mdoc", "session"]

    /// `approvals(since:target:)`, strict as the server is: `since` a whole
    /// number, `approvals` an array, `truncated` a JSON boolean; each row's
    /// `kind` one of the five, `id`, `createdAt` and `status` strings,
    /// `approvedByDeviceId` a string or null, the optional strings strings
    /// when present.
    static func parseApprovals(_ json: String) throws -> Approvals {
        let obj = try parseObject(json, what: "approvals")
        func bad(_ what: String) -> CredentialSdkError { .jsonError("approvals reply has invalid \(what): \(json)") }
        guard let since = jsonInt(obj["since"]) else { throw bad("since") }
        guard let rowsRaw = obj["approvals"] as? [Any] else { throw bad("approvals") }
        guard let truncated = obj["truncated"] as? NSNumber,
              CFGetTypeID(truncated as CFTypeRef) == CFBooleanGetTypeID()
        else { throw bad("truncated") }
        let rows: [ApprovalRow] = try rowsRaw.map { raw in
            guard let r = raw as? [String: Any] else { throw bad("row") }
            guard let kind = r["kind"] as? String, approvalKinds.contains(kind) else { throw bad("kind") }
            guard let id = r["id"] as? String, !id.isEmpty else { throw bad("id") }
            guard let createdAt = r["createdAt"] as? String, !createdAt.isEmpty else { throw bad("createdAt") }
            guard let status = r["status"] as? String, !status.isEmpty else { throw bad("status") }
            let approvedBy: String?
            switch r["approvedByDeviceId"] {
            case is NSNull: approvedBy = nil
            case let v as String: approvedBy = v
            default: throw bad("approvedByDeviceId")
            }
            func optional(_ key: String) throws -> String? {
                guard let v = r[key] else { return nil }
                guard let s = v as? String else { throw bad(key) }
                return s
            }
            return ApprovalRow(kind: kind, id: id, approvedByDeviceId: approvedBy, createdAt: createdAt, status: status,
                               pattern: try parseDevicePattern(r["pattern"]),
                               rpId: try optional("rpId"), label: try optional("label"),
                               agentId: try optional("agentId"), origin: try optional("origin"))
        }
        return Approvals(since: since, approvals: rows, truncated: truncated.boolValue)
    }

    /// `cancelRecovery(transactionId:)`: `cancelled`, or `completed` with the new device's id.
    static func parseRecoveryCancelResult(_ json: String) throws -> RecoveryCancelResult {
        let obj = try parseObject(json, what: "recovery cancel")
        switch obj["status"] as? String {
        case "cancelled":
            return .cancelled
        case "completed":
            guard let deviceId = obj["deviceId"] as? String, !deviceId.isEmpty else {
                throw CredentialSdkError.jsonError("recovery cancel 'completed' reply missing deviceId: \(json)")
            }
            return .completed(deviceId: deviceId, pattern: try parseDevicePattern(obj["pattern"]))
        default:
            throw CredentialSdkError.jsonError("recovery cancel reply has unknown status: \(json)")
        }
    }

    // MARK: identity graph parsing (strict: required fields throw on absence)

    private static func gErr(_ what: String, _ key: String) -> CredentialSdkError {
        .jsonError("identity graph \(what): missing or malformed '\(key)'")
    }
    private static func gStr(_ o: [String: Any], _ k: String, _ w: String) throws -> String {
        guard let v = o[k] as? String else { throw gErr(w, k) }
        return v
    }
    private static func gOptStr(_ o: [String: Any], _ k: String, _ w: String) throws -> String? {
        guard let v = o[k], !(v is NSNull) else { return nil }
        guard let s = v as? String else { throw gErr(w, k) }
        return s
    }
    private static func gInt(_ o: [String: Any], _ k: String, _ w: String) throws -> Int {
        guard let v = jsonInt(o[k]) else { throw gErr(w, k) }
        return v
    }
    private static func gOptInt(_ o: [String: Any], _ k: String, _ w: String) throws -> Int? {
        guard let v = o[k], !(v is NSNull) else { return nil }
        guard let i = jsonInt(v) else { throw gErr(w, k) }
        return i
    }
    private static func gBool(_ o: [String: Any], _ k: String, _ w: String) throws -> Bool {
        guard let n = o[k] as? NSNumber, CFGetTypeID(n as CFTypeRef) == CFBooleanGetTypeID() else { throw gErr(w, k) }
        return n.boolValue
    }
    private static func gObj(_ o: [String: Any], _ k: String, _ w: String) throws -> [String: Any] {
        guard let v = o[k] as? [String: Any] else { throw gErr(w, k) }
        return v
    }
    private static func gRows(_ o: [String: Any], _ k: String, _ w: String) throws -> [[String: Any]] {
        guard let v = o[k] as? [[String: Any]] else { throw gErr(w, k) }
        return v
    }
    private static func gGrantMap(_ raw: Any?, _ w: String) throws -> [String: GrantEntry] {
        guard let m = raw as? [String: Any] else { throw gErr(w, "grants") }
        var out: [String: GrantEntry] = [:]
        for (name, v) in m {
            guard let g = v as? [String: Any] else { throw gErr(w, "grants.\(name)") }
            out[name] = GrantEntry(claim: nil, action: try gStr(g, "action", w), scope: try gStr(g, "scope", w))
        }
        return out
    }

    /// Absent or null (no evidence, or an older server) is `nil`; a present object is read field by field.
    private static func gAttestation(_ raw: Any?) throws -> GraphAttestation? {
        guard let raw, !(raw is NSNull) else { return nil }
        guard let a = raw as? [String: Any] else { throw gErr("device", "attestation") }
        let w = "attestation"
        return GraphAttestation(
            environment: try gOptStr(a, "environment", w), validationCategory: try gOptInt(a, "validationCategory", w),
            appId: try gOptStr(a, "appId", w), bundleVersion: try gOptStr(a, "bundleVersion", w),
            codeHash: try gOptStr(a, "codeHash", w))
    }
    private static func gCredentials(_ raw: Any?) throws -> GraphCredentials? {
        guard let raw, !(raw is NSNull) else { return nil }
        guard let c = raw as? [String: Any] else { throw gErr("device", "credentials") }
        let w = "credentials"
        return GraphCredentials(active: try gInt(c, "active", w), issuedAt: try gOptStr(c, "issuedAt", w), expiresAt: try gOptStr(c, "expiresAt", w))
    }

    static func parseIdentityGraph(_ json: String) throws -> IdentityGraph {
        let obj = try parseObject(json, what: "identity graph")
        let version = try gInt(obj, "schemaVersion", "graph")
        guard version == 1 else {
            throw CredentialSdkError.jsonError("identity graph schemaVersion \(version) not supported")
        }
        let idObj = try gObj(obj, "identity", "graph")
        let w = "identity"
        let grants: [GrantEntry] = try gRows(idObj, "grants", w).map {
            GrantEntry(claim: try gStr($0, "claim", w), action: try gStr($0, "action", w), scope: try gStr($0, "scope", w))
        }
        let identity = IdentityNode(
            identityId: try gStr(idObj, "identityId", w), status: try gStr(idObj, "status", w),
            version: try gInt(idObj, "version", w), createdAt: try gStr(idObj, "createdAt", w),
            claims: try gObj(idObj, "claims", w), grants: grants,
            grantsValid: try gBool(idObj, "grantsValid", w))

        let devices: [GraphDeviceNode] = try gRows(obj, "devices", "graph").map { d in
            let w = "device"
            guard let cascadeRaw = d["cascade"] as? [Any] else { throw gErr(w, "cascade") }
            let cascade: [String] = try cascadeRaw.map {
                guard let s = $0 as? String else { throw gErr(w, "cascade") }
                return s
            }
            var cascadePasskeys: [String] = []
            if let raw = d["cascadePasskeys"], !(raw is NSNull) {
                guard let arr = raw as? [Any] else { throw gErr(w, "cascadePasskeys") }
                cascadePasskeys = try arr.map {
                    guard let s = $0 as? String else { throw gErr(w, "cascadePasskeys") }
                    return s
                }
            }
            return GraphDeviceNode(
                deviceId: try gStr(d, "deviceId", w), isCaller: try gBool(d, "isCaller", w),
                role: try gOptStr(d, "role", w), status: try gStr(d, "status", w),
                platform: try gOptStr(d, "platform", w), enrollmentMethod: try gOptStr(d, "enrollmentMethod", w),
                attestedAt: try gOptStr(d, "attestedAt", w), pattern: try parseDevicePattern(d["pattern"]),
                createdAt: try gStr(d, "createdAt", w), revokedAt: try gOptStr(d, "revokedAt", w),
                revocationSeq: try gOptInt(d, "revocationSeq", w),
                endorsedByDeviceId: try gOptStr(d, "endorsedByDeviceId", w),
                replacesDeviceId: try gOptStr(d, "replacesDeviceId", w),
                replacedByDeviceId: try gOptStr(d, "replacedByDeviceId", w), cascade: cascade,
                attestation: try gAttestation(d["attestation"]), credentials: try gCredentials(d["credentials"]),
                cascadePasskeys: cascadePasskeys)
        }
        let agents: [AgentNode] = try gRows(obj, "agents", "graph").map { a in
            let w = "agent"
            var grants: [String: GrantEntry]? = nil
            if let g = a["grants"], !(g is NSNull) { grants = try gGrantMap(g, w) }
            return AgentNode(
                jti: try gStr(a, "jti", w), agentId: try gStr(a, "agentId", w),
                humanAuthorizationJti: try gOptStr(a, "humanAuthorizationJti", w), status: try gStr(a, "status", w),
                grants: grants, authorizerDeviceId: try gStr(a, "authorizerDeviceId", w),
                identityVersionAtIssuance: try gInt(a, "identityVersionAtIssuance", w),
                issuedAt: try gStr(a, "issuedAt", w), expiresAt: try gStr(a, "expiresAt", w),
                revokedAt: try gOptStr(a, "revokedAt", w), revocationSeq: try gOptInt(a, "revocationSeq", w))
        }
        let sessions: [SessionNode] = try gRows(obj, "sessions", "graph").map { s in
            let w = "session"
            return SessionNode(
                sessionId: try gStr(s, "sessionId", w), status: try gStr(s, "status", w),
                grants: try gGrantMap(s["grants"], w),
                identityVersionAtIssuance: try gInt(s, "identityVersionAtIssuance", w),
                createdAt: try gStr(s, "createdAt", w), expiresAt: try gStr(s, "expiresAt", w),
                closedAt: try gOptStr(s, "closedAt", w))
        }
        let alerts: [AlertNode] = try gRows(obj, "alerts", "graph").map { a in
            let w = "alert"
            return AlertNode(
                alertId: try gStr(a, "alertId", w), endorsedDeviceId: try gStr(a, "endorsedDeviceId", w),
                approvedByDeviceId: try gOptStr(a, "approvedByDeviceId", w),
                createdAt: try gStr(a, "createdAt", w),
                acknowledgedAt: try gOptStr(a, "acknowledgedAt", w), resolvedAt: try gOptStr(a, "resolvedAt", w))
        }
        // Additive at schemaVersion 1: absent or null on a server that predates sign-in keys.
        var passkeys: [PasskeyNode] = []
        if let raw = obj["passkeys"], !(raw is NSNull) {
            guard raw is [[String: Any]] else { throw gErr("graph", "passkeys") }
            passkeys = try gRows(obj, "passkeys", "graph").map { p in
                let w = "passkey"
                return PasskeyNode(
                    jti: try gStr(p, "jti", w), rpId: try gStr(p, "rpId", w), label: try gStr(p, "label", w),
                    status: try gStr(p, "status", w), authorizerDeviceId: try gStr(p, "authorizerDeviceId", w),
                    humanAuthorizationJti: try gStr(p, "humanAuthorizationJti", w),
                    identityVersionAtIssuance: try gInt(p, "identityVersionAtIssuance", w),
                    issuedAt: try gStr(p, "issuedAt", w), expiresAt: try gStr(p, "expiresAt", w),
                    revokedAt: try gOptStr(p, "revokedAt", w), revocationSeq: try gOptInt(p, "revocationSeq", w),
                    pattern: try parseDevicePattern(p["pattern"]))
            }
        }
        // Additive at schemaVersion 1 (A4): absent or null on a server that predates mdoc status.
        var mdocs: [MdocNode] = []
        if let raw = obj["mdocs"], !(raw is NSNull) {
            guard raw is [[String: Any]] else { throw gErr("graph", "mdocs") }
            mdocs = try gRows(obj, "mdocs", "graph").map { m in
                let w = "mdoc"
                // A status this SDK does not know (a later server's) reads as "unknown", never as a failed graph:
                // callers treat it as not ended.
                let raw = try gStr(m, "status", w)
                let status = raw == "active" || raw == "revoked" ? raw : "unknown"
                return MdocNode(
                    jti: try gStr(m, "jti", w), deviceId: try gStr(m, "deviceId", w), status: status,
                    humanAuthorizationJti: try gStr(m, "humanAuthorizationJti", w),
                    identityVersionAtIssuance: try gInt(m, "identityVersionAtIssuance", w),
                    issuedAt: try gStr(m, "issuedAt", w), expiresAt: try gStr(m, "expiresAt", w),
                    revokedAt: try gOptStr(m, "revokedAt", w), revocationSeq: try gOptInt(m, "revocationSeq", w))
            }
        }
        let t = try gObj(obj, "truncated", "graph")
        var passkeysTruncated = false
        if let raw = t["passkeys"], !(raw is NSNull) { passkeysTruncated = try gBool(t, "passkeys", "truncated") }
        var mdocsTruncated = false
        if let raw = t["mdocs"], !(raw is NSNull) { mdocsTruncated = try gBool(t, "mdocs", "truncated") }
        return IdentityGraph(
            schemaVersion: version, generatedAt: try gStr(obj, "generatedAt", "graph"),
            identity: identity, devices: devices, agents: agents, sessions: sessions, alerts: alerts,
            devicesTruncated: try gBool(t, "devices", "truncated"), agentsTruncated: try gBool(t, "agents", "truncated"),
            sessionsTruncated: try gBool(t, "sessions", "truncated"), alertsTruncated: try gBool(t, "alerts", "truncated"),
            passkeys: passkeys, passkeysTruncated: passkeysTruncated,
            mdocs: mdocs, mdocsTruncated: mdocsTruncated)
    }

    static func parseDeviceRevocation(_ json: String, fallbackDeviceId: String) throws -> DeviceRevocation {
        let obj = try parseObject(json, what: "device revoke")
        guard let already = obj["alreadyRevoked"] as? NSNumber,
              CFGetTypeID(already as CFTypeRef) == CFBooleanGetTypeID()
        else {
            throw CredentialSdkError.jsonError("device revoke reply missing alreadyRevoked boolean: \(json)")
        }
        return DeviceRevocation(deviceId: obj["deviceId"] as? String ?? fallbackDeviceId,
                                 alreadyRevoked: already.boolValue)
    }

    static func parseMdocIssueChallenge(_ json: String) throws -> MdocIssueChallenge {
        let obj = try parseObject(json, what: "mdoc challenge")
        func field(_ k: String) throws -> String {
            guard let v = obj[k] as? String, !v.isEmpty else {
                throw CredentialSdkError.jsonError("mdoc challenge reply missing \(k): \(json)")
            }
            return v
        }
        return MdocIssueChallenge(challenge: try field("challenge"), tenant: try field("tenant"), audience: try field("audience"))
    }

    static func parseMdocIssued(_ json: String) throws -> MdocIssued {
        let obj = try parseObject(json, what: "mdoc issue")
        func field(_ k: String) throws -> String {
            guard let v = obj[k] as? String, !v.isEmpty else {
                throw CredentialSdkError.jsonError("mdoc issue reply missing \(k)")
            }
            return v
        }
        guard let replaced = obj["replacedJtis"] as? [String] else {
            throw CredentialSdkError.jsonError("mdoc issue reply missing replacedJtis array")
        }
        return MdocIssued(jti: try field("jti"), docType: try field("docType"), namespace: try field("namespace"),
                          issuerSigned: try field("issuerSigned"), validFrom: try field("validFrom"),
                          validUntil: try field("validUntil"), replacedJtis: replaced)
    }

    static func parsePasskeyRevocation(_ json: String, fallbackJti: String) throws -> PasskeyRevocation {
        let obj = try parseObject(json, what: "passkey revoke")
        guard let already = obj["alreadyRevoked"] as? NSNumber,
              CFGetTypeID(already as CFTypeRef) == CFBooleanGetTypeID()
        else {
            throw CredentialSdkError.jsonError("passkey revoke reply missing alreadyRevoked boolean: \(json)")
        }
        return PasskeyRevocation(jti: obj["jti"] as? String ?? fallbackJti,
                                  alreadyRevoked: already.boolValue)
    }
}
