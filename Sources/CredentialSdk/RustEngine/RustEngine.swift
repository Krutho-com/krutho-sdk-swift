import Foundation
import LocalAuthentication
import CredentialSdkCoreBindings

// SDK v2: the Rust core behind `CredentialSdk`'s public API (the only
// engine). `CredentialSdk` keeps its public
// signatures; each call runs here, on the SDK's serial queue, against one
// `CredentialCore`.
//
// What this layer does, and only this:
// - passes every host string through `CredentialSdk.hostString` before the
//   core sees it (an unpaired surrogate is refused, typed);
// - turns the core's records into today's public types, and the getState,
//   sync and endorsement-status replies into the JSON text SDK v1's JavaScript
//   engine returned (the public API's shape);
// - keeps the last pending transaction so `endorse(transactionId:)` and
//   `signInPresent(_:)` find their handle (the wrapper looks up the
//   pending handle by transaction id or handle string and calls approve);
//   a call that names a transaction this instance did not inspect passes the
//   core a handle it never issued, so the core refuses it (`NotInspected`);
// - hands the core's errors to `CredentialSdk`'s per-call mapping (see
//   `RustEngine.bridged`).
//
// It builds no signed byte and no digest: the core does.

typealias CoreEnrollResult = CredentialSdkCoreBindings.EnrollResult
typealias CoreAttestationOutcome = CredentialSdkCoreBindings.AttestationOutcome
typealias CoreDevicePattern = CredentialSdkCoreBindings.DevicePattern
typealias CorePendingTransaction = CredentialSdkCoreBindings.PendingTransaction

final class RustEngine {
    let core: CredentialCore
    let keys: KeychainKeys
    /// The storage the core was built over (one core per storage identity).
    let storage: KeychainStorage
    /// The HTTP transport the core was built over.
    let http: URLSessionHttp
    /// The App Attest runner the core was built over.
    let appAttest: AppAttestRunner
    let config: SdkConfig

    private let lock = NSLock()

    /// Held by every SDK sharing this core across each call that can reach the keys: every core call (`call`,
    /// which covers each device-JWT request, so each sign) except the three that only read local records
    /// (`getStateJson`, `endorsementStatusJson`, `endorsementStatusRequest`), plus the mdoc approval and, in
    /// `CredentialSdk.endorsementFinish()`, the whole status request, attempt, finish and withdrawal.
    /// The finish's cancellation attempt lives on the core's keys, one at a time, and every sign on those keys
    /// registers under it; SDKs sharing the core have separate queues, so without this a second SDK's call could
    /// replace the attempt, clear it before the first signs, or sign under it and be withdrawn by its watcher.
    /// A call on a sharer waits for the gate; one person and one prompt at a time anyway. Recursive, so the
    /// finish can hold it across its own core calls. Host code the SDK calls while a call holds the gate (the
    /// `hostProof` closure, an injected URLSession or its authentication delegate, any injected platform
    /// adapter) must not call another SDK sharing this core: that call waits on the gate the first call holds,
    /// across queues, until the first call fails (an HTTP request after its timeout).
    let gate = NSRecursiveLock()
    /// The pending transaction the last inspect or prepare returned. The core
    /// holds at most one per instance; this is only the lookup from a
    /// transaction id or a sign-in handle to its approval handle.
    private var pending: CorePendingTransaction?
    /// The approval running now, with the calling SDK's `approvalPromptText` hook: set under `gate` for the length of
    /// one approval (`withPrompt`), from the transaction that approval names. Its own copy, never `pending`: another
    /// SDK sharing this core may inspect (and so replace `pending`) while it runs.
    private var activeApproval: (handleId: String, facts: CredentialSdkCoreBindings.Facts, hook: ApprovalPromptText)?
    /// Test seam: runs as an approval starts, holding `gate`, before the core approves. Nil in production.
    var willRunApproval: (() -> Void)?
    /// Test seam: runs as an inspect or prepare starts, before it takes `gate`. Nil in production.
    var willHold: (() -> Void)?
    /// The adapters' way back to this engine for a prompt's words (`promptText(scopeId:reason:)`).
    private let route: PromptRoute

    private init(core: CredentialCore, route: PromptRoute, platform: IOSPlatform, config: SdkConfig) {
        self.core = core
        self.route = route
        self.keys = platform.keys
        self.storage = platform.storage
        self.http = platform.http
        self.appAttest = platform.appAttest
        self.config = config
    }

    // MARK: - One core per storage

    private final class WeakEngine {
        weak var engine: RustEngine?
        init(_ engine: RustEngine) { self.engine = engine }
    }

    private static let registryLock = NSLock()
    private static var registry: [String: WeakEngine] = [:]

    /// The engine for `platform`'s storage. The core keys its device-auth lock
    /// and its pending-transaction slot on the storage it holds, and deletes
    /// `transaction.pending` when it is built, so two cores over one storage
    /// would order their device-JWT requests apart and the second would delete
    /// the first's pending record. A `CredentialSdk` over the same storage with
    /// the same configuration therefore shares the first one's core.
    ///
    /// "The same storage" is the same backing and keychain service
    /// (`KeychainStorage.ownershipKey`), not the same object: the app builds
    /// each SDK with its own `KeychainStorage`, `KeychainKeys` and
    /// `URLSessionHttp` over one service, and those are one store of records.
    /// Sharing is refused (`unsupported`) when the platform differs in what the
    /// shared core would silently take from the first: the configuration (a
    /// core is built for one server), the keychain access group (a storage with
    /// no group reaches the records of one with a group, so one process uses
    /// one group per storage: nil and an explicit group differ, and so do two
    /// explicit groups), the key store (`KeychainKeys.sharingIdentity`)
    /// or the HTTP transport (`URLSessionHttp.sharingIdentity`: an injected
    /// session with its own pinning delegate is not the default session).
    static func engine(platform: IOSPlatform, config: SdkConfig) throws -> RustEngine {
        registryLock.lock(); defer { registryLock.unlock() }
        registry = registry.filter { $0.value.engine != nil }
        let key = platform.storage.ownershipKey
        if let live = registry[key]?.engine {
            guard live.config == config else {
                throw CredentialSdkError.unsupported(
                    detail: "a Rust core already runs over this storage with another configuration; build one CredentialSdk per storage")
            }
            guard live.storage.accessGroup == platform.storage.accessGroup else {
                throw CredentialSdkError.unsupported(
                    detail: "a Rust core already runs over this storage with another keychain group; build one CredentialSdk per storage")
            }
            guard live.keys.sharingIdentity == platform.keys.sharingIdentity else {
                throw CredentialSdkError.unsupported(
                    detail: "a Rust core already runs over this storage with another key store; build one CredentialSdk per storage")
            }
            guard live.http.sharingIdentity == platform.http.sharingIdentity else {
                throw CredentialSdkError.unsupported(
                    detail: "a Rust core already runs over this storage with another HTTP transport; build one CredentialSdk per storage")
            }
            guard config.attestation == .off || live.appAttest.sharingIdentity == platform.appAttest.sharingIdentity else {
                throw CredentialSdkError.unsupported(
                    detail: "a Rust core already runs over this storage with another App Attest service; build one CredentialSdk per storage")
            }
            return live
        }
        let route = PromptRoute()
        let core = try CredentialCore(
            config: config,
            keys: KeysAdapter(platform.keys, route: route),
            storage: StorageAdapter(platform.storage),
            http: HttpAdapter(platform.http),
            attestation: AttestationAdapter(platform.appAttest))
        let engine = RustEngine(core: core, route: route, platform: platform, config: config)
        route.engine = engine
        registry[key] = WeakEngine(engine)
        return engine
    }

    static func config(coreApiUrl: URL, audience: URL, attestation: AttestationMode, appBuild: Int?) throws -> SdkConfig {
        let mode: CredentialSdkCoreBindings.AttestationMode
        switch attestation {
        case .off:      mode = .off
        case .on:       mode = .on
        case .required: mode = .required
        }
        return SdkConfig(
            coreApiUrl: try CredentialSdk.hostString(coreApiUrl.absoluteString, argument: "coreApiUrl"),
            audience: try CredentialSdk.hostString(audience.absoluteString, argument: "audience"),
            appBuild: appBuild.flatMap { UInt64(exactly: $0) },
            attestation: mode)
    }

    // MARK: - Errors

    /// The core's error as SDK v1 reported the same failure:
    /// `JsBridgeError.jsException` with the core's message, the text the
    /// TypeScript core threw (the error-code table pins every code's message
    /// prefix and detail rule). `CredentialSdk`'s per-call mapping then types
    /// it, so a host sees the `CredentialSdkError` case SDK v1 gave it, and a
    /// failure the mapping leaves untyped (a refused transaction, a protocol
    /// refusal, a storage failure) arrives as `JsBridgeError`, as it did.
    /// A failure inside the bindings themselves (a caught Rust panic, a lift
    /// error) arrives the same way, as `internal: ...`. Errors this layer or
    /// the host raised (`CredentialSdkError`, the host proof's own error) pass
    /// through.
    static func bridged(_ error: Error) -> Error {
        switch error {
        case let e as SdkError:
            return JsBridgeError.jsException(text(of: e))
        case is CredentialSdkError, is JsBridgeError, is KeychainStorageError:
            return error
        default:
            return JsBridgeError.jsException("internal: \(error.localizedDescription)")
        }
    }

    static func text(of error: SdkError) -> String {
        switch error {
        case .KeyError(_, _, let text), .StorageError(_, _, let text), .NetworkUnreachable(_, let text),
             .AlreadyEnrolled(let text), .DeviceExists(_, let text), .AttestationFailed(_, _, let text),
             .AttestationRefused(_, _, _, let text), .EndorsementRefused(_, _, _, let text),
             .MdocRouteAbsent(let text), .KeyInvalidated(_, _, _, let text),
             .UnenrollCleanupFailed(_, _, let text), .ResetCleanupFailed(_, _, let text),
             .RevocationSnapshot(_, _, let text), .Transaction(_, let text),
             .EnrollmentAttemptConflict(_, _, let text), .Unsupported(_, let text),
             .Protocol(let text), .Internal(let text):
            return text
        }
    }

    /// Run one core call under the core's gate, its error bridged.
    func call<T>(_ work: () throws -> T) throws -> T {
        gate.lock(); defer { gate.unlock() }
        return try callUngated(work)
    }

    /// A core call that only reads local records: no gate.
    private func callUngated<T>(_ work: () throws -> T) throws -> T {
        do { return try work() } catch { throw Self.bridged(error) }
    }

    // MARK: - Pending transactions

    /// Run an inspect or prepare and hold what it returns. The core supersedes the instance's earlier pending
    /// transaction whether or not the new one succeeds, so the earlier one is dropped here first: after a refused
    /// inspection, `endorse` or `signInPresent` names nothing this instance holds, and the core refuses it as not
    /// inspected (as SDK v1 did), not as superseded. The drop, the inspection and the hold all run
    /// under `gate`, so an approval another SDK sharing this core runs meanwhile never sees `pending` change under it.
    private func hold(_ inspect: () throws -> CorePendingTransaction) throws -> CorePendingTransaction {
        willHold?()
        gate.lock(); defer { gate.unlock() }
        lock.lock(); pending = nil; lock.unlock()
        let tx = try callUngated(inspect)
        lock.lock(); pending = tx; lock.unlock()
        return tx
    }

    /// The facts of the transaction this instance holds (tests: the prompt's reason against the core's summary line).
    var heldFacts: CredentialSdkCoreBindings.Facts? {
        lock.lock(); defer { lock.unlock() }
        return pending?.facts
    }

    /// The held transaction `matches` accepts, or nil.
    private func held(where matches: (CorePendingTransaction) -> Bool) -> CorePendingTransaction? {
        lock.lock(); defer { lock.unlock() }
        if let tx = pending, matches(tx) { return tx }
        return nil
    }

    /// Approves `tx`; nil passes the core a handle it never issued (it refuses it, `NotInspected`).
    private func approve(_ tx: CorePendingTransaction?, prompt: ApprovalPromptText?) throws -> ApprovalOutcome {
        try call { try withPrompt(tx, prompt) { try core.approve(handle: tx?.handle ?? ApprovalHandle(id: "")) } }
    }

    // MARK: - The approval prompt's words (the host's `approvalPromptText`)

    /// Runs `work`, the approval of `tx`, with `prompt` as the hook its Face ID asks for words, and `tx`'s handle and
    /// facts as what the hook is told. The caller holds `gate`, so SDKs sharing this core, each with its own hook,
    /// never see each other's: one approval runs at a time.
    private func withPrompt<T>(_ tx: CorePendingTransaction?, _ prompt: ApprovalPromptText?,
                               _ work: () throws -> T) rethrows -> T {
        var approval: (handleId: String, facts: CredentialSdkCoreBindings.Facts, hook: ApprovalPromptText)?
        if let tx, let prompt { approval = (tx.handle.id, tx.facts, prompt) }
        lock.lock(); let outer = activeApproval; activeApproval = approval; lock.unlock()
        defer { lock.lock(); activeApproval = outer; lock.unlock() }
        willRunApproval?()
        return try work()
    }

    /// The words the prompt of scope `scopeId` shows, `reason` the core's (`KeychainKeys` asks only where it raises a
    /// prompt). The host's hook answers for the scope of the approval running now: the core opens each approval's
    /// scope as `<handle>#<n>` (`core.rs` `scope_for`). Any other scope (an enrollment's or a presentation's
    /// high-assurance signature), no hook, or a nil, empty or whitespace-only answer: `reason`. The hook runs on the
    /// calling SDK's queue with `gate` and the scope's sign lock held, and outside `lock`.
    func promptText(scopeId: String, reason: String) -> String {
        lock.lock(); let approval = activeApproval; lock.unlock()
        guard let approval, !approval.handleId.isEmpty, scopeId.hasPrefix(approval.handleId + "#") else { return reason }
        return ApprovalPrompt.shown(approval.hook(ApprovalPrompt(facts: approval.facts, defaultText: reason)),
                                    defaultText: reason)
    }

    /// The outcome `approve` must answer for this door; anything else is a
    /// core bug, reported as a malformed answer (`jsonError`).
    private static func unexpected(_ outcome: ApprovalOutcome, _ what: String) -> Error {
        CredentialSdkError.jsonError("\(what): the core answered another kind of approval: \(outcome)")
    }

    // MARK: - Lifecycle

    func getStateJson() throws -> String {
        let state = try callUngated { try core.getState() }
        var members: [String] = []
        if let id = state.deviceId { members.append("\"deviceId\":\(Self.json(id))") }
        members.append("\"credentials\":[\(state.credentials.joined(separator: ","))]")
        if let e = state.enrollment {
            var inner = "\"method\":\(Self.json(e.method))"
            if let role = e.role { inner += ",\"role\":\(Self.json(role))" }
            members.append("\"enrollment\":{\(inner)}")
        }
        if let pattern = state.pattern { members.append("\"pattern\":\(Self.json(pattern))") }
        return "{\(members.joined(separator: ","))}"
    }

    func generateKeyPairs() throws {
        try call { try core.generateKeyPairs() }
    }

    func enroll(accessToken: String) throws -> EnrollResult {
        let token = try CredentialSdk.hostString(accessToken, argument: "accessToken")
        return try EnrollResult(try call { try core.enrollOauth2(accessToken: token) })
    }

    func syncJson() throws -> String {
        switch try call({ try core.sync() }) {
        case .unchanged:              return "{}"
        case .revoked:                return "{\"revoked\":true}"
        case .credentials(let list):  return "{\"credentials\":[\(list.joined(separator: ","))]}"
        }
    }

    func fetchRevocationSnapshot() throws -> RevocationSnapshot {
        let s = try call { try core.fetchRevocationSnapshot() }
        guard let version = Int(exactly: s.version), let builtAt = Int(exactly: s.builtAt) else {
            throw CredentialSdkError.jsonError("fetchRevocationSnapshot response version or builtAt out of range")
        }
        return RevocationSnapshot(metadataJws: s.metadataJws, filterBytes: s.filterBytes, version: version, builtAt: builtAt)
    }

    func unenroll() throws { try call { try core.unenroll() } }

    func resetLocalState() throws { try call { try core.resetLocalState() } }

    func createPresentation(authRequest: String) throws -> PresentationResult {
        let request = try CredentialSdk.hostString(authRequest, argument: "authRequest")
        let out = try call { try core.createPresentation(authRequestJson: request) }
        return PresentationResult(vpToken: out.vpToken, presentationSubmission: out.presentationSubmission)
    }

    // MARK: - Endorsement: the enrolling device

    func endorsementOpen(tenant: String, origin: String, replaces: String?, kind: EndorsementKind) throws -> EndorsementOpened {
        let opts = EndorsementOpenOptions(
            tenant: try CredentialSdk.hostString(tenant, argument: "tenant"),
            origin: try CredentialSdk.hostString(origin, argument: "origin"),
            replaces: try replaces.map { try CredentialSdk.hostString($0, argument: "replaces") },
            kind: kind == .rootProof ? .rootProof : .endorsement)
        let o = try call { try core.endorsementOpen(opts: opts) }
        return EndorsementOpened(transactionId: o.transactionId, qrPayload: o.qrPayload, pairingCode: o.pairingCode,
                                 opticalPayload: Data(base64Encoded: o.opticalPayload) ?? Data(),
                                 expiresAt: o.expiresAt, attestation: AttestationOutcome(o.attestation))
    }

    /// `{"status","expiresAt"}`, plus `holdUntil` and `pattern` when the
    /// server sent them, in the TypeScript reply's member order.
    func endorsementStatusJson() throws -> String {
        let s = try callUngated { try core.endorsementStatus() }
        var members = ["\"status\":\(Self.json(s.status))", "\"expiresAt\":\(Self.json(s.expiresAt))"]
        if let hold = s.holdUntil { members.append("\"holdUntil\":\(hold.map(Self.json) ?? "null")") }
        if let pattern = s.pattern { members.append("\"pattern\":\(Self.json(pattern))") }
        return "{\(members.joined(separator: ","))}"
    }

    /// The status request for the finish watcher; nil when there is none.
    func endorsementStatusRequest() -> StatusRequest? {
        try? core.endorsementStatusRequest()
    }

    func endorsementFinish() throws -> EnrollResult {
        try EnrollResult(try call { try core.endorsementFinish() })
    }

    // MARK: - Endorsement: the approving phone

    func endorsementInspect(qrPayload: String) throws -> EndorsementInvitation {
        let qr = try CredentialSdk.hostString(qrPayload, argument: "qrPayload")
        return try Self.invitation(try hold { try core.inspectEndorsementQr(qrPayload: qr) })
    }

    func endorsementInspectOptical(payload: Data) throws -> EndorsementInvitation {
        try Self.invitation(try hold { try core.inspectEndorsementOptical(payload: payload) })
    }

    static func invitation(_ tx: CorePendingTransaction) throws -> EndorsementInvitation {
        guard case .endorsement(let inv) = tx.facts.detail else {
            throw CredentialSdkError.jsonError("endorsement inspect: the core answered another kind of transaction")
        }
        return EndorsementInvitation(transactionId: inv.transactionId, origin: inv.origin, replaces: inv.replaces,
                                     expiresAt: inv.expiresAt, createdAt: inv.createdAt,
                                     attestation: inv.attestation.map(DeviceAttestationFacts.init))
    }

    func endorse(transactionId: String, prompt: ApprovalPromptText? = nil) throws -> EndorsementApproved {
        let id = try CredentialSdk.hostString(transactionId, argument: "transactionId")
        let tx = held { tx in
            if case .endorsement(let inv) = tx.facts.detail { return inv.transactionId == id }
            return false
        }
        let outcome = try approve(tx, prompt: prompt)
        guard case .endorsement(let approved) = outcome else { throw Self.unexpected(outcome, "endorse") }
        // An answer naming another transaction is refused, never relabelled (as SDK v1 did).
        guard approved.transactionId == id else {
            throw CredentialSdkError.jsonError("endorse: the answer names a different transaction than the one approved")
        }
        return EndorsementApproved(transactionId: id, pattern: try approved.pattern.map(DevicePattern.init))
    }

    func endorsementCancel(transactionId: String) throws -> EndorsementCancelled {
        let id = try CredentialSdk.hostString(transactionId, argument: "transactionId")
        switch try call({ try core.endorsementCancel(transactionId: id) }) {
        case .cancelled:
            return .cancelled
        case .consumed(let deviceId, let pattern):
            return .consumed(deviceId: deviceId, pattern: try pattern.map(DevicePattern.init))
        }
    }

    // MARK: - Site sign-in

    func signInInspectOptical(payload: Data) throws -> SiteSignInInvitation {
        let tx = try hold { try core.inspectSiteSignin(payload: payload) }
        guard case .siteSignin(let handle, let tenant, let rpId, let origin, let label, let pkt, let credentialId) = tx.facts.detail else {
            throw CredentialSdkError.jsonError("sign-in inspect: the core answered another kind of transaction")
        }
        let fields = [handle, tenant, rpId, origin, tx.responseUri, label, pkt, tx.siteNonce ?? "", credentialId,
                      tx.authorizationRequest, tx.nonceDigest, tx.facts.expiresAt ?? ""]
        guard !fields.contains(where: \.isEmpty) else {
            throw CredentialSdkError.jsonError("sign-in inspect: the core's transaction is missing a field")
        }
        return SiteSignInInvitation(handle: handle, tenant: tenant, rpId: rpId, origin: origin,
                                    responseUri: tx.responseUri, label: label, pkt: pkt, siteNonce: tx.siteNonce ?? "",
                                    credentialId: credentialId, authRequest: tx.authorizationRequest,
                                    digest: tx.nonceDigest, expiresAt: tx.facts.expiresAt ?? "")
    }

    func signInPresent(_ invitation: SiteSignInInvitation, prompt: ApprovalPromptText? = nil) throws -> SiteSignInResult {
        let wanted = try CredentialSdk.hostString(invitation.handle, argument: "handle")
        let tx = held { tx in
            if case .siteSignin(let h, _, _, _, _, _, _) = tx.facts.detail { return h == wanted }
            return false
        }
        let outcome = try approve(tx, prompt: prompt)
        guard case .siteSignIn(let presented) = outcome else { throw Self.unexpected(outcome, "sign-in present") }
        guard !presented.status.isEmpty else {
            throw CredentialSdkError.jsonError("sign-in present response missing status")
        }
        return SiteSignInResult(status: presented.status)
    }

    func endSiteSignIn(handle: String) throws -> SiteSignInEnded {
        let h = try CredentialSdk.hostString(handle, argument: "handle")
        return SiteSignInEnded(endedAt: try call { try core.endSiteSignin(handle: h) }.endedAt)
    }

    // MARK: - Devices, recovery, passkeys

    func devicesList() throws -> DeviceListing {
        let l = try call { try core.devicesList() }
        return DeviceListing(
            devices: try l.devices.map(DeviceSummary.init),
            alerts: try l.alerts.map { try EndorsementAlert($0.alert, deviceStatus: $0.deviceStatus) },
            passkeyAlerts: try l.passkeyAlerts.map(PasskeyAlert.init),
            identityAlerts: try l.identityAlerts.map(IdentityAlert.init))
    }

    func deviceAlerts() throws -> DeviceAlerts {
        let a = try call { try core.deviceAlerts() }
        return DeviceAlerts(alerts: try a.alerts.map { try EndorsementAlert($0, deviceStatus: nil) },
                            passkeyAlerts: try a.passkeyAlerts.map(PasskeyAlert.init),
                            identityAlerts: try a.identityAlerts.map(IdentityAlert.init))
    }

    func identityGraph() throws -> IdentityGraph {
        try IdentityGraph(try call { try core.identityGraph() })
    }

    func acknowledgeAlert(alertId: String) throws {
        let id = try CredentialSdk.hostString(alertId, argument: "alertId")
        try call { try core.acknowledgeAlert(alertId: id) }
    }

    func approvals(since: Int?, target: String?) throws -> Approvals {
        let query = ApprovalsQuery(since: since.flatMap { UInt64(exactly: $0) },
                                   target: try target.map { try CredentialSdk.hostString($0, argument: "target") })
        if let since, since < 0 {
            throw CredentialSdkError.jsonError("approvals: since must be 0 or more, got \(since)")
        }
        return try Approvals(try call { try core.approvals(query: query) })
    }

    func revokeDevice(targetDeviceId: String, prompt: ApprovalPromptText? = nil) throws -> DeviceRevocation {
        let id = try CredentialSdk.hostString(targetDeviceId, argument: "targetDeviceId")
        let tx = try hold { try core.prepareDeviceRevoke(targetDeviceId: id) }
        let outcome = try approve(tx, prompt: prompt)
        guard case .deviceRevoke(let r) = outcome else { throw Self.unexpected(outcome, "device revoke") }
        return DeviceRevocation(deviceId: r.deviceId, alreadyRevoked: r.alreadyRevoked)
    }

    func containDevice(targetDeviceId: String, since: Int, prompt: ApprovalPromptText? = nil) throws -> DeviceRevocation {
        let id = try CredentialSdk.hostString(targetDeviceId, argument: "targetDeviceId")
        guard let since = UInt64(exactly: since) else {
            throw CredentialSdkError.jsonError("containDevice: since must be 0 or more, got \(since)")
        }
        let tx = try hold { try core.prepareDeviceContain(targetDeviceId: id, since: since) }
        let outcome = try approve(tx, prompt: prompt)
        guard case .deviceContain(let r) = outcome else { throw Self.unexpected(outcome, "device contain") }
        return DeviceRevocation(deviceId: r.deviceId, alreadyRevoked: r.alreadyRevoked)
    }

    func cancelRecovery(transactionId: String, prompt: ApprovalPromptText? = nil) throws -> RecoveryCancelResult {
        let id = try CredentialSdk.hostString(transactionId, argument: "transactionId")
        let tx = try hold { try core.prepareRecoveryCancel(transactionId: id) }
        let outcome = try approve(tx, prompt: prompt)
        guard case .recoveryCancel(let r) = outcome else { throw Self.unexpected(outcome, "recovery cancel") }
        switch r {
        case .cancelled:
            return .cancelled
        case .completed(let deviceId, let pattern):
            return .completed(deviceId: deviceId, pattern: try pattern.map(DevicePattern.init))
        }
    }

    func revokePasskey(targetJti: String, prompt: ApprovalPromptText? = nil) throws -> PasskeyRevocation {
        let jti = try CredentialSdk.hostString(targetJti, argument: "targetJti")
        let tx = try hold { try core.preparePasskeyRevoke(targetJti: jti) }
        let outcome = try approve(tx, prompt: prompt)
        guard case .passkeyRevoke(let r) = outcome else { throw Self.unexpected(outcome, "passkey revoke") }
        return PasskeyRevocation(jti: r.jti, alreadyRevoked: r.alreadyRevoked)
    }

    // MARK: - mdoc

    func mdocIssueChallenge() throws -> MdocIssueChallenge {
        let c = try call { try core.mdocIssueChallenge() }
        return MdocIssueChallenge(challenge: c.challenge, tenant: c.tenant, audience: c.audience)
    }

    /// `prepare_mdoc_issue`, then `approve_mdoc_issue` with the host's signer:
    /// one scope, the host's signature verified by the core over the core's
    /// own input before anything is sent. When the host's closure threw, its
    /// own error is rethrown once the core has rolled the approval back.
    func issueMdoc(challenge: String, tenant: String, deviceKeyX: String, deviceKeyY: String,
                   prompt: ApprovalPromptText? = nil,
                   hostProof: @escaping HostProofSigner.Body) throws -> MdocIssued {
        let key = EcPublicJwk(kty: "EC", crv: "P-256",
                              x: try CredentialSdk.hostString(deviceKeyX, argument: "deviceKeyX"),
                              y: try CredentialSdk.hostString(deviceKeyY, argument: "deviceKeyY"))
        let tx = try hold {
            try core.prepareMdocIssue(challenge: try CredentialSdk.hostString(challenge, argument: "challenge"),
                                      tenant: try CredentialSdk.hostString(tenant, argument: "tenant"),
                                      deviceKey: key)
        }
        let signer = HostProofSigner(keys: keys, route: route, body: hostProof)
        let issued: CredentialSdkCoreBindings.MdocIssued
        do {
            gate.lock(); defer { gate.unlock() }
            issued = try withPrompt(tx, prompt) { try core.approveMdocIssue(handle: tx.handle, hostProof: signer) }
        } catch {
            if let hostError = signer.hostError { throw hostError }
            // The scope's Face ID failed: the LocalAuthentication error itself, as the host's own evaluation gave it
            // before SDK v2, so the host tells the person's cancel (.userCancel) from the system's (.systemCancel,
            // .appCancel).
            if let evaluation = signer.evaluationError { throw evaluation }
            throw Self.bridged(error)
        }
        return MdocIssued(jti: issued.jti, docType: issued.docType, namespace: issued.namespace,
                          issuerSigned: issued.issuerSigned, validFrom: issued.validFrom,
                          validUntil: issued.validUntil, replacedJtis: issued.replacedJtis)
    }

    // MARK: - JSON text

    /// A JSON string literal as `JSON.stringify` writes it (slashes unescaped).
    static func json(_ s: String) -> String {
        let data = try? JSONSerialization.data(withJSONObject: s, options: [.fragmentsAllowed, .withoutEscapingSlashes])
        return data.map { String(decoding: $0, as: UTF8.self) } ?? "\"\""
    }

    /// `{"patternVersion":v,"patternEntry":e}`, or `null`.
    static func json(_ pattern: CoreDevicePattern?) -> String {
        guard let p = pattern, let v = Int(exactly: p.patternVersion), let e = Int(exactly: p.patternEntry) else {
            return "null"
        }
        return "{\"patternVersion\":\(v),\"patternEntry\":\(e)}"
    }
}

// MARK: - The core's records as today's public types

extension DevicePattern {
    init(_ p: CoreDevicePattern) throws {
        guard let v = Int(exactly: p.patternVersion), let e = Int(exactly: p.patternEntry) else {
            throw CredentialSdkError.jsonError("pattern malformed: \(p)")
        }
        self.init(patternVersion: v, patternEntry: e)
    }
}

extension DeviceAttestationFacts {
    init(_ f: AttestationFacts) {
        switch f.platform {
        case .iphoneos: self.init(platform: "iphoneos")
        case .macosx:   self.init(platform: "macosx")
        }
    }
}

extension AttestationOutcome {
    init(_ o: CoreAttestationOutcome) {
        switch o {
        case .attested:
            self.init(attested: true, reason: nil)
        case .notAttested(let why):
            switch why {
            case .off:         self.init(attested: false, reason: .off)
            case .absent:      self.init(attested: false, reason: .absent)
            case .unsupported: self.init(attested: false, reason: .unsupported)
            }
        }
    }
}

extension EnrollResult {
    init(_ r: CoreEnrollResult) throws {
        let credentials: [[String: Any]] = try r.credentials.map { text in
            guard let object = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else {
                throw CredentialSdkError.jsonError("enroll response credential not a JSON object")
            }
            return object
        }
        self.init(deviceId: r.deviceId, externalId: r.externalId ?? "", credentials: credentials,
                  attestation: r.attestation.map(AttestationOutcome.init),
                  pattern: try (r.pattern ?? nil).map(DevicePattern.init))
    }
}

private func statusText(_ s: DeviceStatus) -> String {
    switch s {
    case .active:  return "active"
    case .revoked: return "revoked"
    }
}

private func roleText(_ r: DeviceRole) -> String {
    switch r {
    case .root:     return "root"
    case .endorsed: return "endorsed"
    }
}

extension DeviceSummary {
    init(_ d: CredentialSdkCoreBindings.DeviceSummary) throws {
        self.init(deviceId: d.deviceId, status: statusText(d.status), role: d.role.map(roleText),
                  createdAt: d.createdAt, attestation: d.attestation.map(DeviceAttestationFacts.init),
                  pattern: try d.pattern.map(DevicePattern.init), endorsedByDeviceId: d.endorsedByDeviceId,
                  isCaller: d.isCaller)
    }
}

extension EndorsementAlert {
    /// `deviceStatus` nil: the `deviceAlerts()` row, which carries none ("active").
    init(_ a: DeviceAlert, deviceStatus: DeviceStatus?) throws {
        self.init(alertId: a.alertId, deviceId: a.deviceId, createdAt: a.createdAt,
                  approvedByDeviceId: a.approvedByDeviceId, pattern: try a.pattern.map(DevicePattern.init),
                  attestation: a.attestation.map(DeviceAttestationFacts.init),
                  deviceStatus: deviceStatus.map(statusText) ?? "active")
    }
}

extension PasskeyAlert {
    init(_ a: CredentialSdkCoreBindings.PasskeyAlert) throws {
        self.init(alertId: a.alertId, jti: a.jti, origin: a.origin, rpId: a.rpId, label: a.label,
                  createdAt: a.createdAt, approvedByDeviceId: a.approvedByDeviceId,
                  pattern: try a.pattern.map(DevicePattern.init))
    }
}

extension IdentityAlert {
    init(_ a: CredentialSdkCoreBindings.IdentityAlert) throws {
        let kind: String
        switch a.kind {
        case .deviceRetired:     kind = "device_retired"
        case .recoveryStarted:   kind = "recovery_started"
        case .recoveryCompleted: kind = "recovery_completed"
        case .ringSignin:        kind = "ring_signin"
        }
        self.init(alertId: a.alertId, kind: kind, subject: a.subject, pattern: try a.pattern.map(DevicePattern.init),
                  createdAt: a.createdAt, siteName: a.siteName)
    }
}

extension Approvals {
    init(_ a: CredentialSdkCoreBindings.Approvals) throws {
        guard let since = Int(exactly: a.since) else {
            throw CredentialSdkError.jsonError("approvals reply has invalid since")
        }
        self.init(since: since, approvals: try a.approvals.map { r in
            let kind: String
            switch r.kind {
            case .device:  kind = "device"
            case .passkey: kind = "passkey"
            case .agent:   kind = "agent"
            case .mdoc:    kind = "mdoc"
            case .session: kind = "session"
            }
            return ApprovalRow(kind: kind, id: r.id, approvedByDeviceId: r.approvedByDeviceId, createdAt: r.createdAt,
                               status: r.status, pattern: try (r.pattern ?? nil).map(DevicePattern.init),
                               rpId: r.rpId, label: r.label, agentId: r.agentId, origin: r.origin)
        }, truncated: a.truncated)
    }
}

private func int(_ v: Int64, _ what: String) throws -> Int {
    guard let i = Int(exactly: v) else { throw CredentialSdkError.jsonError("identity graph: \(what) out of range") }
    return i
}

private func grants(_ map: [NamedGrant]) -> [String: GrantEntry] {
    var out: [String: GrantEntry] = [:]
    for g in map { out[g.name] = GrantEntry(claim: nil, action: g.grant.action, scope: g.grant.scope) }
    return out
}

extension IdentityGraph {
    init(_ g: CredentialSdkCoreBindings.IdentityGraph) throws {
        guard g.schemaVersion == 1 else {
            throw CredentialSdkError.jsonError("identity graph schemaVersion \(g.schemaVersion) not supported")
        }
        guard let claims = (try? JSONSerialization.jsonObject(with: Data(g.identity.claims.utf8))) as? [String: Any] else {
            throw CredentialSdkError.jsonError("identity graph identity: missing or malformed 'claims'")
        }
        let identity = IdentityNode(
            identityId: g.identity.identityId, status: g.identity.status,
            version: try int(g.identity.version, "version"), createdAt: g.identity.createdAt, claims: claims,
            grants: g.identity.grants.map { GrantEntry(claim: $0.claim, action: $0.action, scope: $0.scope) },
            grantsValid: g.identity.grantsValid)
        let devices: [GraphDeviceNode] = try g.devices.map { d in
            let platform: String?
            switch d.platform {
            case .iphoneos?: platform = "iphoneos"
            case .macosx?:   platform = "macosx"
            case nil:        platform = nil
            }
            let method: String?
            switch d.enrollmentMethod {
            case .bootstrap?:   method = "bootstrap"
            case .idp?:         method = "idp"
            case .endorsement?: method = "endorsement"
            case .reproof?:     method = "reproof"
            case nil:           method = nil
            }
            let attestation = try d.attestation.map { a -> GraphAttestation in
                let environment: String?
                switch a.environment {
                case .development?: environment = "development"
                case .production?:  environment = "production"
                case nil:           environment = nil
                }
                return GraphAttestation(environment: environment,
                                        validationCategory: try a.validationCategory.map { try int($0, "validationCategory") },
                                        appId: a.appId, bundleVersion: a.bundleVersion, codeHash: a.codeHash)
            }
            let credentials = try d.credentials.map {
                GraphCredentials(active: try int($0.active, "credentials.active"), issuedAt: $0.issuedAt, expiresAt: $0.expiresAt)
            }
            return GraphDeviceNode(
                deviceId: d.deviceId, isCaller: d.isCaller, role: d.role.map(roleText), status: statusText(d.status),
                platform: platform, enrollmentMethod: method, attestedAt: d.attestedAt,
                pattern: try d.pattern.map(DevicePattern.init), createdAt: d.createdAt, revokedAt: d.revokedAt,
                revocationSeq: try d.revocationSeq.map { try int($0, "revocationSeq") },
                endorsedByDeviceId: d.endorsedByDeviceId, replacesDeviceId: d.replacesDeviceId,
                replacedByDeviceId: d.replacedByDeviceId, cascade: d.cascade, attestation: attestation,
                credentials: credentials, cascadePasskeys: d.cascadePasskeys)
        }
        let agents: [AgentNode] = try g.agents.map { a in
            AgentNode(jti: a.jti, agentId: a.agentId, humanAuthorizationJti: a.humanAuthorizationJti,
                      status: statusText(a.status), grants: a.grants.map(grants),
                      authorizerDeviceId: a.authorizerDeviceId,
                      identityVersionAtIssuance: try int(a.identityVersionAtIssuance, "identityVersionAtIssuance"),
                      issuedAt: a.issuedAt, expiresAt: a.expiresAt, revokedAt: a.revokedAt,
                      revocationSeq: try a.revocationSeq.map { try int($0, "revocationSeq") })
        }
        let sessions: [SessionNode] = try g.sessions.map { s in
            SessionNode(sessionId: s.sessionId, status: s.status == .active ? "active" : "closed",
                        grants: grants(s.grants),
                        identityVersionAtIssuance: try int(s.identityVersionAtIssuance, "identityVersionAtIssuance"),
                        createdAt: s.createdAt, expiresAt: s.expiresAt, closedAt: s.closedAt)
        }
        let alerts: [AlertNode] = g.alerts.map { a in
            AlertNode(alertId: a.alertId, endorsedDeviceId: a.endorsedDeviceId, approvedByDeviceId: a.approvedByDeviceId,
                      createdAt: a.createdAt, acknowledgedAt: a.acknowledgedAt, resolvedAt: a.resolvedAt)
        }
        let passkeys: [PasskeyNode] = try g.passkeys.map { p in
            PasskeyNode(jti: p.jti, rpId: p.rpId, label: p.label, status: statusText(p.status),
                        authorizerDeviceId: p.authorizerDeviceId, humanAuthorizationJti: p.humanAuthorizationJti,
                        identityVersionAtIssuance: try int(p.identityVersionAtIssuance, "identityVersionAtIssuance"),
                        issuedAt: p.issuedAt, expiresAt: p.expiresAt, revokedAt: p.revokedAt,
                        revocationSeq: try p.revocationSeq.map { try int($0, "revocationSeq") },
                        pattern: try p.pattern.map(DevicePattern.init))
        }
        let mdocs: [MdocNode] = try g.mdocs.map { m in
            let status: String
            switch m.status {
            case .active:  status = "active"
            case .revoked: status = "revoked"
            case .unknown: status = "unknown"
            }
            return MdocNode(jti: m.jti, deviceId: m.deviceId, status: status,
                            humanAuthorizationJti: m.humanAuthorizationJti,
                            identityVersionAtIssuance: try int(m.identityVersionAtIssuance, "identityVersionAtIssuance"),
                            issuedAt: m.issuedAt, expiresAt: m.expiresAt, revokedAt: m.revokedAt,
                            revocationSeq: try m.revocationSeq.map { try int($0, "revocationSeq") })
        }
        self.init(schemaVersion: try int(g.schemaVersion, "schemaVersion"), generatedAt: g.generatedAt,
                  identity: identity, devices: devices, agents: agents, sessions: sessions, alerts: alerts,
                  devicesTruncated: g.truncated.devices, agentsTruncated: g.truncated.agents,
                  sessionsTruncated: g.truncated.sessions, alertsTruncated: g.truncated.alerts,
                  passkeys: passkeys, passkeysTruncated: g.truncated.passkeys,
                  mdocs: mdocs, mdocsTruncated: g.truncated.mdocs)
    }
}
