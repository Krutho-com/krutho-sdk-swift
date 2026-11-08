import Foundation
import CredentialSdkCoreBindings

/// The core's Mac passkey doors, as `CredentialSdk` calls them. `CredentialCore` answers them; tests
/// inject a stand-in to drive the verdict table and the boundary interleavings without an enrolled core.
protocol MacPasskeyCore: AnyObject {
    func prepareMacPasskey(tenant: String, request: CredentialSdkCoreBindings.MacPasskeyRequest) throws
        -> CredentialSdkCoreBindings.MacPasskeyPrepared
    func sendMacPasskey(token: String, sigPossession: Data, kbSignature: Data) throws
        -> CredentialSdkCoreBindings.MacPasskeyPending
    func cancelMacPasskey(token: String)
    func reportHighAssuranceInvalidated(token: String) throws -> KeyInvalidatedOutcome
    func reportHighAssuranceInvalidatedBound(binding: MacPasskeyHoldBinding,
                                             shape: CredentialSdkCoreBindings.KeyUnusableShape) throws
        -> KeyInvalidatedOutcome
    func resolveMacPasskeyHold(binding: MacPasskeyHoldBinding) throws -> HoldBinding
}

extension CredentialCore: MacPasskeyCore {}

/// Test seams for the Mac passkey door; nil (the defaults) in production.
final class MacPasskeySeams: @unchecked Sendable {
    /// Replaces the engine's core for the Mac passkey doors.
    var core: MacPasskeyCore?
    /// Replaces the hold store (default: the keychain, every group, or memory under in-memory storage).
    var holds: MacPasskeyHoldStore?
    /// Replaces the app's reading of the enrolled set against the high-assurance key's label.
    var comparison: (() -> BiometricSetComparison.Verdict)?
    /// Runs after the pre-send hold read, under the lock, just before the core's send.
    var willSend: (() -> Void)?
    /// Runs after the pre-M1 hold read, under the lock, just before the core's prepare.
    var willPrepare: (() -> Void)?
    /// Runs inside `resolveMacPasskeyHolds` after a hold's comparison and before its delete, with its id.
    var willDeleteHold: ((String) -> Void)?
}

extension CredentialSdk {

    // MARK: - The app side of the Mac passkey door

    /// M1: resolves any hold first (`resolveMacPasskeyHolds`), then reads the holds again; a hold left standing
    /// refuses `MacPasskeyDoorError.hold`. Then the core's `prepare_mac_passkey`: the statement and the KB-JWT signing
    /// input under a fresh token, or a typed refusal (`not_enrolled`, `key_invalidated`, `invalid_input` with its
    /// field, `no_credential`). All of it under the core's gate.
    public func prepareMacPasskey(tenant: String, request: MacPasskeyRequest) async throws -> MacPasskeyPrepared {
        try await initTask.value
        return try await runOnQueue { rust in
            rust.gate.lock(); defer { rust.gate.unlock() }
            let parts = self.macPasskeyParts(rust)
            try self.admitMacPasskey(parts)
            self.macPasskeySeams.willPrepare?()
            let coreRequest = CredentialSdkCoreBindings.MacPasskeyRequest(
                rpId: try CredentialSdk.hostString(request.rpId, argument: "rpId"),
                handleRef: try CredentialSdk.hostString(request.handleRef, argument: "handleRef"),
                credentialId: try CredentialSdk.hostString(request.credentialId, argument: "credentialId"),
                x: try CredentialSdk.hostString(request.x, argument: "x"),
                y: try CredentialSdk.hostString(request.y, argument: "y"),
                clientDataHash: try CredentialSdk.hostString(request.clientDataHash, argument: "clientDataHash"))
            do {
                return MacPasskeyPrepared(try parts.core.prepareMacPasskey(
                    tenant: try CredentialSdk.hostString(tenant, argument: "tenant"), request: coreRequest))
            } catch {
                throw MacPasskeyDoorError.from(error)
            }
        }
    }

    /// M3: resolves any hold first and reads the holds again, under the same gate as the send; a hold left standing
    /// spends the token and refuses `MacPasskeyDoorError.hold` with no request. Then the core's `send_mac_passkey`:
    /// it verifies both signatures and posts phase A, answering core-api's 202 or a typed refusal.
    public func sendMacPasskey(token: String, sigPossession: Data, kbSignature: Data) async throws
        -> MacPasskeyPending {
        try await initTask.value
        return try await runOnQueue { rust in
            rust.gate.lock(); defer { rust.gate.unlock() }
            let parts = self.macPasskeyParts(rust)
            let token = try CredentialSdk.hostString(token, argument: "token")
            do {
                try self.admitMacPasskey(parts)
            } catch {
                parts.core.cancelMacPasskey(token: token)
                throw error
            }
            self.macPasskeySeams.willSend?()
            do {
                let pending = try parts.core.sendMacPasskey(token: token, sigPossession: sigPossession,
                                                            kbSignature: kbSignature)
                return MacPasskeyPending(handleRef: pending.handleRef, pendingExpiresAt: pending.pendingExpiresAt)
            } catch {
                throw MacPasskeyDoorError.from(error)
            }
        }
    }

    /// M4: the core forgets the token. Never fails for an unknown token.
    public func cancelMacPasskey(token: String) async throws {
        try await initTask.value
        try await runOnQueue { rust in
            rust.gate.lock(); defer { rust.gate.unlock() }
            self.macPasskeyParts(rust).core.cancelMacPasskey(token: try CredentialSdk.hostString(token, argument: "token"))
        }
    }

    /// M5: re-validates `shape` in this process with `isKeyUnusableShape`'s rule (a forged description or `AKSError`
    /// is `notAShape`, whatever the hashes say), then reads the enrolled set in the app's identity against the
    /// high-assurance key's label: `changed` calls the core's `report_high_assurance_invalidated` (the self-revoke, for
    /// a live token of this enrollment); `unchanged` or `unknown` destroys nothing (`notCorroborated`). The token is
    /// spent on every path.
    public func reportMacPasskeyKeyUnusable(token: String, shape: KeyUnusableShape) async throws
        -> KeyUnusableVerdict {
        try await initTask.value
        return try await runOnQueue { rust in
            rust.gate.lock(); defer { rust.gate.unlock() }
            let parts = self.macPasskeyParts(rust)
            let token = try CredentialSdk.hostString(token, argument: "token")
            guard shape.isAdmitted else {
                parts.core.cancelMacPasskey(token: token)
                return .notAShape
            }
            guard parts.comparison() == .changed else {
                parts.core.cancelMacPasskey(token: token)
                return .notCorroborated
            }
            do {
                return .revoked(MacPasskeyRevocation(try parts.core.reportHighAssuranceInvalidated(token: token)))
            } catch CredentialSdkCoreBindings.MacPasskeyError.Refused(let refusal, _, _)
                        where [.staleReport, .unknownToken, .staleToken].contains(refusal) {
                return .staleReport
            } catch {
                throw MacPasskeyDoorError.from(error)
            }
        }
    }

    /// Decides every hold item, each on its own, under the core's gate:
    /// 1. its decoded shape is re-validated first; an item that does not decode, or whose shape the rule refuses, is
    ///    `notAShape`, deleted by its id, nothing destroyed;
    /// 2. the core answers whether its binding names this enrollment (`resolve_mac_passkey_hold`); `stale` is
    ///    `staleHold`, deleted, nothing destroyed;
    /// 3. bound: the enrolled set is read in this process; `changed` calls the core's bound destructive door
    ///    (`revoked`, deleted), `unchanged` is deleted, `unknown` (a lockout, no readable set) stays.
    /// Each item is deleted by its exact id, never by a read-compare-delete: a hold added meanwhile is its own item and
    /// is decided on the next pass. A core or keychain failure while deciding leaves that item (`failed`).
    public func resolveMacPasskeyHolds() async throws -> [HoldVerdict] {
        try await initTask.value
        return try await runOnQueue { rust in
            rust.gate.lock(); defer { rust.gate.unlock() }
            return try self.resolveHolds(self.macPasskeyParts(rust))
        }
    }

    // MARK: - Internals

    struct MacPasskeyParts {
        let core: MacPasskeyCore
        let holds: MacPasskeyHoldStore
        let comparison: () -> BiometricSetComparison.Verdict
    }

    private func macPasskeyParts(_ rust: RustEngine) -> MacPasskeyParts {
        let seams = macPasskeySeams
        let keys = rust.keys
        return MacPasskeyParts(
            core: seams.core ?? rust.core,
            holds: seams.holds ?? MacPasskeyHoldStore(backing: rust.storage.backing),
            comparison: seams.comparison ?? { keys.biometricSetComparison(usage: "high-assurance").verdict })
    }

    /// The app's guard before M1 and before the send: resolve, then read again. Caller holds the gate.
    private func admitMacPasskey(_ parts: MacPasskeyParts) throws {
        _ = try resolveHolds(parts)
        let standing: String?
        do { standing = try parts.holds.standingHoldId() } catch { throw Self.holdStoreError(error) }
        if let standing { throw MacPasskeyDoorError.hold(holdId: standing) }
    }

    private func resolveHolds(_ parts: MacPasskeyParts) throws -> [HoldVerdict] {
        let items: [(id: String, hold: MacPasskeyHold?)]
        do { items = try parts.holds.items() } catch { throw Self.holdStoreError(error) }
        return items.map { resolveHold(id: $0.id, hold: $0.hold, parts) }
    }

    private func resolveHold(id: String, hold: MacPasskeyHold?, _ parts: MacPasskeyParts) -> HoldVerdict {
        func definite(_ outcome: HoldVerdict.Outcome) -> HoldVerdict {
            macPasskeySeams.willDeleteHold?(id)
            do {
                try parts.holds.delete(id: id)
                return HoldVerdict(holdId: id, outcome: outcome, deleted: true)
            } catch {
                return HoldVerdict(holdId: id, outcome: outcome, deleted: false)
            }
        }
        guard let hold, hold.shape.isAdmitted else { return definite(.notAShape) }
        let binding = MacPasskeyHoldBinding(server: hold.server, deviceId: hold.deviceId,
                                            highKeyThumbprint: hold.highKeyThumbprint, writtenAt: hold.writtenAt)
        let bound: HoldBinding
        do { bound = try parts.core.resolveMacPasskeyHold(binding: binding) } catch {
            return HoldVerdict(holdId: id, outcome: .failed(String(describing: MacPasskeyDoorError.from(error))),
                               deleted: false)
        }
        guard bound == .bound else { return definite(.staleHold) }
        switch parts.comparison() {
        case .unknown:
            return HoldVerdict(holdId: id, outcome: .unknown, deleted: false)
        case .unchanged:
            return definite(.unchanged)
        case .changed:
            do {
                let outcome = try parts.core.reportHighAssuranceInvalidatedBound(binding: binding, shape: hold.shape.core)
                return definite(.revoked(MacPasskeyRevocation(outcome)))
            } catch CredentialSdkCoreBindings.MacPasskeyError.Refused(.staleHold, _, _) {
                return definite(.staleHold)
            } catch CredentialSdkCoreBindings.MacPasskeyError.Refused(.notAShape, _, _) {
                return definite(.notAShape)
            } catch {
                return HoldVerdict(holdId: id, outcome: .failed(String(describing: MacPasskeyDoorError.from(error))),
                                   deleted: false)
            }
        }
    }

    private static func holdStoreError(_ error: Error) -> Error {
        if let storage = error as? KeychainStorageError {
            return MacPasskeyDoorError.storageFailed(code: storage.bridgeCode, detail: storage.detail)
        }
        return MacPasskeyDoorError.failed(String(describing: error))
    }
}
