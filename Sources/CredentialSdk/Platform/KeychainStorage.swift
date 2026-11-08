import Foundation
import Security

/// Keychain-backed key/value storage using the generic-password class.
///
/// **No automatic fallback.** The storage used to probe the keychain at init
/// and, on failure, silently switch to an in-process dictionary. In
/// production that dropped the core's invalidation tombstone at the next
/// launch. Now the backing is exactly what the
/// caller asks for: `.keychain` (the default) fails typed
/// (`KeychainStorageError`) when the keychain is unusable, and
/// `CredentialSdk` checks it at initialization (`checkAvailable()`). Test
/// processes without a keychain entitlement pass
/// `backing: .insecureInMemoryTestOnly` explicitly.
public final class KeychainStorage {

    /// The SecItem calls the keychain path makes, replaceable so tests can
    /// drive every status branch without a keychain.
    struct SecItemOps {
        var copyMatching: (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
        var update: (CFDictionary, CFDictionary) -> OSStatus
        var add: (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
        var delete: (CFDictionary) -> OSStatus

        static let live = SecItemOps(
            copyMatching: SecItemCopyMatching,
            update: SecItemUpdate,
            add: SecItemAdd,
            delete: SecItemDelete
        )
    }

    let backing: StorageBacking
    private let service: String
    /// The keychain access group every item is read, written and removed under (`kSecAttrAccessGroup`). Nil, the
    /// default, adds no group: the keychain uses the process's first group, as before. Lets a Mac app and its passkey
    /// extension share one store.
    let accessGroup: String?
    private let ops: SecItemOps
    private var usesFallback: Bool { backing == .insecureInMemoryTestOnly }

    // Explicit in-memory store (test-only), keyed by service, protected by a lock. `accessGroup` is ignored in
    // fallback mode: two stores with one service and different groups share these entries.
    private static var fallbackEntries: [String: [String: String]] = [:]
    private static let fallbackLock = NSLock()

    public init(
        service: String = "com.krutho.credentialsdk.storage",
        backing: StorageBacking = .keychain,
        accessGroup: String? = nil
    ) {
        self.service = service
        self.backing = backing
        self.accessGroup = accessGroup
        self.ops = .live
    }

    /// Test seam: the keychain path (never the fallback) with stubbed SecItem calls.
    init(service: String, ops: SecItemOps, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
        self.backing = .keychain
        self.ops = ops
        self.usesLiveOps = false
    }

    /// False for the test seam above: stubbed calls reach no shared store, so such a storage is only ever itself.
    private var usesLiveOps = true

    /// A descriptive label for this storage: its backing, service and, when one is set, `@<access group>`. Nothing
    /// decides on it. Core ownership is decided by `ownershipKey` (backing and service, no group), because a storage
    /// with no group reaches the records of one with a group; `RustEngine.engine` keys its registry on that and
    /// compares `accessGroup` itself. A storage with stubbed SecItem calls is its own label.
    var sharingIdentity: String {
        guard usesLiveOps else { return ownershipKey }
        return ownershipKey + (accessGroup.map { "@\($0)" } ?? "")
    }

    /// What decides who may own a core over this storage: the backing and service, not the group. A storage with no
    /// group looks up, updates and deletes across every group the process may use, so it reaches the records of one
    /// with a group; `RustEngine.engine` keys its registry on this and refuses a second group over a live core.
    var ownershipKey: String {
        guard usesLiveOps else { return "stub:\(ObjectIdentifier(self).hashValue)" }
        return "\(usesFallback ? "memory" : "keychain"):\(service)"
    }

    /// macOS: route to the data-protection (iOS-style) keychain; required for
    /// Secure Enclave keys and gives iOS-parity semantics. No-op on iOS. Adds
    /// the access group when one is configured.
    private func withPlatformDefaults(_ dict: [String: Any]) -> [String: Any] {
        var d = dict
        #if os(macOS)
        d[kSecUseDataProtectionKeychain as String] = true
        #endif
        if let accessGroup { d[kSecAttrAccessGroup as String] = accessGroup }
        return d
    }

    /// Proves the keychain can store and delete an item for this process:
    /// deletes any stale probe (success or not-found), adds one, deletes it.
    /// Throws `KeychainStorageError.unavailable` with the failing status.
    /// No-op for the explicit in-memory backing.
    public func checkAvailable() throws {
        if usesFallback { return }
        let query: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrService as String:    "com.krutho.credentialsdk.__probe",
            kSecAttrAccount as String:    "probe",
            kSecValueData as String:      Data("probe".utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let q = withPlatformDefaults(query) as CFDictionary
        let stale = ops.delete(q)
        guard stale == errSecSuccess || stale == errSecItemNotFound else {
            throw KeychainStorageError.unavailable(status: stale)
        }
        let added = ops.add(q, nil)
        guard added == errSecSuccess else { throw KeychainStorageError.unavailable(status: added) }
        let removed = ops.delete(q)
        guard removed == errSecSuccess else { throw KeychainStorageError.unavailable(status: removed) }
    }

    /// The stored string, or `nil` only when the item does not exist
    /// (`errSecItemNotFound`). Any other status throws
    /// `KeychainStorageError.readFailed`: a read that failed is never
    /// reported as "absent" (the core's invalidation tombstone depends on it).
    public func get(key: String) throws -> String? {
        if usesFallback { return getFallback(key: key) }
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let status = ops.copyMatching(withPlatformDefaults(query) as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw KeychainStorageError.readFailed(key: key, status: status)
        }
        guard let data = out as? Data, let string = String(data: data, encoding: .utf8) else {
            throw KeychainStorageError.readFailed(key: key, status: errSecDecode)
        }
        return string
    }

    /// Writes the value, or throws `KeychainStorageError.writeFailed`. Update
    /// first; if that does not succeed, delete (success or not-found) then
    /// add, and the add must succeed.
    public func set(key: String, value: String) throws {
        if usesFallback { setFallback(key: key, value: value); return }
        let data = Data(value.utf8)
        let base: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        let update: [String: Any] = [
            kSecValueData as String:      data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let updateStatus = ops.update(withPlatformDefaults(base) as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        let deleteStatus = ops.delete(withPlatformDefaults(base) as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw KeychainStorageError.writeFailed(key: key, status: deleteStatus)
        }
        var add = base
        add[kSecValueData as String]      = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = ops.add(withPlatformDefaults(add) as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainStorageError.writeFailed(key: key, status: addStatus)
        }
    }

    /// Removes the item; success or not-found is success. Any other status
    /// throws `KeychainStorageError.removeFailed`.
    public func remove(key: String) throws {
        if usesFallback { removeFallback(key: key); return }
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        let status = ops.delete(withPlatformDefaults(query) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStorageError.removeFailed(key: key, status: status)
        }
    }

    /// Clears every entry under the configured service. Test-only.
    func wipeAll() {
        if usesFallback {
            Self.fallbackLock.lock()
            defer { Self.fallbackLock.unlock() }
            Self.fallbackEntries[service] = nil
            return
        }
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        _ = SecItemDelete(withPlatformDefaults(query) as CFDictionary)
    }

    // MARK: - Fallback

    private func getFallback(key: String) -> String? {
        Self.fallbackLock.lock()
        defer { Self.fallbackLock.unlock() }
        return Self.fallbackEntries[service]?[key]
    }

    private func setFallback(key: String, value: String) {
        Self.fallbackLock.lock()
        defer { Self.fallbackLock.unlock() }
        if Self.fallbackEntries[service] == nil {
            Self.fallbackEntries[service] = [:]
        }
        Self.fallbackEntries[service]?[key] = value
    }

    private func removeFallback(key: String) {
        Self.fallbackLock.lock()
        defer { Self.fallbackLock.unlock() }
        Self.fallbackEntries[service]?.removeValue(forKey: key)
    }
}

/// A keychain read or write that did not complete. Crosses the JS bridge as
/// `storage_error:<code>: <detail>`, with the OSStatus as `Code=<n>`.
public enum KeychainStorageError: Error, Equatable, LocalizedError {
    /// `SecItemCopyMatching` returned a status other than success or
    /// not-found, or returned data that is not UTF-8 (`errSecDecode`).
    case readFailed(key: String, status: OSStatus)
    /// The update, the delete before add, or the add did not succeed.
    case writeFailed(key: String, status: OSStatus)
    /// `SecItemDelete` returned a status other than success or not-found.
    case removeFailed(key: String, status: OSStatus)
    /// The keychain cannot store items for this process (for example
    /// `errSecMissingEntitlement`, -34018). Raised by `checkAvailable()`,
    /// which `CredentialSdk` runs at initialization.
    case unavailable(status: OSStatus)

    public var bridgeCode: String {
        switch self {
        case .readFailed:  return "storage_read_failed"
        case .writeFailed:  return "storage_write_failed"
        case .removeFailed: return "storage_remove_failed"
        case .unavailable:  return "storage_unavailable"
        }
    }

    /// The text after the code: what failed, with the status as `Code=<n>`.
    public var detail: String {
        switch self {
        case .readFailed(let key, let status):
            return "reading '\(key)' failed: Error Domain=NSOSStatusErrorDomain Code=\(status)"
        case .writeFailed(let key, let status):
            return "writing '\(key)' failed: Error Domain=NSOSStatusErrorDomain Code=\(status)"
        case .removeFailed(let key, let status):
            return "removing '\(key)' failed: Error Domain=NSOSStatusErrorDomain Code=\(status)"
        case .unavailable(let status):
            return "the keychain cannot store items for this process: Error Domain=NSOSStatusErrorDomain Code=\(status)"
        }
    }

    public var errorDescription: String? {
        "storage_error:\(bridgeCode): \(detail)"
    }
}

/// Where `KeychainStorage` keeps its items. There is no automatic choice.
public enum StorageBacking: Equatable {
    /// Production: the keychain, or a typed `KeychainStorageError`.
    case keychain
    /// Test-only: an in-process dictionary. NOT persistent: the core's
    /// invalidation tombstone would not survive a relaunch. Never use outside
    /// test bundles.
    case insecureInMemoryTestOnly
}
