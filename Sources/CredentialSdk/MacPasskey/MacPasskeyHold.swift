import Foundation
import Security

/// A durable refusal: the extension measured a key-unusable shape and could not deliver M5, so it
/// writes this before cancelling. While a hold younger than `expiry` stands, every ceremony is refused at its next
/// guard: the extension before M1, the door before its evaluation, the app before M1 and before the send. The app
/// resolves it (`CredentialSdk.resolveMacPasskeyHolds()`).
///
/// It refers to no core's memory: it carries the persisted binding the app can check after a restart.
public struct MacPasskeyHold: Codable, Equatable, Sendable {
    /// The item's id: its account is `hold.<holdId>`.
    public let holdId: String
    /// The core API URL from M1's answer (`MacPasskeyPrepared.server`).
    public let server: String
    /// The canonical's `device`.
    public let deviceId: String
    /// The RFC 7638 thumbprint of the high-assurance public key the door signed with.
    public let highKeyThumbprint: String
    public let shape: KeyUnusableShape
    /// When the extension wrote it, Unix seconds.
    public let writtenAt: UInt64

    /// How long a hold stands: older, the door and the extension ignore it and the app resolves it `stale_hold`
    /// (30 days, a default; the core's `HOLD_EXPIRY_S`).
    public static let expiry: UInt64 = 30 * 86_400

    public init(holdId: String = UUID().uuidString, server: String, deviceId: String, highKeyThumbprint: String,
                shape: KeyUnusableShape, writtenAt: UInt64 = MacPasskeyHold.now()) {
        self.holdId = holdId
        self.server = server
        self.deviceId = deviceId
        self.highKeyThumbprint = highKeyThumbprint
        self.shape = shape
        self.writtenAt = writtenAt
    }

    /// The hold for a ceremony whose high-assurance signature refused with `shape`: binding from `prepared` (its
    /// `server` and the canonical's `device`) and the thumbprint of `keys`' high-assurance public key, read without a
    /// prompt.
    public init(prepared: MacPasskeyPrepared, keys: KeychainKeys, shape: KeyUnusableShape,
                writtenAt: UInt64 = MacPasskeyHold.now()) throws {
        guard let statement = (try? JSONSerialization.jsonObject(with: Data(prepared.canonical.utf8))) as? [String: Any],
              let device = statement["device"] as? String else {
            throw MacPasskeyCheckError.malformed(field: "canonical")
        }
        self.init(server: prepared.server, deviceId: device,
                  highKeyThumbprint: try keys.publicKeyThumbprint(usage: "high-assurance"), shape: shape,
                  writtenAt: writtenAt)
    }

    /// True once the hold is older than `expiry` at `now`.
    public func isExpired(now: UInt64 = MacPasskeyHold.now()) -> Bool {
        now >= writtenAt && now - writtenAt > Self.expiry
    }

    public static func now() -> UInt64 { UInt64(Date().timeIntervalSince1970) }

    private enum CodingKeys: String, CodingKey {
        case holdId = "hold_id", server, deviceId = "device_id", highKeyThumbprint = "high_key_thumbprint", shape,
             writtenAt = "written_at"
    }
}

/// The hold items in the keychain: one generic password per event, account `hold.<holdId>`, service
/// `com.krutho.credentialsdk.mac-passkey-hold`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Items are added once and
/// never updated; reading lists them all; deleting names one exact account. Nothing reads, compares and deletes in one
/// step, so a hold added after another's final comparison is never removed by it.
///
/// `accessGroup` is the group a hold is added in (the extension's `.passkeys` group). Nil adds in the process's first
/// group; reads and deletes with nil search every group the process may use, so the app reads and deletes holds with
/// nil while it lists `.passkeys` second.
public final class MacPasskeyHoldStore {
    public static let service = "com.krutho.credentialsdk.mac-passkey-hold"
    static let accountPrefix = "hold."

    private let accessGroup: String?
    private let backing: StorageBacking
    private let service: String
    /// The clock the standing check reads; replaceable so tests can age a hold.
    var now: () -> UInt64 = MacPasskeyHold.now

    // In-memory items (test-only), keyed by service then account; holds the encoded bytes as the keychain would.
    private static var memory: [String: [String: Data]] = [:]
    private static let memoryLock = NSLock()

    public init(accessGroup: String? = nil, backing: StorageBacking = .keychain) {
        self.accessGroup = accessGroup
        self.backing = backing
        self.service = Self.service
    }

    /// Test seam: an in-memory store under its own service, so tests never see each other's holds.
    init(testService: String) {
        self.accessGroup = nil
        self.backing = .insecureInMemoryTestOnly
        self.service = testService
    }

    private func base(account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        if let account { query[kSecAttrAccount as String] = account }
        #if os(macOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        return query
    }

    /// Adds `hold` as a new item. Never updates: an item with the same account already there is refused
    /// (`writeFailed` with `errSecDuplicateItem`), and nothing is changed.
    public func add(_ hold: MacPasskeyHold) throws {
        let account = Self.accountPrefix + hold.holdId
        let data = try JSONEncoder().encode(hold)
        if backing == .insecureInMemoryTestOnly {
            Self.memoryLock.lock(); defer { Self.memoryLock.unlock() }
            guard Self.memory[service]?[account] == nil else {
                throw KeychainStorageError.writeFailed(key: account, status: errSecDuplicateItem)
            }
            Self.memory[service, default: [:]][account] = data
            return
        }
        var add = base(account: account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        if let accessGroup { add[kSecAttrAccessGroup as String] = accessGroup }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainStorageError.writeFailed(key: account, status: status) }
    }

    /// Every hold item that decodes, in no particular order.
    public func all() throws -> [MacPasskeyHold] {
        try items().compactMap(\.hold)
    }

    /// Deletes the one item `hold.<id>`; nothing else is touched. Gone already is success.
    public func delete(id: String) throws {
        let account = Self.accountPrefix + id
        if backing == .insecureInMemoryTestOnly {
            Self.memoryLock.lock(); defer { Self.memoryLock.unlock() }
            Self.memory[service]?.removeValue(forKey: account)
            return
        }
        let status = SecItemDelete(base(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStorageError.removeFailed(key: account, status: status)
        }
    }

    /// The id of a hold that stands now, or nil: any item younger than `expiry`, and any item that does not decode
    /// (its age cannot be read, so it refuses until the app resolves it). A failed read throws: the guard refuses
    /// rather than admit a ceremony it could not check.
    public func standingHoldId() throws -> String? {
        let now = self.now()
        for item in try items() {
            guard let hold = item.hold else { return item.id }
            if !hold.isExpired(now: now) { return item.id }
        }
        return nil
    }

    /// Every `hold.*` item: its id and the hold it decodes to (nil when it does not).
    func items() throws -> [(id: String, hold: MacPasskeyHold?)] {
        let raw: [(String, Data?)]
        if backing == .insecureInMemoryTestOnly {
            Self.memoryLock.lock()
            raw = (Self.memory[service] ?? [:]).map { ($0.key, $0.value) }
            Self.memoryLock.unlock()
        } else {
            var query = base(account: nil)
            query[kSecMatchLimit as String] = kSecMatchLimitAll
            query[kSecReturnAttributes as String] = true
            query[kSecReturnData as String] = true
            var out: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &out)
            if status == errSecItemNotFound { return [] }
            guard status == errSecSuccess, let rows = out as? [[String: Any]] else {
                throw KeychainStorageError.readFailed(key: Self.accountPrefix + "*", status: status)
            }
            raw = rows.compactMap { row in
                (row[kSecAttrAccount as String] as? String).map { ($0, row[kSecValueData as String] as? Data) }
            }
        }
        return raw.filter { $0.0.hasPrefix(Self.accountPrefix) }.sorted { $0.0 < $1.0 }.map { account, data in
            let id = String(account.dropFirst(Self.accountPrefix.count))
            let hold = data.flatMap { try? JSONDecoder().decode(MacPasskeyHold.self, from: $0) }
            // An item whose content names another id is not a hold this account describes.
            return (id, hold?.holdId == id ? hold : nil)
        }
    }

    /// Test seam: writes raw bytes under `hold.<id>`, as a forged or damaged item would be.
    func addRaw(id: String, data: Data) {
        precondition(backing == .insecureInMemoryTestOnly)
        Self.memoryLock.lock(); defer { Self.memoryLock.unlock() }
        Self.memory[service, default: [:]][Self.accountPrefix + id] = data
    }
}
