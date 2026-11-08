import Foundation

/// Optical reading: collects the 24-bit chunks of a payload from CRC-passing frames and
/// assembles it. Version 1 (pairing) is eight chunks and a 24-byte payload; version 2 (sign-in) is four chunks and a
/// 12-byte payload. No UI, camera or SDK dependency; the clock is injected so the timing rules can be tested.
///
/// The caller passes the decoder's whole first byte (the CRC already passed in the decoder). That byte is the
/// header: version = byte >> 3, index = byte & 7.
///
/// Rules (3a): a chunk not yet held is stored; a held index with the same value is a repeat and changes nothing;
/// a held index with a different value discards the whole collection and restarts from that frame; the collection
/// resets after 1.5 s without an accepted frame, at 5 s of age without completing, or when the person leaves.
/// The first accepted frame fixes the collection's version. A frame of the other version is a conflict, exactly like
/// a held index with another value: the collection is discarded and restarts from that frame under its version, so
/// chunks of a pairing ring and a sign-in ring are never mixed into one payload. Any version but 1 or 2, and an
/// index the frame's version does not have, is `rejected` and never stored (the collection and its timers are left
/// as they were).
@available(iOS 15, *)
struct OpticalCollector {
    typealias ResetReason = OpticalPairingReader.ResetReason

    enum Outcome: Equatable {
        case rejected               // not version 1 or 2, or an index its version lacks: not a frame this collector accepts
        case stored(index: Int)     // a new chunk
        case repeated               // the same value for a held index; nothing changed
        case restarted(index: Int)  // conflict: the collection was discarded, this frame starts a new one
        case complete(Data)         // the last chunk: the 24-byte (version 1) or 12-byte (version 2) payload, returned once
        case stopped                // already complete; collecting has stopped
    }

    /// Version 1 and its chunk count: what an idle collector reports.
    static let version = OpticalFrame.version
    static let chunkCount = OpticalFrame.chunkCount
    static let idleLimit = 1.5
    static let ageLimit = 5.0

    private(set) var chunks = [Int?](repeating: nil, count: OpticalFrame.maxChunkCount)
    /// The version of the frames held; nil while nothing is held.
    private(set) var activeVersion: Int?
    private(set) var resets: [ResetReason: Int] = [:]
    private(set) var finished = false
    private var startedAt: Double?
    private var lastAccepted: Double?
    private let now: () -> Double

    init(now: @escaping () -> Double) { self.now = now }

    var heldCount: Int { chunks.reduce(0) { $0 + ($1 == nil ? 0 : 1) } }
    /// Which pieces are held: sized for the version being collected (4 for a sign-in ring, 8 for pairing), and for
    /// version 1 while nothing is held.
    var held: [Bool] { chunks.prefix(chunkTotal).map { $0 != nil } }
    /// How many chunks complete the collection in progress.
    var chunkTotal: Int { OpticalFrame.chunkCount(version: activeVersion ?? Self.version) ?? Self.chunkCount }
    func resetCount(_ r: ResetReason) -> Int { resets[r] ?? 0 }

    /// Apply the idle and age limits. Call it on every camera frame, decoded or not, so a stale collection clears
    /// while nothing is being read. Returns the reason if it reset.
    @discardableResult
    mutating func expire() -> ResetReason? {
        guard !finished, heldCount > 0, let last = lastAccepted, let start = startedAt else { return nil }
        let t = now()
        if t - last >= Self.idleLimit { discard(.idle); return .idle }
        if t - start >= Self.ageLimit { discard(.age); return .age }
        return nil
    }

    /// The person left the scanner. A partial collection is discarded and counted.
    @discardableResult
    mutating func leave() -> ResetReason? {
        guard !finished, heldCount > 0 else { return nil }
        discard(.left)
        return .left
    }

    /// One frame whose CRC passed. `byte0` is the decoder's whole first byte.
    mutating func accept(byte0: Int, value: Int) -> Outcome {
        if finished { return .stopped }
        expire()
        let version = byte0 >> 3
        let index = byte0 & 7
        guard let count = OpticalFrame.chunkCount(version: version), index < count else { return .rejected }
        let t = now()
        lastAccepted = t
        // A frame of the other version than the one being collected is a conflict: nothing of the old ring survives.
        if let active = activeVersion, active != version {
            discard(.conflict)
            store(version, index, value, t)
            return .restarted(index: index)
        }
        if let held = chunks[index] {
            if held == value { return .repeated }
            discard(.conflict)
            store(version, index, value, t)
            return .restarted(index: index)
        }
        store(version, index, value, t)
        if heldCount == count {
            finished = true
            return .complete(assemble())
        }
        return .stored(index: index)
    }

    private mutating func store(_ version: Int, _ index: Int, _ value: Int, _ t: Double) {
        if heldCount == 0 { startedAt = t }
        activeVersion = version
        // A conflict's discard clears lastAccepted; the restarted collection needs it back, or expire() never runs
        // on it.
        lastAccepted = t
        chunks[index] = value & 0xFFFFFF
    }

    private mutating func discard(_ reason: ResetReason) {
        resets[reason, default: 0] += 1
        chunks = [Int?](repeating: nil, count: OpticalFrame.maxChunkCount)
        activeVersion = nil
        startedAt = nil
        lastAccepted = nil
    }

    /// Chunk i is bytes 3i..3i+2, big-endian; 24 bytes for version 1, 12 for version 2.
    private func assemble() -> Data {
        var bytes = [UInt8]()
        for c in chunks.prefix(chunkTotal) {
            let v = c ?? 0
            bytes.append(UInt8((v >> 16) & 255)); bytes.append(UInt8((v >> 8) & 255)); bytes.append(UInt8(v & 255))
        }
        return Data(bytes)
    }
}
