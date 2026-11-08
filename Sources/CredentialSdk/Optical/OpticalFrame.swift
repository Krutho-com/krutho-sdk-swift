import Foundation

/// Optical frames (protocol sections 3 and 3a). A frame is 48 bits: header(8) | value(24) | crc16(16).
/// header = (version << 3) | index. CRC-16/CCITT-FALSE over the four bytes header + value.
///
///   version 1: payload A, 8 chunks of 3 bytes, a 24-byte payload (pairing)
///   version 2: sign-in, 4 chunks of 3 bytes, a 12-byte payload (6 handle bytes, 6 commitment bytes)
///
/// The TypeScript twin is `credential-sdk-core/src/optical/frame.ts`; both are pinned by
/// `optical-vectors.json`. Every call that does not name a version means version 1, so the pairing path
/// (the Mac's pattern and its tests) is untouched.
enum OpticalFrame {
    /// Version 1, the pairing payload.
    static let payloadLength = 24
    static let chunkCount = 8
    static let version = 1
    /// Version 2, the sign-in payload.
    static let signInVersion = 2

    /// How many 3-byte chunks a payload of `version` has; nil for a version this reader does not know.
    static func chunkCount(version: Int) -> Int? {
        switch version {
        case 1: return 8
        case 2: return 4
        default: return nil
        }
    }

    /// The payload length of `version`, or nil.
    static func payloadLength(for version: Int) -> Int? { chunkCount(version: version).map { $0 * 3 } }

    /// The most chunks any version has: the size of a collector's chunk table.
    static let maxChunkCount = 8

    static func crc16(_ data: [UInt8]) -> UInt16 {
        var crc: UInt16 = 0xFFFF
        for b in data {
            crc ^= UInt16(b) << 8
            for _ in 0..<8 { crc = (crc & 0x8000) != 0 ? (crc << 1) ^ 0x1021 : crc << 1 }
        }
        return crc
    }

    static func header(index: Int, version: Int = OpticalFrame.version) -> UInt8 { UInt8((version << 3) | (index & 7)) }
    static func version(of header: UInt8) -> Int { Int(header >> 3) }
    static func index(of header: UInt8) -> Int { Int(header & 7) }

    /// Chunk `index` of a payload as a 24-bit big-endian value.
    static func value(_ payload: Data, index: Int) -> UInt32 {
        let b = [UInt8](payload)
        return UInt32(b[3 * index]) << 16 | UInt32(b[3 * index + 1]) << 8 | UInt32(b[3 * index + 2])
    }

    /// The 48-bit frame word for chunk `index` of `payload` under `version` (1 when not named).
    static func word(payload: Data, index: Int, version: Int = OpticalFrame.version) -> UInt64 {
        let h = header(index: index, version: version), v = value(payload, index: index)
        let body: [UInt8] = [h, UInt8((v >> 16) & 255), UInt8((v >> 8) & 255), UInt8(v & 255)]
        return UInt64(h) << 40 | UInt64(v) << 16 | UInt64(crc16(body))
    }

    /// Bit `i` (0 = MSB) of a frame word, for the renderer and the decoder's bit order.
    static func bit(_ word: UInt64, _ i: Int) -> Int { Int((word >> UInt64(47 - i)) & 1) }

    /// A decoded 48-bit word split into its fields; `ok` is the CRC check.
    struct Decoded: Equatable {
        let header: UInt8
        let value: UInt32
        let crc: UInt16
        let ok: Bool
        init(word: UInt64) {
            header = UInt8((word >> 40) & 255)
            value = UInt32((word >> 16) & 0xFFFFFF)
            crc = UInt16(word & 0xFFFF)
            let body: [UInt8] = [header, UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255)]
            ok = OpticalFrame.crc16(body) == crc
        }
    }
}
