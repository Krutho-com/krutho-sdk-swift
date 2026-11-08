import Foundation
import CoreGraphics

/// The frozen v1 drawing of one device pattern: the `buildSVG` output
/// (woven cloth, 1000 x 1000 viewBox) kept as data, the same data the server
/// serves as SVG, so both renderers draw the same vertices.
///
/// Paint order, which `draw(...)` follows: the ground rectangle in the ground
/// colour; each of the three ink paths in the ink colour (nonzero rule, one
/// path at a time, as separate SVG `<path>` elements fill); the cut path in
/// the ground colour (nonzero rule, one path); all clipped to the square.
/// On an opaque ground this equals the SVG's masked rendering up to
/// anti-aliasing.
public struct SettGeometry {
    /// The viewBox side every coordinate is in.
    public static let viewBox: CGFloat = 1000

    /// The ink polygons of the three families, flattened in path order.
    public let ink: [[CGPoint]]
    /// The break (cut) polygons.
    public let cut: [[CGPoint]]
    /// The ink grouped by source path (three), kept so each path is filled on
    /// its own, as the SVG does.
    let inkPaths: [[[CGPoint]]]

    init(inkPaths: [[[CGPoint]]], cut: [[CGPoint]]) {
        self.inkPaths = inkPaths
        self.ink = inkPaths.flatMap { $0 }
        self.cut = cut
    }

    /// How many patterns the v1 list holds (N), or 0 when the list is not
    /// readable.
    public static var count: Int { Store.shared.count }

    /// The geometry for a pattern, or `nil` for any version but 1, an entry
    /// outside `[0, N)`, or data this build cannot read. A caller shows the
    /// fallback words on `nil`.
    public static func entry(_ p: DevicePattern) -> SettGeometry? {
        guard p.patternVersion == 1, p.patternEntry >= 0, p.patternEntry < Store.shared.count else { return nil }
        return Store.shared.geometry(at: p.patternEntry)
    }

    /// The v1 list entry's `tc` string for an index, for tests that prove the
    /// list is consumed identically across implementations.
    static func tc(at entry: Int) -> String? { Store.shared.tc(at: entry) }

    // MARK: Paths

    /// One CGPath per ink path (nonzero fill each), and one for the cut.
    func cgPaths() -> (ink: [CGPath], cut: CGPath) {
        (inkPaths.map(Self.cgPath), Self.cgPath(cut))
    }

    static func cgPath(_ polygons: [[CGPoint]]) -> CGPath {
        let path = CGMutablePath()
        for polygon in polygons where polygon.count > 1 {
            path.addLines(between: polygon)
            path.closeSubpath()
        }
        return path
    }

    /// Draws the pattern into the square `rect` of `ctx` (any size; the 1000
    /// unit viewBox is scaled to fit). The caller owns the context's y-axis.
    public func draw(in ctx: CGContext, rect: CGRect, ink inkColor: CGColor, ground groundColor: CGColor) {
        let (inkPaths, cutPath) = cgPaths()
        ctx.saveGState()
        ctx.clip(to: rect)
        ctx.translateBy(x: rect.minX, y: rect.minY)
        ctx.scaleBy(x: rect.width / Self.viewBox, y: rect.height / Self.viewBox)
        ctx.setFillColor(groundColor)
        ctx.fill(CGRect(x: 0, y: 0, width: Self.viewBox, height: Self.viewBox))
        ctx.setFillColor(inkColor)
        for path in inkPaths {
            ctx.addPath(path)
            ctx.fillPath(using: .winding)
        }
        ctx.setFillColor(groundColor)
        ctx.addPath(cutPath)
        ctx.fillPath(using: .winding)
        ctx.restoreGState()
    }

    // MARK: Path grammar

    /// Parses the frozen path grammar: `M x,y`, `L x,y`, `Z`, numbers with one
    /// decimal, no separators other than the comma. Returns `nil` on any
    /// other character or a malformed number.
    public static func parse(_ d: String) -> [[CGPoint]]? {
        var polygons: [[CGPoint]] = []
        var current: [CGPoint] = []
        var open = false
        let bytes = Array(d.utf8)
        var i = 0
        func number() -> Double? {
            let start = i
            if i < bytes.count, bytes[i] == UInt8(ascii: "-") { i += 1 }
            while i < bytes.count, (bytes[i] >= 0x30 && bytes[i] <= 0x39) || bytes[i] == UInt8(ascii: ".") { i += 1 }
            guard i > start, let s = String(bytes: bytes[start..<i], encoding: .utf8) else { return nil }
            return Double(s)
        }
        while i < bytes.count {
            let c = bytes[i]
            switch c {
            case UInt8(ascii: "M"), UInt8(ascii: "L"):
                i += 1
                guard let x = number() else { return nil }
                guard i < bytes.count, bytes[i] == UInt8(ascii: ",") else { return nil }
                i += 1
                guard let y = number() else { return nil }
                if c == UInt8(ascii: "M") {
                    if open { polygons.append(current) }
                    current = []
                    open = true
                } else if !open {
                    return nil
                }
                current.append(CGPoint(x: x, y: y))
            case UInt8(ascii: "Z"):
                guard open else { return nil }
                polygons.append(current)
                current = []
                open = false
                i += 1
            case 0x20, 0x0A, 0x0D, 0x09:
                i += 1
            default:
                return nil
            }
        }
        if open { return nil }
        return polygons
    }

    /// The inverse of `parse` under the one-decimal rule: `M x,y L x,y ... Z`
    /// with `%.1f` numbers. Parsing a source string and serialising the
    /// result reproduces the source byte for byte.
    public static func serialize(_ polygons: [[CGPoint]]) -> String {
        var out = ""
        for polygon in polygons {
            for (index, point) in polygon.enumerated() {
                out += index == 0 ? "M" : "L"
                out += String(format: "%.1f,%.1f", Double(point.x), Double(point.y))
            }
            out += "Z"
        }
        return out
    }

    // MARK: Store

    /// Reads `list.json` and `geometry.json` once and parses an entry on
    /// first use.
    private final class Store {
        static let shared = Store()

        private let lock = NSLock()
        private var entries: [Int: [String: Any]] = [:]
        private var parsed: [Int: SettGeometry] = [:]
        private var tcs: [String] = []
        let count: Int

        init() {
            var rowsByEntry: [Int: [String: Any]] = [:]
            var tcStrings: [String] = []
            var total = 0
            if let listData = PatternResources.data("list.json"),
               let list = (try? JSONSerialization.jsonObject(with: listData)) as? [[String: Any]],
               let geometryData = PatternResources.data("geometry.json"),
               let geometry = (try? JSONSerialization.jsonObject(with: geometryData)) as? [String: Any],
               (geometry["patternVersion"] as? NSNumber)?.intValue == 1,
               let rows = geometry["entries"] as? [[String: Any]] {
                for row in rows {
                    if let n = (row["entry"] as? NSNumber)?.intValue { rowsByEntry[n] = row }
                }
                tcStrings = list.map { $0["tc"] as? String ?? "" }
                // Drawable only when every list entry has geometry.
                if (0..<list.count).allSatisfy({ rowsByEntry[$0] != nil }) { total = list.count }
            }
            entries = rowsByEntry
            tcs = tcStrings
            count = total
        }

        func tc(at entry: Int) -> String? { entry >= 0 && entry < tcs.count ? tcs[entry] : nil }

        func geometry(at entry: Int) -> SettGeometry? {
            lock.lock(); defer { lock.unlock() }
            if let hit = parsed[entry] { return hit }
            guard let row = entries[entry],
                  let inkStrings = row["ink"] as? [String], inkStrings.count == 3,
                  let cutString = row["cut"] as? String,
                  let cut = Self.parseOrNil(cutString)
            else { return nil }
            var inkPaths: [[[CGPoint]]] = []
            for s in inkStrings {
                guard let polys = Self.parseOrNil(s) else { return nil }
                inkPaths.append(polys)
            }
            let g = SettGeometry(inkPaths: inkPaths, cut: cut)
            parsed[entry] = g
            return g
        }

        private static func parseOrNil(_ s: String) -> [[CGPoint]]? { SettGeometry.parse(s) }
    }
}
