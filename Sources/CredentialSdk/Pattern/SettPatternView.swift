#if canImport(SwiftUI)
import SwiftUI

/// Draws a device pattern natively in two caller-supplied colours: the ink
/// and the ground. The drawing is the frozen v1 geometry (see
/// `SettGeometry`), so it matches the server's SVG vertex for vertex.
///
/// The view is a square: it draws in the largest centred square of the space
/// it is given. An unknown version or an entry outside `[0, N)` draws
/// nothing; a caller shows the fallback words (`PatternUnavailableView`).
/// Ground must be an opaque colour: the breaks in the cloth are painted in it.
@available(iOS 15, macOS 13, *)
public struct SettPatternView: View {
    private let geometry: SettGeometry?
    private let ink: Color
    private let ground: Color
    private let label: String

    public init(pattern: DevicePattern, ink: Color, ground: Color) {
        self.geometry = SettGeometry.entry(pattern)
        self.ink = ink
        self.ground = ground
        self.label = "Device pattern \(pattern.patternVersion)/\(pattern.patternEntry)"
    }

    public var body: some View {
        Canvas { context, size in
            guard let geometry else { return }
            let side = min(size.width, size.height)
            guard side > 0 else { return }
            var context = context
            let square = CGRect(x: (size.width - side) / 2, y: (size.height - side) / 2, width: side, height: side)
            context.clip(to: Path(square))
            context.translateBy(x: square.minX, y: square.minY)
            let k = side / SettGeometry.viewBox
            context.scaleBy(x: k, y: k)
            let (inkPaths, cutPath) = geometry.cgPaths()
            context.fill(Path(CGRect(x: 0, y: 0, width: SettGeometry.viewBox, height: SettGeometry.viewBox)),
                         with: .color(ground))
            for path in inkPaths {
                context.fill(Path(path), with: .color(ink), style: FillStyle(eoFill: false))
            }
            context.fill(Path(cutPath), with: .color(ground), style: FillStyle(eoFill: false))
        }
        .aspectRatio(1, contentMode: .fit)
        .accessibilityElement()
        .accessibilityLabel(label)
    }
}
#endif
