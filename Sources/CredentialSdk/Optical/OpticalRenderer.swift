import Foundation
#if canImport(CoreGraphics)
import CoreGraphics

/// Draws one frame of the optical pairing pattern (layout in `OpticalLayout`).
///
/// The drawing is a plain `CGContext` routine so a test can rasterise a frame without SwiftUI. It assumes y grows
/// downward, so increasing angle runs clockwise on screen: a SwiftUI `Canvas` already is, a bare bitmap context
/// must be flipped first (`translateBy(x: 0, y: side)`, `scaleBy(x: 1, y: -1)`, as `rasterise` does).
enum OpticalRenderer {
    /// Fills the square `[0, side] x [0, side]` black, then draws the frame word in white. The finder ring's outer
    /// edge sits at `radiusShare * side` from the centre (0.40 in the view; the reference image used 0.49).
    ///
    /// `inverted` draws black marks on a white ground instead (every gray flipped; the margin stays as drawn, now
    /// light). `ground`, when given, replaces the ground colour everywhere the normal drawing is "dark" (the
    /// square, the gap inside the finder ring, the centre dot); the marks keep their gray.
    static func draw(word: UInt64, into ctx: CGContext, side: CGFloat,
                     radiusShare: Double = OpticalLayout.ringShareOfSide,
                     inverted: Bool = false, ground: CGColor? = nil) {
        let S = Double(side)
        let c = S / 2, R = S * radiusShare
        ctx.saveGState()
        defer { ctx.restoreGState() }
        ctx.setAllowsAntialiasing(true)
        ctx.setShouldAntialias(true)
        let ink: CGFloat = inverted ? 0 : 1
        func setGround() {
            if let ground { ctx.setFillColor(ground) } else { ctx.setFillColor(gray: 1 - ink, alpha: 1) }
        }
        setGround()
        ctx.fill(CGRect(x: 0, y: 0, width: S, height: S))
        guard side > 0 else { return }

        func disc(_ r: Double, _ isInk: Bool) {
            if isInk { ctx.setFillColor(gray: ink, alpha: 1) } else { setGround() }
            ctx.fillEllipse(in: CGRect(x: c - r * R, y: c - r * R, width: 2 * r * R, height: 2 * r * R))
        }
        disc(1.0, true)
        disc(OpticalLayout.finderInner, false)
        disc(OpticalLayout.centreDisc, true)
        disc(OpticalLayout.centreDot, false)

        ctx.setFillColor(gray: ink, alpha: 1)
        let rw = OpticalLayout.ringWidth
        let wedgeDegrees = 360.0 / Double(OpticalLayout.wedges)
        let subDegrees = wedgeDegrees / Double(OpticalLayout.subSectors)
        for w in 0..<OpticalLayout.wedges {
            for i in 0..<OpticalLayout.rings {
                for j in 0..<OpticalLayout.subSectors {
                    let bit = i == 0 ? OpticalLayout.sync[j]
                                     : OpticalFrame.bit(word, (i - 1) * OpticalLayout.subSectors + j)
                    if bit == 0 { continue }
                    let a0 = Double(w) * wedgeDegrees + Double(j) * subDegrees + OpticalLayout.angularInsetDegrees
                    let a1 = Double(w) * wedgeDegrees + Double(j + 1) * subDegrees - OpticalLayout.angularInsetDegrees
                    let ra = OpticalLayout.r0 + Double(i) * rw + rw * OpticalLayout.radialInset
                    let rb = OpticalLayout.r0 + Double(i + 1) * rw - rw * OpticalLayout.radialInset
                    let n = max(2, Int((a1 - a0) / 1.5))
                    let path = CGMutablePath()
                    // Outer arc forward, inner arc back.
                    for k in 0...n {
                        let a = (a0 + (a1 - a0) * Double(k) / Double(n)) * .pi / 180
                        let p = CGPoint(x: c + rb * R * cos(a), y: c + rb * R * sin(a))
                        if k == 0 { path.move(to: p) } else { path.addLine(to: p) }
                    }
                    for k in stride(from: n, through: 0, by: -1) {
                        let a = (a0 + (a1 - a0) * Double(k) / Double(n)) * .pi / 180
                        path.addLine(to: CGPoint(x: c + ra * R * cos(a), y: c + ra * R * sin(a)))
                    }
                    path.closeSubpath()
                    ctx.addPath(path)
                    ctx.fillPath()
                }
            }
        }
    }

    /// One frame as 8-bit gray pixels, row 0 at the top, `side * side` bytes. For tests and tools.
    static func rasterise(word: UInt64, side: Int, radiusShare: Double = OpticalLayout.ringShareOfSide,
                          inverted: Bool = false) -> [UInt8]? {
        guard side > 0,
              let ctx = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: side,
                                  space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)
        else { return nil }
        // y down, so increasing angle runs clockwise on screen.
        ctx.translateBy(x: 0, y: CGFloat(side))
        ctx.scaleBy(x: 1, y: -1)
        draw(word: word, into: ctx, side: CGFloat(side), radiusShare: radiusShare, inverted: inverted)
        guard let data = ctx.data else { return nil }
        // After the flip user y = 0 is the top row, so memory row y is user row y.
        let buf = data.bindMemory(to: UInt8.self, capacity: side * side)
        return Array(UnsafeBufferPointer(start: buf, count: side * side))
    }
}
#endif
