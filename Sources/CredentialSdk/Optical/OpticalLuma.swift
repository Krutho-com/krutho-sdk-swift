import Foundation

/// 8-bit grayscale frame, row-major, no padding. Port of the reference `Luma` (the decoder); the
/// camera reader copies the luma plane of each video frame into one of these.
struct OpticalLuma {
    let width: Int
    let height: Int
    var pixels: [UInt8]

    init(width: Int, height: Int, pixels: [UInt8]) {
        precondition(pixels.count == width * height)
        self.width = width
        self.height = height
        self.pixels = pixels
    }

    /// Bilinear sample with edge replication (cv2.remap BORDER_REPLICATE).
    @inline(__always)
    func sampleClamped(_ x: Double, _ y: Double) -> Float {
        pixels.withUnsafeBufferPointer { p in OpticalLuma.bilinearClamped(p, width, height, x, y) }
    }

    @inline(__always)
    static func bilinearClamped(_ p: UnsafeBufferPointer<UInt8>, _ w: Int, _ h: Int, _ x: Double, _ y: Double) -> Float {
        let xc = min(max(x, 0), Double(w - 1)), yc = min(max(y, 0), Double(h - 1))
        let x0 = Int(xc), y0 = Int(yc)
        let x1 = min(x0 + 1, w - 1), y1 = min(y0 + 1, h - 1)
        let fx = Float(xc - Double(x0)), fy = Float(yc - Double(y0))
        let r0 = p[y0 * w + x0], r1 = p[y0 * w + x1], r2 = p[y1 * w + x0], r3 = p[y1 * w + x1]
        let top = Float(r0) + (Float(r1) - Float(r0)) * fx
        let bot = Float(r2) + (Float(r3) - Float(r2)) * fx
        return top + (bot - top) * fy
    }

    /// Bilinear sample with zero outside the frame (cv2.warpAffine BORDER_CONSTANT 0).
    @inline(__always)
    static func bilinearZero(_ p: UnsafeBufferPointer<UInt8>, _ w: Int, _ h: Int, _ x: Double, _ y: Double) -> Float {
        let xf = floor(x), yf = floor(y)
        let x0 = Int(xf), y0 = Int(yf)
        let fx = Float(x - xf), fy = Float(y - yf)
        if x0 >= 0 && y0 >= 0 && x0 + 1 < w && y0 + 1 < h {
            let i = y0 * w + x0
            let r0 = Float(p[i]), r1 = Float(p[i + 1]), r2 = Float(p[i + w]), r3 = Float(p[i + w + 1])
            let top = r0 + (r1 - r0) * fx, bot = r2 + (r3 - r2) * fx
            return top + (bot - top) * fy
        }
        if x0 < -1 || y0 < -1 || x0 >= w || y0 >= h { return 0 }
        @inline(__always) func tap(_ xi: Int, _ yi: Int) -> Float {
            (xi >= 0 && yi >= 0 && xi < w && yi < h) ? Float(p[yi * w + xi]) : 0
        }
        let top = tap(x0, y0) * (1 - fx) + tap(x0 + 1, y0) * fx
        let bot = tap(x0, y0 + 1) * (1 - fx) + tap(x0 + 1, y0 + 1) * fx
        return top * (1 - fy) + bot * fy
    }
}

extension OpticalLuma {
    /// The same frame with brightness flipped, so a dark-on-light pattern reads as the normal light-on-dark one.
    func inverted() -> OpticalLuma {
        OpticalLuma(width: width, height: height, pixels: pixels.map { 255 &- $0 })
    }
}
