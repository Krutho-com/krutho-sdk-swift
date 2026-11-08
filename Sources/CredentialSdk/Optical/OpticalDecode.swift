import Foundation

/// One decoded frame: the whole 48-bit word split into header, value and CRC (`frame.ok` is the CRC check), plus
/// what the decoder saw. The collector takes `frame.header` and `frame.value`; nothing is stored on a CRC failure.
struct OpticalDecodeResult {
    let frame: OpticalFrame.Decoded
    let scale: Double
    let phase: Double
    let margin: Double
    /// Refined ring ellipse the canonical image was built from.
    let ellipse: OpticalEllipse
    let black: Double
    let white: Double

    var ok: Bool { frame.ok }
    var header: UInt8 { frame.header }
    var value: UInt32 { frame.value }
}

/// Refine the finder ring from `initial`, then decode. nil when refinement fails or contrast is too low.
func opticalDecode(_ luma: OpticalLuma, init initial: OpticalEllipse, canon: Int = 480) -> OpticalDecodeResult? {
    guard let el = opticalRefineEllipse(luma, initial) else { return nil }
    return opticalDecode(luma, refined: el, canon: canon)
}

func opticalDecode(_ luma: OpticalLuma, refined el: OpticalEllipse, canon: Int = 480) -> OpticalDecodeResult? {
    let rc = Double(canon) / 2
    let th = el.angleDeg * .pi / 180, ct = cos(th), st = sin(th)
    let isx = (el.w / 2) / rc, isy = (el.h / 2) / rc
    // Inverse of the reference affine: canonical (x, y) -> source c + Rot(ang) * diag(w/2, h/2) / rc * (x - rc, y - rc)
    var can = [Float](repeating: 0, count: canon * canon)
    luma.pixels.withUnsafeBufferPointer { px in
        can.withUnsafeMutableBufferPointer { cp in
            for y in 0..<canon {
                let v = (Double(y) - rc) * isy
                let bx = el.cx - st * v, by = el.cy + ct * v
                for x in 0..<canon {
                    let u = (Double(x) - rc) * isx
                    cp[y * canon + x] = OpticalLuma.bilinearZero(px, luma.width, luma.height, bx + ct * u, by + st * u)
                }
            }
        }
    }

    // Black/white levels: 10th and 90th percentile (numpy linear interpolation) over the data annulus.
    var band: [Float] = []
    band.reserveCapacity(canon * canon * 3 / 5)
    for y in 0..<canon {
        let dy = Double(y) - rc
        for x in 0..<canon {
            let dx = Double(x) - rc
            let rr = (dx * dx + dy * dy).squareRoot() / rc
            if rr > OpticalLayout.r0 && rr < OpticalLayout.r1 { band.append(can[y * canon + x]) }
        }
    }
    band.sort()
    func pct(_ q: Double) -> Double {
        let pos = q / 100 * Double(band.count - 1)
        let i = Int(pos), f = pos - Double(i)
        return i + 1 < band.count ? Double(band[i]) + f * (Double(band[i + 1]) - Double(band[i])) : Double(band[i])
    }
    let black = pct(10), white = pct(90)
    if white - black < 40 { return nil }
    let thr = Float((white + black) / 2), span = Float(white - black)
    for i in 0..<can.count { can[i] = (can[i] - thr) / span }

    return can.withUnsafeBufferPointer { soft -> OpticalDecodeResult in
        // 3x3 mean of the soft image at polar (r, deg); the reference implementation rounds half to even.
        @inline(__always) func sample(_ r: Double, _ deg: Double) -> Double {
            let a = deg * .pi / 180
            let xi = Int((rc + r * rc * cos(a)).rounded(.toNearestOrEven))
            let yi = Int((rc + r * rc * sin(a)).rounded(.toNearestOrEven))
            var s: Float = 0
            for yy in (yi - 1)...(yi + 1) {
                let row = yy * canon
                s += soft[row + xi - 1] + soft[row + xi] + soft[row + xi + 1]
            }
            return Double(s) / 9
        }

        let wedges = OpticalLayout.wedges, sub = OpticalLayout.subSectors
        // Whole degrees (60 and 10), so the sums below are the reference's `w * 60 + p + (j * 10 + 5)` exactly.
        let wedgeDegrees = 360 / wedges, subDegrees = wedgeDegrees / sub
        let rs = OpticalLayout.r0 + OpticalLayout.ringWidth * 0.5
        var best = -1e9, phi = 0.0
        for p10 in 0..<600 {
            let p = Double(p10) / 10
            var sc = 0.0
            for w in 0..<wedges {
                for j in 0..<sub {
                    sc += sample(rs, Double(w * wedgeDegrees) + p + Double(j * subDegrees + subDegrees / 2))
                        * Double(2 * OpticalLayout.sync[j] - 1)
                }
            }
            if sc > best { best = sc; phi = p }
        }

        func readBits(_ scale: Double) -> (OpticalFrame.Decoded, Double) {
            var word: UInt64 = 0, margin = Double.infinity
            for i in 1..<OpticalLayout.rings {
                let r = (OpticalLayout.r0 + (Double(i) + 0.5) * OpticalLayout.ringWidth) * scale
                for j in 0..<sub {
                    var sb = 0.0
                    for w in 0..<wedges {
                        sb += sample(r, Double(w * wedgeDegrees) + phi + Double(j * subDegrees + subDegrees / 2))
                    }
                    word = (word << 1) | (sb > 0 ? 1 : 0)
                    margin = min(margin, abs(sb))
                }
            }
            return (OpticalFrame.Decoded(word: word), margin)
        }

        // Try scales nearest 1.0 first; accept a checksum pass with real decision margin.
        var bestR: (OpticalFrame.Decoded, Double)? = nil, bestS = 1.0
        for sc in OpticalLayout.scales {
            let r = readBits(sc)
            if bestR == nil || (r.1 > bestR!.1 && !bestR!.0.ok) { bestR = r; bestS = sc }
            if r.0.ok && r.1 >= OpticalLayout.minMargin { bestR = r; bestS = sc; break }
        }
        let (frame, margin) = bestR!
        return OpticalDecodeResult(frame: frame, scale: bestS, phase: phi, margin: margin, ellipse: el, black: black, white: white)
    }
}
