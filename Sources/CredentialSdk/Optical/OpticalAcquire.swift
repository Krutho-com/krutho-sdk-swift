import Foundation

/// A round guide on screen: centre and radius in frame pixels. The ring need not be on it exactly.
struct OpticalGuide {
    var cx: Double, cy: Double, r: Double
}

/// Block-mean downscale so the ring search runs on a small image and ignores single-pixel noise.
func opticalDownscale(_ l: OpticalLuma, factor: Int) -> OpticalLuma {
    if factor <= 1 { return l }
    let w = l.width / factor, h = l.height / factor
    var out = [UInt8](repeating: 0, count: w * h)
    l.pixels.withUnsafeBufferPointer { p in
        for y in 0..<h {
            for x in 0..<w {
                var s = 0
                for dy in 0..<factor { let row = (y * factor + dy) * l.width + x * factor; for dx in 0..<factor { s += Int(p[row + dx]) } }
                out[y * w + x] = UInt8(s / (factor * factor))
            }
        }
    }
    return OpticalLuma(width: w, height: h, pixels: out)
}

/// Score a circle as the finder ring: bright band at 0.90 to 0.96 R, darker gap at 0.80 to 0.86, dark outside at
/// 1.10 to 1.20. Same test as the reference `_ring_score`, on a circle.
func opticalRingScore(_ l: OpticalLuma, _ cx: Double, _ cy: Double, _ r: Double) -> Double {
    let n = 40
    var ring = [Float](repeating: 0, count: n)
    var gapSum: Float = 0, outSum: Float = 0
    l.pixels.withUnsafeBufferPointer { p in
        for i in 0..<n {
            let a = 2 * Double.pi * Double(i) / Double(n)
            let ca = cos(a), sa = sin(a)
            var rs: Float = 0, gs: Float = 0, os: Float = 0
            for k in 0..<3 {
                let t = Double(k) / 2
                let rr = r * (0.90 + 0.06 * t), rg = r * (0.80 + 0.06 * t), ro = r * (1.10 + 0.10 * t)
                rs += OpticalLuma.bilinearClamped(p, l.width, l.height, cx + rr * ca, cy + rr * sa)
                gs += OpticalLuma.bilinearClamped(p, l.width, l.height, cx + rg * ca, cy + rg * sa)
                os += OpticalLuma.bilinearClamped(p, l.width, l.height, cx + ro * ca, cy + ro * sa)
            }
            ring[i] = rs / 3; gapSum += gs / 3; outSum += os / 3
        }
    }
    let mean = ring.reduce(0, +) / Float(n)
    let sd = sqrt(ring.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Float(n))
    let gap = gapSum / Float(n), out = outSum / Float(n)
    return Double((mean - out) - 0.5 * sd + 0.5 * (mean - gap))
}

/// Find the finder ring near a guide. Searches centres within +-0.6 guide radius and ring radii 0.5 to 1.8 x the
/// guide's, then hill-climbs. Returns a round ellipse (outer ring edge) for `opticalRefineEllipse` and
/// `opticalDecode`, or nil when nothing ring-like is there.
func opticalAcquireRing(_ luma: OpticalLuma, guide: OpticalGuide, minScore: Double = 40) -> OpticalEllipse? {
    let factor = max(1, luma.width / 360)
    let small = opticalDownscale(luma, factor: factor)
    let f = Double(factor)
    let gx = guide.cx / f, gy = guide.cy / f, gr = guide.r / f
    var best = (score: -Double.infinity, x: gx, y: gy, r: gr)
    var dy = -0.6
    while dy <= 0.601 {
        var dx = -0.6
        while dx <= 0.601 {
            var s = 0.5
            while s <= 1.801 {
                let r = gr * s
                let sc = opticalRingScore(small, gx + dx * gr, gy + dy * gr, r)
                if sc > best.score { best = (sc, gx + dx * gr, gy + dy * gr, r) }
                s *= 1.08
            }
            dx += 0.1
        }
        dy += 0.1
    }
    var step = 0.05 * best.r
    var rstep = 0.04 * best.r
    for _ in 0..<5 {
        var improved = true
        while improved {
            improved = false
            for (ox, oy, orr) in [(step, 0.0, 0.0), (-step, 0, 0), (0, step, 0), (0, -step, 0), (0, 0, rstep), (0, 0, -rstep)] {
                let sc = opticalRingScore(small, best.x + ox, best.y + oy, best.r + orr)
                if sc > best.score { best = (sc, best.x + ox, best.y + oy, best.r + orr); improved = true }
            }
        }
        step /= 2; rstep /= 2
    }
    if best.score < minScore { return nil }
    return OpticalEllipse(cx: best.x * f, cy: best.y * f, w: 2 * best.r * f, h: 2 * best.r * f, angleDeg: 0)
}
