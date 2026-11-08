import Foundation

/// Radii probed along each ray, as numpy linspace(0.70, 1.40, 281) cast to float32.
let opticalRefineRadii: [Float] = (0..<281).map { Float(0.70 + Double($0) * (0.70 / 280.0)) }

/// First index whose radius is >= v (numpy searchsorted on the float32 radii with a float64 key).
func opticalRadiusIndex(_ v: Double) -> Int {
    opticalRefineRadii.firstIndex { Double($0) >= v } ?? opticalRefineRadii.count
}

/// 21-tap Gaussian, sigma 2.5: what cv2.GaussianBlur picks for ksize 0 on a float image.
let opticalRefineKernel: [Float] = {
    let sigma = 2.5, radius = 10
    var k = (-radius...radius).map { exp(-Double($0 * $0) / (2 * sigma * sigma)) }
    let sum = k.reduce(0, +)
    k = k.map { $0 / sum }
    return k.map { Float($0) }
}()

/// Re-find the outer ring edge by half-brightness along rays, so glare or a halo cannot inflate the circle.
/// Returns the input ellipse when fewer than 60% of rays have a usable edge (as the reference implementation does),
/// nil when the edge points do not fit an ellipse.
func opticalRefineEllipse(_ luma: OpticalLuma, _ el: OpticalEllipse, nAng: Int = 120) -> OpticalEllipse? {
    let (xs, ys) = opticalRingEdgePoints(luma, el, nAng: nAng)
    if Double(xs.count) < Double(nAng) * 0.6 { return el }
    return opticalFitEllipse(xs: xs, ys: ys)
}

/// Outer-edge point per ray where one was found.
func opticalRingEdgePoints(_ luma: OpticalLuma, _ el: OpticalEllipse, nAng: Int) -> (xs: [Double], ys: [Double]) {
    let th = el.angleDeg * .pi / 180, ct = cos(th), st = sin(th)
    let rs = opticalRefineRadii, nR = rs.count, kernel = opticalRefineKernel, kr = kernel.count / 2
    let lo = opticalRadiusIndex(0.80), hi = opticalRadiusIndex(1.06)
    let o0 = opticalRadiusIndex(1.15), o1 = opticalRadiusIndex(1.35)
    var prof = [Float](repeating: 0, count: nR), sm = prof, outer = [Float](repeating: 0, count: o1 - o0)
    var xs: [Double] = [], ys: [Double] = []
    xs.reserveCapacity(nAng); ys.reserveCapacity(nAng)

    luma.pixels.withUnsafeBufferPointer { px in
        for i in 0..<nAng {
            let phi = 2 * Double.pi * Double(i) / Double(nAng)
            for k in 0..<nR {
                let (x, y) = el.point(phi, r: Double(rs[k]), ct: ct, st: st)
                prof[k] = OpticalLuma.bilinearClamped(px, luma.width, luma.height, x, y)
            }
            // 1-D Gaussian along the ray, BORDER_REFLECT_101
            for k in 0..<nR {
                var acc: Float = 0
                for t in -kr...kr {
                    var idx = k + t
                    if idx < 0 { idx = -idx }
                    if idx >= nR { idx = 2 * (nR - 1) - idx }
                    acc += kernel[t + kr] * prof[idx]
                }
                sm[k] = acc
            }
            var k = lo
            for j in lo..<hi where sm[j] > sm[k] { k = j }
            let peak = sm[k]
            for j in o0..<o1 { outer[j - o0] = sm[j] }
            outer.sort()
            let m = outer.count
            let out = m % 2 == 1 ? outer[m / 2] : (outer[m / 2 - 1] + outer[m / 2]) / 2
            if peak - out < 30 { continue }
            let lvl = (peak + out) / 2
            var j = k
            while j < nR - 1 && sm[j] > lvl { j += 1 }
            if j == k || j >= nR - 1 { continue }
            let f = (sm[j - 1] - lvl) / max(sm[j - 1] - sm[j], 1e-6)
            let rE = Double(rs[j - 1] + f * (rs[j] - rs[j - 1]))
            let (x, y) = el.point(phi, r: rE, ct: ct, st: st)
            xs.append(x); ys.append(y)
        }
    }
    return (xs, ys)
}
