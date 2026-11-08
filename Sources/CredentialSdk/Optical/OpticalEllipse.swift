import Foundation

/// OpenCV fitEllipse convention: (cx, cy) centre, w and h full axis lengths, w along `angleDeg`
/// (degrees from +x, clockwise on screen), h perpendicular. Port of the reference `Ellipse`.
struct OpticalEllipse: Equatable {
    var cx: Double
    var cy: Double
    var w: Double
    var h: Double
    var angleDeg: Double

    /// Point at parameter angle `phi` on the ellipse scaled by `r` (r = 1 is the ellipse itself).
    @inline(__always)
    func point(_ phi: Double, r: Double, ct: Double, st: Double) -> (Double, Double) {
        let ex = w / 2 * r * cos(phi), ey = h / 2 * r * sin(phi)
        return (cx + ct * ex - st * ey, cy + st * ex + ct * ey)
    }
}

/// Direct least-squares conic fit with the trace constraint A + C = 1 (rotation invariant, linear),
/// solved on centred and scaled coordinates. Returns nil unless the conic is a real ellipse.
func opticalFitEllipse(xs: [Double], ys: [Double]) -> OpticalEllipse? {
    let n = xs.count
    guard n >= 5, ys.count == n else { return nil }
    let mx = xs.reduce(0, +) / Double(n), my = ys.reduce(0, +) / Double(n)
    var s = 0.0
    for i in 0..<n { s += ((xs[i] - mx) * (xs[i] - mx) + (ys[i] - my) * (ys[i] - my)).squareRoot() }
    s /= Double(n)
    guard s > 0 else { return nil }

    // Unknowns p = [A, B, D, E, F] with C = 1 - A:  A(u^2 - v^2) + B uv + D u + E v + F = -v^2
    var N = [[Double]](repeating: [Double](repeating: 0, count: 5), count: 5)
    var rhs = [Double](repeating: 0, count: 5)
    for i in 0..<n {
        let u = (xs[i] - mx) / s, v = (ys[i] - my) / s
        let row = [u * u - v * v, u * v, u, v, 1.0], b = -v * v
        for r in 0..<5 {
            rhs[r] += row[r] * b
            for c in 0..<5 { N[r][c] += row[r] * row[c] }
        }
    }
    guard let p = opticalSolve(N, rhs) else { return nil }
    let A = p[0], B = p[1], C = 1 - A, D = p[2], E = p[3], F = p[4]
    let det = B * B - 4 * A * C
    guard det < 0 else { return nil }
    let ux = (2 * C * D - B * E) / det, uy = (2 * A * E - B * D) / det
    let Fc = F + (D * ux + E * uy) / 2
    // Eigen-decompose [[A, B/2], [B/2, C]]: semi-axis along eigenvector of lambda is sqrt(-Fc / lambda).
    let half = (A + C) / 2, dd = (((A - C) / 2) * ((A - C) / 2) + (B / 2) * (B / 2)).squareRoot()
    let l1 = half + dd, l2 = half - dd
    guard l1 > 0, l2 > 0, Fc < 0 else { return nil }
    let (vx, vy): (Double, Double) = abs(B) > 1e-12 ? (B / 2, l1 - A) : (A >= C ? (1, 0) : (0, 1))
    var ang = atan2(vy, vx) * 180 / .pi
    ang = ang.truncatingRemainder(dividingBy: 180)
    if ang < 0 { ang += 180 }
    let a1 = (-Fc / l1).squareRoot(), a2 = (-Fc / l2).squareRoot()
    return OpticalEllipse(cx: mx + s * ux, cy: my + s * uy, w: 2 * a1 * s, h: 2 * a2 * s, angleDeg: ang)
}

/// Gaussian elimination with partial pivoting.
func opticalSolve(_ A: [[Double]], _ b: [Double]) -> [Double]? {
    let n = b.count
    var M = A, x = b
    for k in 0..<n {
        var piv = k
        for r in (k + 1)..<n where abs(M[r][k]) > abs(M[piv][k]) { piv = r }
        if abs(M[piv][k]) < 1e-14 { return nil }
        if piv != k { M.swapAt(piv, k); x.swapAt(piv, k) }
        for r in (k + 1)..<n {
            let f = M[r][k] / M[k][k]
            if f == 0 { continue }
            for c in k..<n { M[r][c] -= f * M[k][c] }
            x[r] -= f * x[k]
        }
    }
    for k in stride(from: n - 1, through: 0, by: -1) {
        var sum = x[k]
        for c in (k + 1)..<n { sum -= M[k][c] * x[c] }
        x[k] = sum / M[k][k]
    }
    return x
}
