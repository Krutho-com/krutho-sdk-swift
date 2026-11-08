import Foundation

/// The optical pattern's layout (unchanged from the reference implementation).
/// Canonical radius 1.0, angle 0 = +x, increasing clockwise on screen. Outer finder ring 0.90..1.00 white; centre
/// disc < 0.18 white with a black dot < 0.06; data region 0.22..0.86 in 9 rings of 6 sub-sectors (10 degrees) per
/// wedge, 6 wedges; ring 0 is the sync word; rings 1..8 carry the 48 frame bits, identical in all six wedges.
enum OpticalLayout {
    static let wedges = 6
    static let subSectors = 6
    static let rings = 9
    static let r0 = 0.22
    static let r1 = 0.86
    static let ringWidth = (r1 - r0) / Double(rings)
    static let sync = [1, 1, 0, 1, 0, 0]
    static let finderInner = 0.90
    static let centreDisc = 0.18
    static let centreDot = 0.06
    /// Decoder: ring-scale candidates nearest 1.0 first, and the decision margin a CRC pass must reach.
    static let scales = [1.0, 0.99, 1.01, 0.98, 1.02, 0.97, 1.03, 0.96, 1.04, 0.95, 1.05, 0.94, 1.06, 0.93, 1.07, 0.92, 1.08]
    static let minMargin = 0.6
    /// Renderer: cells are inset 1 degree each side and 8% of the ring width each edge.
    static let angularInsetDegrees = 1.0
    static let radialInset = 0.08
    /// The view: the finder ring's outer edge as a share of the square's side (0.98 of the half-side in the reference image;
    /// 0.80 of the half-side here so the view carries its own dark margin of 0.25 R).
    static let ringShareOfSide = 0.40
    static let frameRate = 10.0
}
