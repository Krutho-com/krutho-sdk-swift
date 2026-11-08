import Foundation
#if canImport(SwiftUI) && canImport(CoreImage)
import SwiftUI
import CoreImage
import CoreImage.CIFilterBuiltins

/// The backup QR: black modules on a white tile, a quiet zone of at least four modules, error correction M. Each
/// module is a whole number of points, drawn as an unantialiased square (nearest-neighbour scaling of CoreImage's
/// one-pixel-per-module output), so the edges stay crisp at any window size; the spare points go to the quiet zone.
/// Fills the square it is given (the waiting screen gives it the pattern's side).
///
/// The modules are drawn as rects rather than as a scaled `Image`: a render through `NSHostingView` blurred an
/// `Image` even with `.interpolation(.none)` and `.antialiased(false)`.
@available(iOS 15, macOS 13, *)
struct PairingQRCode: View {
    let text: String
    private let grid: QRModuleGrid?

    init(text: String) {
        self.text = text
        grid = QRModuleGrid(text: text)
    }

    var body: some View {
        GeometryReader { geo in
            let side = min(geo.size.width, geo.size.height)
            ZStack {
                RoundedRectangle(cornerRadius: 12).fill(Color.white)
                if let grid {
                    let count = CGFloat(grid.count)
                    // Four modules of quiet zone each side, on top of CoreImage's own margin.
                    let module = max(1, floor(side / (count + 8)))
                    grid.path(module: module)
                        .fill(Color.black, style: FillStyle(antialiased: false))
                        .frame(width: module * count, height: module * count)
                }
            }
            .frame(width: side, height: side)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("QR code")
    }
}

/// CIQRCodeGenerator's modules (correction level M) as a square grid, row 0 at the top. nil when the text does not
/// fit a QR.
struct QRModuleGrid {
    let count: Int
    /// Row-major, `count * count`; true is a dark module.
    let dark: [Bool]

    init?(text: String) {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let image = filter.outputImage,
              let cg = CIContext(options: [.useSoftwareRenderer: true]).createCGImage(image, from: image.extent),
              cg.width == cg.height, cg.width > 0 else { return nil }
        let n = cg.width
        var luma = [UInt8](repeating: 255, count: n * n)
        let drawn: Bool = luma.withUnsafeMutableBytes { buffer in
            guard let ctx = CGContext(data: buffer.baseAddress, width: n, height: n, bitsPerComponent: 8, bytesPerRow: n,
                                      space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue) else { return false }
            ctx.interpolationQuality = .none
            ctx.draw(cg, in: CGRect(x: 0, y: 0, width: n, height: n))
            return true
        }
        guard drawn else { return nil }
        count = n
        dark = luma.map { $0 < 128 }   // a bitmap context's memory is top row first
    }

    func isDark(row: Int, column: Int) -> Bool { dark[row * count + column] }

    /// One square per dark module, `module` points on a side, origin top left.
    func path(module: CGFloat) -> Path {
        var path = Path()
        for row in 0..<count {
            for column in 0..<count where isDark(row: row, column: column) {
                path.addRect(CGRect(x: CGFloat(column) * module, y: CGFloat(row) * module, width: module, height: module))
            }
        }
        return path
    }
}
#endif
