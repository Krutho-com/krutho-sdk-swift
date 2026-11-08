#if canImport(SwiftUI)
import SwiftUI
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// The Krutho logo (mark and KRUTHO wordmark in the signal orange #CE331B, transparent ground: the supplied PNG's black was keyed out), shown small at
/// the top of the pairing screens. Embedded as a 216 x 42 PNG so the SDK needs no resource bundle for it
/// (replace with a vector when there is one).
@available(iOS 15, macOS 13, *)
struct KruthoLogo: View {
    var height: CGFloat = 16

    var body: some View {
        if let image = Self.image {
            image.resizable().interpolation(.high).aspectRatio(contentMode: .fit).frame(height: height)
                .accessibilityLabel("Krutho")
        }
    }

    static let image: Image? = {
        guard let data = Data(base64Encoded: png) else { return nil }
        #if canImport(UIKit)
        return UIImage(data: data).map { Image(uiImage: $0) }
        #elseif canImport(AppKit)
        return NSImage(data: data).map { Image(nsImage: $0) }
        #else
        return nil
        #endif
    }()

    private static let png = "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"
}
#endif
