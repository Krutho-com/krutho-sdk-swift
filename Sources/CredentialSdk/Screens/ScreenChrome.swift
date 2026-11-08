#if canImport(SwiftUI)
import SwiftUI

/// The pairing screens' palette (design system: achromatic plus one signal). Black end to end; the sett sits on a dark tile.
@available(iOS 15, macOS 13, *) let krSignal = Color(red: 0xCE / 255, green: 0x33 / 255, blue: 0x1B / 255)   // #CE331B, the signal orange
@available(iOS 15, macOS 13, *) let krBlack  = Color.black
/// The Mac window's near-black ground, soft white words and muted secondary words (the premium layout).
@available(iOS 15, macOS 13, *) let krMacGround = Color(red: 0x08 / 255, green: 0x08 / 255, blue: 0x08 / 255)
@available(iOS 15, macOS 13, *) let krSoftWhite = Color(red: 0xF5 / 255, green: 0xF5 / 255, blue: 0xF7 / 255)
@available(iOS 15, macOS 13, *) let krMuted     = Color(red: 0x8E / 255, green: 0x8E / 255, blue: 0x93 / 255)
@available(iOS 15, macOS 13, *) let krTile   = Color(red: 0x18 / 255, green: 0x18 / 255, blue: 0x18 / 255)
@available(iOS 15, macOS 13, *) let krPaper  = Color(red: 0xFA / 255, green: 0xFA / 255, blue: 0xFA / 255)

/// "1 Scan with your iPhone · 2 Approve on your iPhone · 3 Finish with Touch ID" (Mac) or "Scan · Approve · Check" (phone).
/// `now` is 1-based; `labels.count + 1` means all done. Done steps dim; the current step is underlined in the signal orange.
@available(iOS 15, macOS 13, *)
struct StepStrip: View {
    let labels: [String]
    let now: Int
    var compact = false

    var body: some View {
        HStack(spacing: compact ? 18 : 28) {
            ForEach(Array(labels.enumerated()), id: \.offset) { i, label in
                let step = i + 1
                VStack(spacing: 4) {
                    Text(label)
                        .font(.system(size: compact ? 10.5 : 11.5, design: .monospaced))
                        .tracking(compact ? 0.8 : 0.7)
                        .foregroundColor(step == now ? .white : Color.white.opacity(step < now ? 0.35 : 0.5))
                    Rectangle().fill(step == now ? krSignal : Color.clear).frame(height: 2)
                }
                .fixedSize()
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(now > labels.count ? "All steps done"
                            : now < 1 ? "\(labels.count) steps"
                            : "Step \(now) of \(labels.count): \(labels[now - 1])")
    }
}

/// Black ground, white words, dark scheme, an optional step strip at the top (Mac) or bottom (phone).
@available(iOS 15, macOS 13, *)
struct DarkScreen<Content: View>: View {
    let title: String?
    let strip: StepStrip?
    var stripAtBottom = false
    var maxWidth: CGFloat? = nil
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(spacing: 0) {
            // Its own row above everything: top left on the Mac, top centre on the phone.
            KruthoLogo()
                .frame(maxWidth: .infinity, alignment: stripAtBottom ? .center : .leading)
                .padding(.horizontal, 24)
                .padding(.top, 20)
            VStack(spacing: 16) {
                if let strip, !stripAtBottom { strip.padding(.bottom, 4) }
                if let title {
                    Text(title).font(.system(.title2).weight(.medium)).multilineTextAlignment(.center)
                }
                content()
                if let strip, stripAtBottom { strip.padding(.top, 4) }
            }
            .padding(24)
            .frame(maxWidth: maxWidth)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .foregroundColor(.white)
        .background(krBlack.ignoresSafeArea())
        .environment(\.colorScheme, .dark)
    }
}

/// A text-only action at 70% white: "Cancel" in a status row, "Continue without checking".
@available(iOS 15, macOS 13, *)
struct QuietButton: View {
    let title: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(.body)).foregroundColor(Color.white.opacity(0.7)).padding(.vertical, 8)
        }
        .buttonStyle(.plain)
    }
}

/// Status, facts and steps: monospaced, 12.5 pt, 70% white.
@available(iOS 15, macOS 13, *)
struct MonoLine: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.system(size: 12.5, design: .monospaced)).tracking(0.4).foregroundColor(Color.white.opacity(0.7))
            .multilineTextAlignment(.center)
    }
}
#endif
