#if canImport(SwiftUI)
import SwiftUI

/// Shown where a pattern cannot be drawn because this build does not know its
/// version: "Pattern unavailable" and the way out.
@available(iOS 15, macOS 13, *)
public struct PatternUnavailableView: View {
    public init() {}

    public var body: some View {
        VStack(spacing: 6) {
            Text(ScreenWords.unavailableTitle)
                .font(.system(.headline).weight(.medium))
            Text(ScreenWords.unavailableBody)
                .font(.system(.subheadline))
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The slot every screen draws its pattern in: the sett when this build can
/// draw it, "Pattern unavailable" alone when the server sent no pattern, and
/// the full fallback (with "Update the app ...") for an unknown version or
/// entry. The screen's buttons stay in every case.
///
/// `tile: true` is the dark pairing design: the sett on a rounded tile of
/// `ground` (the screens pass krTile by default) with a faint edge, and the
/// fallback words in a dashed box of the same width.
@available(iOS 15, macOS 13, *)
struct PatternSlot: View {
    let pattern: DevicePattern?
    let ink: Color
    let ground: Color
    var side: CGFloat = 220
    var tile: Bool = false

    var body: some View {
        Group {
            if let pattern, CredentialSdk.patternKnown(pattern) {
                if tile {
                    SettPatternView(pattern: pattern, ink: ink, ground: ground)
                        .frame(width: side, height: side)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.white.opacity(0.12), lineWidth: 1))
                } else {
                    SettPatternView(pattern: pattern, ink: ink, ground: ground)
                        .frame(width: side, height: side)
                }
            } else if tile {
                fallback
                    .padding(18)
                    .frame(width: side)
                    .frame(minHeight: min(150, side))
                    .overlay(RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.white.opacity(0.25), style: StrokeStyle(lineWidth: 1, dash: [4, 3])))
            } else {
                fallback.frame(minHeight: side / 2)
            }
        }
    }

    @ViewBuilder private var fallback: some View {
        if pattern != nil {
            PatternUnavailableView()
        } else {
            Text(ScreenWords.unavailableTitle)
                .font(.system(.headline).weight(.medium))
        }
    }
}


/// The first action on the phone screens: full width, 50 pt, the signal orange, an optional system glyph before
/// the words (Face ID on "Approve with Face ID").
@available(iOS 15, macOS 13, *)
struct PrimaryButton: View {
    let title: String
    var systemImage: String? = nil
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                if let systemImage { Image(systemName: systemImage).font(.system(size: 19, weight: .regular)) }
                Text(title).font(.system(size: 17, weight: .medium))
            }
            .frame(maxWidth: .infinity, minHeight: 50)
            .foregroundColor(.white)
            .background(RoundedRectangle(cornerRadius: 10).fill(krSignal))
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(PressScale())
    }
}

/// The second action on the phone screens: full width, 50 pt, a faint fill and a hairline edge.
@available(iOS 15, macOS 13, *)
struct SecondaryButton: View {
    let title: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 17, weight: .medium))
                .frame(maxWidth: .infinity, minHeight: 50)
                .foregroundColor(krSoftWhite)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.white.opacity(0.05)))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.white.opacity(0.28), lineWidth: 1))
                .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(PressScale())
    }
}

/// A press scales the button to 97%.
@available(iOS 15, macOS 13, *)
struct PressScale: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

@available(iOS 15, macOS 13, *)
struct ScreenLayout<Content: View, Buttons: View>: View {
    let title: String
    @ViewBuilder var content: () -> Content
    @ViewBuilder var buttons: () -> Buttons

    var body: some View {
        VStack(spacing: 16) {
            Text(title)
                .font(.system(.title2).weight(.medium))
                .multilineTextAlignment(.center)
            content()
            VStack(spacing: 8) { buttons() }
        }
        .padding(24)
        .frame(maxWidth: 420)
    }
}

/// The platform's opaque background. The pairing screens no longer use it (they are black with the sett on
/// krTile); kept for `SettPatternView` callers that lay a sett on their own light ground.
@available(iOS 15, macOS 13, *)
let krDefaultGround: Color = {
    #if canImport(UIKit)
    return Color(UIColor.systemBackground)
    #elseif canImport(AppKit)
    return Color(NSColor.windowBackgroundColor)
    #else
    return Color.white
    #endif
}()
#endif
