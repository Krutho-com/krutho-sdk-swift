import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// The haptics the pairing screens ask for. `.lock` is an impact (medium); `.piece` a light impact;
/// `.read`, `.stopped` and `.removalRequested` are a success notification; `.reset` a warning;
/// `.removalFailed` an error. Nothing plays on the Mac, and the SDK plays no sounds.
public enum PairingHaptic: Equatable {
    case lock              // the pattern fits the circle and reading starts
    case piece             // one more of the eight pieces is in (not the eighth: that is .read)
    case read              // the eighth piece is in
    case reset             // a collection was discarded while reading
    case stopped           // "Pairing stopped" appeared
    case removalRequested  // RevokeScreen landed on .requested
    case removalFailed     // RevokeScreen landed on .failed
}

/// Where the screens send their haptics. Pass `NoPairingHaptics()` for none, or your own to route them.
public protocol PairingHaptics {
    func play(_ haptic: PairingHaptic)
}

/// Plays nothing: the default on macOS and in tests.
public struct NoPairingHaptics: PairingHaptics {
    public init() {}
    public func play(_ haptic: PairingHaptic) {}
}

#if canImport(UIKit)
/// The system's feedback generators: `UIImpactFeedbackGenerator(style: .medium)` for `.lock`, `(style: .light)` for `.piece`,
/// `UINotificationFeedbackGenerator` for the rest. The generators are made and prepared once, and always used on
/// the main thread (a call from elsewhere hops there).
public struct SystemPairingHaptics: PairingHaptics {
    public init() {}

    public func play(_ haptic: PairingHaptic) {
        if Thread.isMainThread {
            SystemHapticGenerators.shared.play(haptic)
        } else {
            DispatchQueue.main.async { SystemHapticGenerators.shared.play(haptic) }
        }
    }
}

/// One set of generators for the process, touched on the main thread only.
final class SystemHapticGenerators {
    static let shared = SystemHapticGenerators()

    private var impact: UIImpactFeedbackGenerator?
    private var light: UIImpactFeedbackGenerator?
    private var notification: UINotificationFeedbackGenerator?

    func play(_ haptic: PairingHaptic) {
        switch haptic {
        case .lock:
            let g = impact ?? UIImpactFeedbackGenerator(style: .medium)
            impact = g
            g.impactOccurred()
            g.prepare()
        case .piece:
            let g = light ?? UIImpactFeedbackGenerator(style: .light)
            light = g
            g.impactOccurred()
            g.prepare()
        case .read, .stopped, .removalRequested:
            notify(.success)
        case .reset:
            notify(.warning)
        case .removalFailed:
            notify(.error)
        }
    }

    private func notify(_ type: UINotificationFeedbackGenerator.FeedbackType) {
        let g = notification ?? UINotificationFeedbackGenerator()
        notification = g
        g.notificationOccurred(type)
        g.prepare()
    }
}
#endif

/// `SystemPairingHaptics` on iOS, `NoPairingHaptics` elsewhere: what a screen plays when the host passes none.
func defaultPairingHaptics() -> PairingHaptics {
    #if canImport(UIKit)
    return SystemPairingHaptics()
    #else
    return NoPairingHaptics()
    #endif
}
