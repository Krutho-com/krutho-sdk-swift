import Foundation
#if canImport(SwiftUI) && canImport(CoreGraphics)
import SwiftUI
import CoreGraphics

/// Draws payload A (24 bytes) as the animated optical pattern: 8 frames at `frameRate` per second, looping.
/// Square; pure black ground and white marks inside its own square, whatever the host puts around it. The
/// finder ring's outer edge is at 0.40 of the side, so the view carries its own dark margin.
///
/// The view is stateless: it draws for as long as it is on screen. The host swaps it for the next screen on the
/// first transaction status other than `keys_attached`. 220 points is the smallest size tested.
///
/// `inverted` draws the pattern dark on light for a light-mode host; the phone's reader accepts either polarity.
/// `ground` sets the square's ground colour (default: black, or white when inverted), so a window of any colour
/// shows no edge. The margin around the ring is drawn in the ground colour.
///
/// A payload that is not 24 bytes draws the ground square only.
@available(iOS 15, macOS 13, *)
public struct OpticalPairingView: View {
    let payload: Data
    let frameRate: Double
    let inverted: Bool
    let ground: Color?
    @StateObject private var clock = OpticalFrameClock()

    /// - Parameters:
    ///   - inverted: dark marks on a light ground (default false: today's light marks on black).
    ///   - ground: the square's ground colour; nil keeps black (white when `inverted`). Marks keep their gray, so
    ///     pick a ground that contrasts with them (a light colour when `inverted`, a dark one otherwise).
    public init(payload: Data, frameRate: Double = 10, inverted: Bool = false, ground: Color? = nil) {
        self.payload = payload
        self.frameRate = frameRate
        self.inverted = inverted
        self.ground = ground
    }

    /// Frame index `elapsed` seconds after the view appeared. Derived from time, not counted, so a dropped
    /// display frame does not shift the sequence.
    static func frameIndex(elapsed: TimeInterval, frameRate: Double) -> Int {
        guard frameRate > 0, elapsed >= 0 else { return 0 }
        return Int(elapsed * frameRate) % OpticalFrame.chunkCount
    }

    public var body: some View {
        let valid = payload.count == OpticalFrame.payloadLength
        let rate = frameRate > 0 ? frameRate : OpticalLayout.frameRate
        let index = Self.frameIndex(elapsed: clock.elapsed, frameRate: rate)
        let inverted = self.inverted, groundColor = ground?.cgColor
        Canvas { context, size in
            let side = min(size.width, size.height)
            let word: UInt64? = valid ? OpticalFrame.word(payload: payload, index: index) : nil
            context.withCGContext { cg in
                cg.translateBy(x: (size.width - side) / 2, y: (size.height - side) / 2)
                if let word {
                    OpticalRenderer.draw(word: word, into: cg, side: side, inverted: inverted, ground: groundColor)
                } else {
                    if let groundColor { cg.setFillColor(groundColor) } else { cg.setFillColor(gray: inverted ? 1 : 0, alpha: 1) }
                    cg.fill(CGRect(x: 0, y: 0, width: side, height: side))
                }
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .onAppear { clock.start(rate: rate) }
        .onDisappear { clock.stop() }
        .accessibilityElement()
        .accessibilityLabel("Pairing pattern")
    }
}

/// Ticks on the main queue at twice the frame rate and publishes the time since `start`. A main-queue timer
/// rather than `TimelineView`, so the pattern also animates in hosts that do not run an AppKit or UIKit
/// event loop (a command-line Mac host driven by Swift concurrency did not advance a `TimelineView`).
@available(iOS 15, macOS 13, *)
final class OpticalFrameClock: ObservableObject {
    @Published private(set) var elapsed: TimeInterval = 0
    private var timer: DispatchSourceTimer?
    private var started: Date?

    func start(rate: Double) {
        stop()
        let begin = Date()
        started = begin
        elapsed = 0
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now(), repeating: 1 / (rate * 2), leeway: .milliseconds(2))
        t.setEventHandler { [weak self] in self?.elapsed = Date().timeIntervalSince(begin) }
        t.resume()
        timer = t
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    deinit { timer?.cancel() }
}
#endif
