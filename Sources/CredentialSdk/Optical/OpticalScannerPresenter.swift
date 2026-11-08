import Foundation

/// What the scanner shows, computed from `OpticalPairingReader`'s published state: the ring, the words, the
/// progress line and the haptic for this change. Pure and `Equatable`, no UIKit, so it is tested on macOS.
///
/// Rules:
/// - Ring: `.searching` for fit `.searching`, `.unfit` for `.tooFar` / `.tooClose`, `.reading(held)` for
///   `.reading`, `.solid` once status is `.complete`.
/// - Words follow the fit. When `resets` rises while the fit is `.reading`, the reset words show for
///   `resetWordsHold` seconds, then the reading words again; leaving `.reading` ends them early.
/// - Progress ("3 of 8 pieces read"; "3 of 4" for a sign-in ring, the total follows `held.count`) only while the fit is `.reading` and once `.complete`.
/// - Haptics: `.lock` on a change into `.reading` when the last lock played at least `lockHapticGap` ago;
///   `.read` once on `.complete`; `.reset` once per rise of `resets`; `.piece` when the count of pieces held
///   rises while scanning. At most one per update, in that order of precedence: `.read`, `.reset`, `.lock`, `.piece`. An unchanged input gives an equal output and no haptic.
/// - `.cameraDenied` and `.cameraUnavailable` are the overlay's own screens; the presenter keeps its words as
///   for `.searching` and plays nothing.
@available(iOS 15, *)
public struct OpticalScannerPresenter {
    public enum Ring: Equatable { case searching, unfit, reading(held: [Bool]), solid }

    public struct Output: Equatable {
        public let ring: Ring
        public let title: String
        public let hint: String
        public let progress: String?
        public let haptic: PairingHaptic?

        public init(ring: Ring, title: String, hint: String, progress: String?, haptic: PairingHaptic?) {
            self.ring = ring; self.title = title; self.hint = hint; self.progress = progress; self.haptic = haptic
        }
    }

    public let resetWordsHold: TimeInterval
    public let lockHapticGap: TimeInterval

    private var lastFit: OpticalPairingReader.Fit?
    private var lastResets: Int?
    private var lastCount: Int?
    private var lastLock: TimeInterval?
    private var readPlayed = false
    private var resetWordsUntil: TimeInterval?

    public init(resetWordsHold: TimeInterval = 1.2, lockHapticGap: TimeInterval = 0.8) {
        self.resetWordsHold = resetWordsHold
        self.lockHapticGap = lockHapticGap
    }

    /// Call on every published change; `resets` is the sum of `timing.resets` (the scanner leaves out `.left`,
    /// the person closing), `now` is `CACurrentMediaTime()`.
    public mutating func update(status: OpticalPairingReader.Status, fit: OpticalPairingReader.Fit,
                                held: [Bool], resets: Int, now: TimeInterval) -> Output {
        let complete = status == .complete
        let camera = status == .cameraDenied || status == .cameraUnavailable

        // A rise in the reset count. The first update only sets the baseline; a fall is a new run.
        let resetRose = lastResets.map { resets > $0 } ?? false
        lastResets = resets

        // Fit changes into .reading.
        let locked = fit == .reading && lastFit != .reading
        lastFit = fit

        if !complete { readPlayed = false }
        if fit != .reading || complete { resetWordsUntil = nil }
        if resetRose && fit == .reading && !complete { resetWordsUntil = now + resetWordsHold }

        let gained = held.filter { $0 }.count
        let pieceRose = lastCount.map { gained > $0 } ?? (gained > 0)
        lastCount = gained

        var haptic: PairingHaptic?
        if !camera {
            if complete && !readPlayed {
                haptic = .read
                readPlayed = true
            } else if resetRose && status == .scanning {
                haptic = .reset
            } else if locked && !complete && status == .scanning && lastLock.map({ now - $0 >= lockHapticGap }) ?? true {
                haptic = .lock
                lastLock = now
            } else if pieceRose && !complete && status == .scanning {
                haptic = .piece
            }
        }

        let total = held.isEmpty ? OpticalFrame.chunkCount : held.count
        let count = held.filter { $0 }.count
        if complete {
            return Output(ring: .solid, title: ScreenWords.readerRead, hint: ScreenWords.readerReadHint,
                          progress: ScreenWords.readerProgress(total, of: total), haptic: haptic)
        }
        switch fit {
        case .searching:
            return Output(ring: .searching, title: ScreenWords.readerSearching, hint: ScreenWords.readerSearchingHint,
                          progress: nil, haptic: haptic)
        case .tooFar:
            return Output(ring: .unfit, title: ScreenWords.readerTooFar, hint: ScreenWords.readerTooFarHint,
                          progress: nil, haptic: haptic)
        case .tooClose:
            return Output(ring: .unfit, title: ScreenWords.readerTooClose, hint: ScreenWords.readerTooCloseHint,
                          progress: nil, haptic: haptic)
        case .reading:
            let resetting = resetWordsUntil.map { now < $0 } ?? false
            if !resetting { resetWordsUntil = nil }
            return Output(ring: .reading(held: held),
                          title: resetting ? ScreenWords.readerReset : ScreenWords.readerReading,
                          hint: resetting ? ScreenWords.readerResetHint : ScreenWords.readerReadingHint,
                          progress: ScreenWords.readerProgress(count, of: total), haptic: haptic)
        }
    }
}
