import Foundation
#if canImport(SwiftUI) && canImport(CoreGraphics)
import SwiftUI

/// Every state the enrolling Mac shows, in the order the poll produces them. The host maps `endorsementStatus()`
/// and its own calls onto this (README, "The enrolling device"); the SDK runs no poll.
@available(iOS 15, macOS 13, *)
public enum MacPairingState: Equatable {
    /// keys_attached; a nil `expiresAt` hides the countdown.
    case waiting(payload: Data, expiresAt: Date?)
    /// authorized: the host is calling `endorsementFinish()`; Touch ID is the system's sheet.
    case approved
    /// `endorsementFinish()` threw `.userAuthenticationFailed`.
    case touchIDFailed
    /// finish 201.
    case endorsed(pattern: DevicePattern?, addedAt: Date)
    /// Cancelled by a phone (poll or finish refused "cancelled").
    case notPaired
    /// Poll "expired", or finish refused "expired".
    case expired
    /// Cancel pressed on this Mac.
    case cancelled
}

/// What the buttons do. Each state shows only the buttons its words name (see `MacPairingFlowScreen`).
@available(iOS 15, macOS 13, *)
public struct MacPairingActions {
    /// waiting: "Cancel"; touchIDFailed: "Cancel".
    public var onCancel: () -> Void = {}
    /// touchIDFailed: "Finish with Touch ID".
    public var onFinish: () -> Void = {}
    /// endorsed: "Done".
    public var onDone: () -> Void = {}
    /// notPaired: "Try again"; cancelled: "Start again"; expired: "Show a new pattern".
    public var onTryAgain: () -> Void = {}
    /// notPaired, expired, cancelled: "Close".
    public var onClose: () -> Void = {}
    public init() {}
}

/// Window sizes the design fixes. The pattern side is min(width - 96, height - 360), never under 220 (the
/// technical floor): the header, title block, helper line and footer take 360 pt. The default window gives 520,
/// the minimum 500 (the premium layout; the phone needs a large pattern to focus).
@available(iOS 15, macOS 13, *)
public enum MacPairingWindowMetrics {
    public static let defaultSize = CGSize(width: 760, height: 880)
    public static let minimumSize = CGSize(width: 660, height: 860)
    public static let title = ScreenWords.macWindowTitle

    public static func patternSide(in size: CGSize) -> CGFloat {
        max(220, min(size.width - 96, size.height - 360))
    }
}

/// One window, every state. Black end to end; the sett tile takes `ink` on `ground` (defaults krPaper on krTile).
/// `hostHint` is the sentence after the approved body on the waiting screen (default `ScreenWords.macOpenHint`;
/// the host names its app and menu). `now` drives "Expires in m:ss" and "Added today HH:mm"; the view ticks
/// its own one-second clock when `now` is nil.
///
/// `qrFallbackPayload` is the backup QR, `opened.qrPayload`. The pattern is the pairing
/// channel; a static QR can be photographed and relayed, so the default (nil) shows no QR anywhere. With it, a quiet
/// "Won't scan?" under the waiting screen's helper line swaps the pattern for a QR of that JSON, and "Show the
/// pattern" swaps back. The phone reads it only when its reader opts in (`OpticalPairingReader.acceptsQR`).
@available(iOS 15, macOS 13, *)
public struct MacPairingFlowScreen: View {
    let state: MacPairingState
    let hostHint: String
    let ink: Color
    let ground: Color
    let now: Date?
    let actions: MacPairingActions
    let qrFallbackPayload: String?
    /// False for the source-compatible `MacEndorsedScreen`, which has no Done.
    var showsDone = true
    /// The waiting screen shows the backup QR instead of the pattern (only with a `qrFallbackPayload`).
    @State private var showingQR: Bool

    /// Height the "Won't scan?" row takes from the pattern, so the window's minimum size still fits every line.
    static let qrLinkAllowance: CGFloat = 28

    public init(state: MacPairingState, hostHint: String? = nil, ink: Color? = nil, ground: Color? = nil,
                now: Date? = nil, actions: MacPairingActions = MacPairingActions(), qrFallbackPayload: String? = nil) {
        self.init(state: state, hostHint: hostHint, ink: ink, ground: ground, now: now, actions: actions,
                  qrFallbackPayload: qrFallbackPayload, showingQR: false)
    }

    /// Tests: `showingQR` opens the waiting screen on the QR, as if "Won't scan?" had been pressed.
    init(state: MacPairingState, hostHint: String?, ink: Color?, ground: Color?, now: Date?, actions: MacPairingActions,
         qrFallbackPayload: String?, showingQR: Bool) {
        self.state = state
        self.hostHint = hostHint ?? ScreenWords.macOpenHint
        self.ink = ink ?? krPaper
        self.ground = ground ?? krTile
        self.now = now
        self.actions = actions
        self.qrFallbackPayload = qrFallbackPayload
        _showingQR = State(initialValue: showingQR && qrFallbackPayload != nil)
    }

    /// The step the strip marks: 1 scan, 3 finish, 4 all done. A pairing that ended without an endorsement marks
    /// none (0); the design dims every step.
    static func step(for state: MacPairingState) -> Int {
        switch state {
        case .waiting: return 1
        case .approved, .touchIDFailed: return 3
        case .endorsed: return ScreenWords.macSteps.count + 1
        case .notPaired, .expired, .cancelled: return 0
        }
    }

    public var body: some View {
        GeometryReader { geo in
            VStack(spacing: 0) {
                // Header: the logo top left, the stepper centred under it (so a narrow window never overlaps them).
                ZStack(alignment: .topLeading) {
                    MacStepper(labels: ScreenWords.macSteps, now: Self.step(for: state), compact: geo.size.width < 720)
                        .frame(maxWidth: .infinity)
                        .padding(.top, 32)
                    KruthoLogo(height: 16)
                }
                .padding(.horizontal, 32)
                .padding(.top, 16)

                VStack(spacing: 0) {
                    content(side: MacPairingWindowMetrics.patternSide(in: geo.size) - (qrFallbackPayload == nil ? 0 : Self.qrLinkAllowance))
                }
                .frame(maxWidth: 960)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(.horizontal, 32)

                MacFooter(state: state, script: script, now: now, actions: actions)
            }
            .foregroundColor(krSoftWhite)
        }
        .background(krMacGround.ignoresSafeArea())
        .environment(\.colorScheme, .dark)
        .onChange(of: state) { if case .waiting = $0 {} else { showingQR = false } }   // a new pattern opens on the pattern
    }

    /// The words each state draws, in one place: the view renders from this and the tests read it (SwiftUI on
    /// macOS exposes no accessibility tree to a headless host, so there is nothing else to probe).
    struct Script: Equatable {
        var title: String
        var body: String
        /// The line under the title (waiting only).
        var subtitle: String? = nil
        /// "Waiting for your iPhone · Expires in m:ss" (the waiting status row, Cancel excluded).
        var status: String?
        var added: String?
        var primary: String?
        var secondary: String?
        /// The quiet link under the helper line (waiting with a `qrFallbackPayload` only): "Won't scan?" or "Show the pattern".
        var qrToggle: String? = nil
    }

    static func script(state: MacPairingState, hostHint: String? = nil, now: Date, showsDone: Bool = true,
                       qrFallback: Bool = false, showingQR: Bool = false) -> Script {
        switch state {
        case .waiting(_, let expiresAt):
            let status = [ScreenWords.macWaiting, MacWaitingStatus.countdown(expiresAt: expiresAt, now: now)]
                .compactMap { $0 }.joined(separator: " · ")
            return Script(title: ScreenWords.macPairTitle, body: ScreenWords.macPairBody + " " + (hostHint ?? ScreenWords.macOpenHint),
                          subtitle: ScreenWords.macPairSubtitle, status: status, added: nil, primary: nil, secondary: ScreenWords.macCancel,
                          qrToggle: qrFallback ? (showingQR ? ScreenWords.macShowPattern : ScreenWords.macWontScan) : nil)
        case .approved:
            return Script(title: ScreenWords.macApprovedTitle, body: ScreenWords.macApprovedBody, status: ScreenWords.macFinishing)
        case .touchIDFailed:
            return Script(title: ScreenWords.macTouchIDFailedTitle, body: ScreenWords.macTouchIDFailedBody,
                          primary: ScreenWords.macFinish, secondary: ScreenWords.macCancel)
        case .endorsed(_, let addedAt):
            return Script(title: ScreenWords.macTitle, body: ScreenWords.macBody, added: ScreenWords.macAdded(addedAt, now: now),
                          primary: showsDone ? ScreenWords.macDone : nil)
        case .notPaired:
            return Script(title: ScreenWords.macNotPairedTitle, body: ScreenWords.macNotPairedBody,
                          primary: ScreenWords.macTryAgain, secondary: ScreenWords.macClose)
        case .expired:
            return Script(title: ScreenWords.macExpiredTitle, body: ScreenWords.macExpiredBody,
                          primary: ScreenWords.macShowNewPattern, secondary: ScreenWords.macClose)
        case .cancelled:
            return Script(title: ScreenWords.macCancelledTitle, body: ScreenWords.macCancelledBody,
                          primary: ScreenWords.macStartAgain, secondary: ScreenWords.macClose)
        }
    }

    private var script: Script {
        Self.script(state: state, hostHint: hostHint, now: now ?? Date(), showsDone: showsDone,
                    qrFallback: qrFallbackPayload != nil, showingQR: showingQR)
    }
    var title: String { script.title }

    @ViewBuilder private func titleText(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 30, weight: .semibold))
            .foregroundColor(krSoftWhite)
            .multilineTextAlignment(.center)
    }

    @ViewBuilder private func bodyText(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 17))
            .foregroundColor(krMuted)
            .multilineTextAlignment(.center)
            .lineSpacing(3)
            .frame(maxWidth: 560)
    }

    @ViewBuilder private func content(side: CGFloat) -> some View {
        let script = self.script
        switch state {
        case .waiting(let payload, _):
            titleText(script.title).padding(.top, 24)
            if let subtitle = script.subtitle { bodyText(subtitle).padding(.top, 8) }
            Spacer(minLength: 16)
            if showingQR, let qrFallbackPayload {
                PairingQRCode(text: qrFallbackPayload)
                    .frame(width: side, height: side)
                    .accessibilityIdentifier("mac.qr")
            } else {
                // Untouched for scan reliability; a faint ring sits outside the pattern's own quiet zone.
                OpticalPairingView(payload: payload)
                    .frame(width: side, height: side)
                    .clipShape(Circle())   // the pattern's black quiet zone stays; only the square's corners go
                    .background(Circle().stroke(Color.white.opacity(0.06), lineWidth: 1).padding(-14))
            }
            Spacer(minLength: 16)
            if let toggle = script.qrToggle {
                bodyText(script.body)
                Button { showingQR.toggle() } label: {
                    Text(toggle).font(.system(size: 14, weight: .medium)).foregroundColor(krMuted)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("mac.qrToggle")
                .padding(.top, 10)
                .padding(.bottom, 18)
            } else {
                bodyText(script.body).padding(.bottom, 24)
            }
        case .endorsed(let pattern, _):
            titleText(script.title).padding(.top, 24)
            bodyText(script.body).padding(.top, 8)
            Spacer(minLength: 16)
            MacSettTile(pattern: pattern, ink: ink, ground: ground)
            Spacer(minLength: 16)
            if let added = script.added {
                Text(added)
                    .font(.system(size: 15).monospacedDigit())
                    .foregroundColor(krMuted)
                    .accessibilityIdentifier("mac.added")
                    .padding(.bottom, 24)
            }
        case .approved, .touchIDFailed, .notPaired, .expired, .cancelled:
            Spacer(minLength: 0)
            titleText(script.title)
            bodyText(script.body).padding(.top, 12)
            Spacer(minLength: 0)
        }
    }
}

/// The footer: one composed row under a hairline. Left, the status (a spinner while the Mac waits on the phone or
/// Touch ID); right, the countdown and the state's buttons, the primary rightmost as macOS places it.
@available(iOS 15, macOS 13, *)
struct MacFooter: View {
    let state: MacPairingState
    let script: MacPairingFlowScreen.Script
    let now: Date?
    let actions: MacPairingActions

    var body: some View {
        VStack(spacing: 0) {
            Rectangle().fill(Color.white.opacity(0.1)).frame(height: 1)
            HStack(spacing: 16) {
                left
                Spacer(minLength: 16)
                right
            }
            .frame(minHeight: 36)
            .padding(.horizontal, 32)
            .padding(.vertical, 20)
        }
    }

    @ViewBuilder private var left: some View {
        switch state {
        case .waiting:
            HStack(spacing: 12) {
                ProgressView().controlSize(.small)
                Text(ScreenWords.macWaiting).font(.system(size: 16, weight: .medium)).foregroundColor(krSoftWhite)
            }
        case .approved:
            HStack(spacing: 12) {
                ProgressView().controlSize(.small)
                Text(ScreenWords.macFinishing).font(.system(size: 16, weight: .medium)).foregroundColor(krSoftWhite)
            }
        default:
            EmptyView()
        }
    }

    @ViewBuilder private var right: some View {
        HStack(spacing: 12) {
            switch state {
            case .waiting(_, let expiresAt):
                MacWaitingStatus(expiresAt: expiresAt, now: now)
                MacButton(title: ScreenWords.macCancel, primary: false, action: actions.onCancel).accessibilityIdentifier("mac.secondary")
            case .approved:
                EmptyView()
            case .touchIDFailed:
                MacButton(title: script.secondary ?? ScreenWords.macCancel, primary: false, action: actions.onCancel).accessibilityIdentifier("mac.secondary")
                MacButton(title: script.primary ?? "", primary: true, action: actions.onFinish).accessibilityIdentifier("mac.primary")
            case .endorsed:
                if let primary = script.primary {
                    MacButton(title: primary, primary: true, action: actions.onDone).accessibilityIdentifier("mac.primary")
                }
            case .notPaired, .expired, .cancelled:
                if let secondary = script.secondary {
                    MacButton(title: secondary, primary: false, action: actions.onClose).accessibilityIdentifier("mac.secondary")
                }
                MacButton(title: script.primary ?? "", primary: true, action: actions.onTryAgain).accessibilityIdentifier("mac.primary")
            }
        }
    }
}

/// Three numbered steps joined by thin lines. The current step is an orange disc with a bright label; the others
/// are a grey ring and a muted label. Step 0 (an ended pairing) leaves every step muted.
@available(iOS 15, macOS 13, *)
struct MacStepper: View {
    let labels: [String]
    let now: Int
    var compact = false

    var body: some View {
        HStack(spacing: compact ? 10 : 14) {
            ForEach(Array(labels.enumerated()), id: \.offset) { index, label in
                if index > 0 {
                    Rectangle().fill(krMuted.opacity(0.45)).frame(width: compact ? 14 : 28, height: 1)
                }
                step(index + 1, label)
            }
        }
        .animation(.easeInOut(duration: 0.25), value: now)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(now >= 1 && now <= labels.count ? "Step \(now) of \(labels.count): \(labels[now - 1])" : "\(labels.count) steps")
    }

    @ViewBuilder private func step(_ n: Int, _ label: String) -> some View {
        let active = n == now
        HStack(spacing: 10) {
            ZStack {
                Circle().fill(active ? krSignal : Color.clear)
                Circle().stroke(active ? krSignal : krMuted.opacity(0.8), lineWidth: 1.5)
                Text("\(n)").font(.system(size: 13, weight: .semibold)).foregroundColor(active ? .white : krMuted)
            }
            .frame(width: 26, height: 26)
            Text(label)
                .font(.system(size: compact ? 14 : 15, weight: .medium))
                .foregroundColor(active ? krSoftWhite : krMuted)
                .lineLimit(1)
                .fixedSize()
        }
    }
}

/// A quiet macOS-style button: 34 pt tall, 8 pt corners. Primary is the signal orange; secondary a faint fill with a
/// hairline border. Hover brightens it, a press scales it to 97%.
@available(iOS 15, macOS 13, *)
struct MacButton: View {
    let title: String
    let primary: Bool
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: 15, weight: .medium))
        }
        .buttonStyle(MacButtonStyle(primary: primary, hover: hover))
        .onHover { hover = $0 }
    }
}

@available(iOS 15, macOS 13, *)
struct MacButtonStyle: ButtonStyle {
    let primary: Bool
    let hover: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(primary ? .white : krSoftWhite)
            .padding(.horizontal, 18)
            .frame(minWidth: 96, minHeight: 34)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(primary ? krSignal.opacity(hover ? 1 : 0.92) : Color.white.opacity(hover ? 0.12 : 0.07))
            )
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(primary ? 0 : 0.16), lineWidth: 1))
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
            .contentShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// "Expires in m:ss" in the footer, digits monospaced. The countdown reads `now` when the host gives one (tests)
/// and a one-second clock otherwise; the clock exists only while this view is on screen, so only in `.waiting`.
@available(iOS 15, macOS 13, *)
struct MacWaitingStatus: View {
    let expiresAt: Date?
    let now: Date?
    @StateObject private var clock = PairingSecondsClock()

    /// "Expires in m:ss", or nil when there is no expiry to show.
    static func countdown(expiresAt: Date?, now: Date) -> String? {
        guard let expiresAt else { return nil }
        return ScreenWords.macExpiresIn(expiresAt.timeIntervalSince(now))
    }

    var body: some View {
        let countdown = Self.countdown(expiresAt: expiresAt, now: now ?? clock.now)
        Group {
            if let countdown {
                Text(countdown).font(.system(size: 15, weight: .medium).monospacedDigit()).foregroundColor(krMuted)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel([ScreenWords.macWaiting, countdown].compactMap { $0 }.joined(separator: " · "))
        .accessibilityIdentifier("mac.status")
        .onAppear { if now == nil && expiresAt != nil { clock.start() } }
        .onDisappear { clock.stop() }
    }
}

/// Ticks on the main queue once a second and publishes the wall clock. A main-queue timer rather than
/// `TimelineView`, for the reason `OpticalFrameClock` is one (a command-line Mac host did not advance a
/// `TimelineView`).
@available(iOS 15, macOS 13, *)
final class PairingSecondsClock: ObservableObject {
    @Published private(set) var now = Date()
    private var timer: DispatchSourceTimer?

    func start() {
        stop()
        now = Date()
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(50))
        t.setEventHandler { [weak self] in self?.now = Date() }
        t.resume()
        timer = t
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    deinit { timer?.cancel() }
}

/// The sett at 340 pt on its dark tile, with the fallback words when this build cannot draw the pattern.
@available(iOS 15, macOS 13, *)
struct MacSettTile: View {
    let pattern: DevicePattern?
    let ink: Color
    let ground: Color
    var side: CGFloat = 340

    var body: some View {
        if let pattern, CredentialSdk.patternKnown(pattern) {
            SettPatternView(pattern: pattern, ink: ink, ground: ground)
                .frame(width: side, height: side)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.white.opacity(0.12), lineWidth: 1))
        } else if pattern != nil {
            PatternUnavailableView().frame(minHeight: side / 2)
        } else {
            Text(ScreenWords.unavailableTitle)
                .font(.system(.headline).weight(.medium))
                .frame(minHeight: side / 2)
        }
    }
}

/// Screen 1, kept source-compatible: the waiting state without a countdown. `ink` and `ground` stay in the
/// signature so callers compile and do not colour this screen (the whole window is black).
@available(iOS 15, macOS 13, *)
public struct MacPairingScreen: View {
    let payload: Data

    public init(payload: Data, ink: Color = .primary, ground: Color? = nil) {
        self.payload = payload
    }

    public var body: some View {
        MacPairingFlowScreen(state: .waiting(payload: payload, expiresAt: nil))
    }
}

/// Screen 4, kept source-compatible: the endorsed state, stamped with the time it appears, without Done.
@available(iOS 15, macOS 13, *)
public struct MacEndorsedScreen: View {
    let pattern: DevicePattern?
    let ink: Color
    let ground: Color?
    @State private var addedAt = Date()

    public init(pattern: DevicePattern?, ink: Color = .primary, ground: Color? = nil) {
        self.pattern = pattern; self.ink = ink; self.ground = ground
    }

    public var body: some View {
        var screen = MacPairingFlowScreen(state: .endorsed(pattern: pattern, addedAt: addedAt), ink: ink, ground: ground)
        screen.showsDone = false
        return screen
    }
}
#endif
