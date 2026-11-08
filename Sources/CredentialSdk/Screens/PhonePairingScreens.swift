#if canImport(SwiftUI)
import SwiftUI

/// Screen 2, on the phone after the scan: "Let a new device act as you?" with the server's facts
/// ("Mac app · attested · asked just now"), never the pattern's. "Approve with Face ID" is the host's
/// `endorse(transactionId:)`; "Cancel" leaves. Before calling `endorse`, check `invitation.expiresAt`
/// against the clock: a row the server has not swept yet still inspects, so show
/// `PairingRefusedScreen(reason: .expired)` once it has passed.
@available(iOS 15, macOS 13, *)
public struct BeforeFaceIDScreen: View {
    let invitation: EndorsementInvitation
    let now: Date
    let onApprove: () -> Void
    let onCancel: () -> Void

    public init(invitation: EndorsementInvitation, now: Date = Date(),
                onApprove: @escaping () -> Void = {}, onCancel: @escaping () -> Void = {}) {
        self.invitation = invitation; self.now = now; self.onApprove = onApprove; self.onCancel = onCancel
    }

    static func glyph(_ attestation: DeviceAttestationFacts?) -> String? {
        switch attestation?.platform {
        case "macosx":   return "laptopcomputer"
        case "iphoneos": return "iphone"
        default:         return nil
        }
    }

    var askedLine: String {
        ScreenWords.askedLine(attestation: invitation.attestation, createdAt: invitation.createdAt, now: now)
    }

    public var body: some View {
        PhoneScreen(title: ScreenWords.approveTitle(invitation.attestation), subtitle: ScreenWords.approveSubtitle(invitation.attestation),
                    step: 2, onClose: onCancel) {
            Spacer(minLength: 0)
            VStack(spacing: 10) {
                // The glyph follows the attestation; an unattested or unknown device gets none.
                if let glyph = Self.glyph(invitation.attestation) {
                    Image(systemName: glyph)
                        .font(.system(size: 96, weight: .ultraLight))
                        .foregroundColor(krSoftWhite)
                        .padding(.bottom, 8)
                        .accessibilityHidden(true)
                }
                Text(ScreenWords.kind(invitation.attestation)).font(.system(size: 20, weight: .semibold))
                if let requested = ScreenWords.requestedLine(createdAt: invitation.createdAt, now: now) {
                    Text(requested).font(.system(size: 16)).foregroundColor(Color.white.opacity(0.72))
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(askedLine)
            Spacer(minLength: 0)
            PhoneBody(ScreenWords.approveBody(invitation.attestation))
            PhoneButtons {
                PrimaryButton(title: ScreenWords.approveYes, systemImage: "faceid", action: onApprove)
                SecondaryButton(title: ScreenWords.approveNo, action: onCancel)
            }
        }
    }
}

/// Straight after Face ID (no match question): "Finish on your Mac", with the approve reply's sett
/// shown as "This Mac's pattern", the pattern assigned to the new device. The host polls `devicesList()` for the
/// alert the Mac's finish writes and shows `EndorsementAlertScreen` when it lands, or
/// `PairingRefusedScreen(reason: .expired)` once `invitation.expiresAt` passes. "Done" leaves early; the alert
/// still arrives. `onRemove` non-nil adds the quiet "Not my Mac? Remove it" (wire it as `ConfirmAfterScreen`'s
/// `onRemove`: `endorsementCancel`, then `PairingStoppedScreen` or `revokeDevice`), for a person who scanned
/// another Mac's screen.
@available(iOS 15, macOS 13, *)
public struct WaitingForMacScreen: View {
    let pattern: DevicePattern?
    let ink: Color
    let ground: Color
    let onDone: () -> Void
    let onRemove: (() -> Void)?

    public init(pattern: DevicePattern?, ink: Color? = nil, ground: Color? = nil,
                onRemove: (() -> Void)? = nil, onDone: @escaping () -> Void = {}) {
        self.pattern = pattern; self.ink = ink ?? krPaper; self.ground = ground ?? krTile
        self.onRemove = onRemove; self.onDone = onDone
    }

    public var body: some View {
        PhoneScreen(title: ScreenWords.waitingTitle, subtitle: ScreenWords.waitingSubtitle, step: 3) {
            Spacer(minLength: 0)
            Text(ScreenWords.waitingPatternLabel)
                .font(.system(size: 13, weight: .medium))
                .foregroundColor(Color.white.opacity(0.6))
            PatternSlot(pattern: pattern, ink: ink, ground: ground, side: 200, tile: true)
            PhoneStatus(text: ScreenWords.waitingStatus).padding(.top, 12)
            PhoneBody(ScreenWords.waitingBody)
            Spacer(minLength: 0)
            PhoneButtons {
                if let onRemove {
                    QuietButton(title: ScreenWords.waitingRemove, action: onRemove)
                        .accessibilityIdentifier("waiting.remove")
                }
                SecondaryButton(title: ScreenWords.waitingDone, action: onDone)
            }
        }
    }
}

/// After "No, remove it" answered `.cancelled`: "Pairing stopped". Nothing was issued. Plays `.stopped` when it
/// appears (`haptics` nil: `SystemPairingHaptics` on iOS).
@available(iOS 15, macOS 13, *)
public struct PairingStoppedScreen: View {
    let haptics: PairingHaptics?
    let onDone: () -> Void

    public init(haptics: PairingHaptics? = nil, onDone: @escaping () -> Void = {}) {
        self.haptics = haptics; self.onDone = onDone
    }

    public var body: some View {
        PhoneScreen(title: ScreenWords.stoppedTitle, step: nil) {
            PhoneBody(ScreenWords.stoppedBody)
            Spacer(minLength: 0)
            PhoneButtons {
                PrimaryButton(title: ScreenWords.stoppedDone, action: onDone)
            }
        }
        .onAppear { (haptics ?? defaultPairingHaptics()).play(.stopped) }
    }
}

/// Inspect or endorse refused on the transaction's state (`CredentialSdkError.transactionState` is "expired" or
/// "cancelled"), or the host's own clock passed `invitation.expiresAt`: "That pattern has expired" or "Pairing was
/// cancelled on the Mac". "Scan again" is the host's `reader.restart()`; "Close" leaves.
@available(iOS 15, macOS 13, *)
public struct PairingRefusedScreen: View {
    public enum Reason: Equatable { case expired, cancelled }

    let reason: Reason
    let onScanAgain: () -> Void
    let onClose: () -> Void

    public init(reason: Reason, onScanAgain: @escaping () -> Void = {}, onClose: @escaping () -> Void = {}) {
        self.reason = reason; self.onScanAgain = onScanAgain; self.onClose = onClose
    }

    public var body: some View {
        PhoneScreen(title: reason == .expired ? ScreenWords.expiredTitle : ScreenWords.macCancelledOnPhoneTitle,
                    step: nil) {
            PhoneBody(reason == .expired ? ScreenWords.expiredBody : ScreenWords.macCancelledOnPhoneBody)
            Spacer(minLength: 0)
            PhoneButtons {
                PrimaryButton(title: ScreenWords.scanAgain, action: onScanAgain)
                SecondaryButton(title: ScreenWords.readerClose, action: onClose)
            }
        }
    }
}

// MARK: The phone screens' layout

/// A phone pairing screen (the premium layout): black, the logo top left and a close cross top right when
/// `onClose` is given, the stepper (Scan · Approve · Verify) when `step` is given, the title and subtitle left
/// aligned, then the content (with its own spacers and buttons).
@available(iOS 15, macOS 13, *)
struct PhoneScreen<Content: View>: View {
    let title: String
    var subtitle: String? = nil
    let step: Int?
    var onClose: (() -> Void)? = nil
    @ViewBuilder let content: () -> Content

    init(title: String, subtitle: String? = nil, step: Int?, onClose: (() -> Void)? = nil,
         @ViewBuilder content: @escaping () -> Content) {
        self.title = title; self.subtitle = subtitle; self.step = step; self.onClose = onClose; self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PhoneHeader(onClose: onClose)
            if let step {
                PhoneStepper(labels: ScreenWords.phoneSteps, now: step).padding(.top, 18)
            }
            PhoneTitle(title: title, subtitle: subtitle).padding(.top, step == nil ? 32 : 26)
            VStack(spacing: 16) { content() }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(.top, 24)
        }
        .padding(.horizontal, 20)
        .padding(.top, 8)
        .padding(.bottom, 16)
        .frame(maxWidth: 440)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .foregroundColor(krSoftWhite)
        .background(krBlack.ignoresSafeArea())
        .environment(\.colorScheme, .dark)
    }
}

/// The logo top left; a close cross top right when `onClose` is given.
@available(iOS 15, macOS 13, *)
struct PhoneHeader: View {
    let onClose: (() -> Void)?
    var body: some View {
        HStack {
            KruthoLogo(height: 15)
            Spacer(minLength: 0)
            if let onClose {
                Button(action: onClose) {
                    Image(systemName: "xmark").font(.system(size: 17, weight: .regular))
                        .foregroundColor(Color.white.opacity(0.75))
                        .frame(width: 32, height: 32)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(ScreenWords.readerClose)
            }
        }
        .frame(minHeight: 32)
    }
}

/// The title (30 pt semibold) and its subtitle, left aligned.
@available(iOS 15, macOS 13, *)
struct PhoneTitle: View {
    let title: String
    let subtitle: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 30, weight: .semibold)).foregroundColor(krSoftWhite)
                .fixedSize(horizontal: false, vertical: true)
            if let subtitle {
                Text(subtitle).font(.system(size: 17)).foregroundColor(Color.white.opacity(0.72))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Three steps joined by thin lines, labels underneath. Done steps are a ring with a tick, the current step an
/// orange disc with its number and a bright label, later steps a grey ring and a muted label.
@available(iOS 15, macOS 13, *)
struct PhoneStepper: View {
    let labels: [String]
    let now: Int

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            ForEach(Array(labels.enumerated()), id: \.offset) { index, label in
                if index > 0 {
                    Rectangle().fill(Color.white.opacity(0.25)).frame(height: 1).padding(.top, 14)
                        .frame(maxWidth: .infinity)
                }
                step(index + 1, label)
            }
        }
        .padding(.horizontal, 24)
        .animation(.easeInOut(duration: 0.25), value: now)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(now >= 1 && now <= labels.count ? "Step \(now) of \(labels.count): \(labels[now - 1])" : "\(labels.count) steps")
    }

    @ViewBuilder private func step(_ n: Int, _ label: String) -> some View {
        let active = n == now
        let done = n < now
        VStack(spacing: 8) {
            ZStack {
                Circle().fill(active ? krSignal : Color.clear)
                Circle().stroke(active ? krSignal : Color.white.opacity(done ? 0.8 : 0.45), lineWidth: 1.5)
                if done {
                    Image(systemName: "checkmark").font(.system(size: 12, weight: .semibold)).foregroundColor(krSoftWhite)
                } else {
                    Text("\(n)").font(.system(size: 13, weight: .semibold))
                        .foregroundColor(active ? .white : Color.white.opacity(0.6))
                }
            }
            .frame(width: 28, height: 28)
            Text(label)
                .font(.system(size: 13, weight: active ? .semibold : .regular))
                .foregroundColor(active ? krSoftWhite : Color.white.opacity(0.6))
                .fixedSize()
        }
        .frame(width: 28)
    }
}

/// A spinner and a status line ("Waiting for your Mac").
@available(iOS 15, macOS 13, *)
struct PhoneStatus: View {
    let text: String
    var body: some View {
        HStack(spacing: 12) {
            ProgressView().tint(krSoftWhite)
            Text(text).font(.system(size: 17, weight: .medium)).foregroundColor(krSoftWhite)
        }
    }
}

/// Body words on the dark ground: 15 points, 70% white, centred.
@available(iOS 15, macOS 13, *)
struct PhoneBody: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.system(size: 16))
            .foregroundColor(Color.white.opacity(0.72))
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// The screen's actions, stacked full width.
@available(iOS 15, macOS 13, *)
struct PhoneButtons<Buttons: View>: View {
    @ViewBuilder let buttons: () -> Buttons
    var body: some View {
        VStack(spacing: 10) { buttons() }
    }
}
#endif
