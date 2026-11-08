#if canImport(SwiftUI)
import SwiftUI

/// Kept for existing hosts; the flow now goes from Face ID straight to `WaitingForMacScreen`
/// (no match question; its `onRemove` carries "Not my Mac? Remove it").
///
/// Screen 3, on the phone after Face ID: "Does your Mac show this pattern?"
/// The host wires `onMatch` to `WaitingForMacScreen` (the endorsement stands;
/// nothing is sent) and `onRemove` to `endorsementCancel(transactionId:)`, then
/// `PairingStoppedScreen` on `.cancelled` or `revokeDevice(targetDeviceId:)`
/// when that answers `.consumed`. Nothing here talks to the server.
///
/// Black, with the sett at 260 points on its tile and the step strip at
/// "Check". `ink` and `ground` colour the sett (defaults #FAFAFA on #181818).
/// Fail closed: with no drawable pattern "Yes, it matches" is never offered;
/// `onContinueUnchecked` non-nil adds the quiet "Continue without checking"
/// in that case only.
@available(iOS 15, macOS 13, *)
public struct ConfirmAfterScreen: View {
    let pattern: DevicePattern?
    let ink: Color
    let ground: Color
    let onMatch: () -> Void
    let onRemove: () -> Void
    let onContinueUnchecked: (() -> Void)?

    public init(pattern: DevicePattern?, ink: Color? = nil, ground: Color? = nil,
                onMatch: @escaping () -> Void = {}, onRemove: @escaping () -> Void = {},
                onContinueUnchecked: (() -> Void)? = nil) {
        self.pattern = pattern; self.ink = ink ?? krPaper; self.ground = ground ?? krTile
        self.onMatch = onMatch; self.onRemove = onRemove; self.onContinueUnchecked = onContinueUnchecked
    }

    public var body: some View {
        let known = CredentialSdk.patternKnown(pattern)
        PhoneScreen(title: ScreenWords.confirmTitle, subtitle: ScreenWords.confirmSubtitle, step: 3) {
            Spacer(minLength: 0)
            PatternSlot(pattern: pattern, ink: ink, ground: ground, side: 260, tile: true)
            PhoneBody(ScreenWords.confirmBody).padding(.top, 8)
            Spacer(minLength: 0)
            PhoneButtons {
                if known {
                    PrimaryButton(title: ScreenWords.confirmYes, action: onMatch)
                        .accessibilityIdentifier("confirm.yes")
                }
                SecondaryButton(title: ScreenWords.confirmNo, action: onRemove)
                    .accessibilityIdentifier("confirm.no")
                if !known, let onContinueUnchecked {
                    QuietButton(title: ScreenWords.confirmContinue, action: onContinueUnchecked)
                        .accessibilityIdentifier("confirm.continue")
                }
            }
        }
    }
}

/// Screen 5, on every root phone: "A new device can act as you". `isThisDevice`
/// says whether this phone approved the new device. "That was me" is the
/// host's `acknowledgeAlert(alertId:)`; "Not me" opens `RevokeScreen`.
///
/// An alert whose `deviceStatus` is "revoked" is for a device that no longer
/// acts: it reads "This device was removed", the fact line ends "removed",
/// and the one button, "OK", calls `onDismissRemoved`, where the host
/// acknowledges it: the alert stays open until its recipient does, so a
/// reload alone shows it again. "Not me" is never offered for it.
@available(iOS 15, macOS 13, *)
public struct EndorsementAlertScreen: View {
    let alert: EndorsementAlert
    let isThisDevice: Bool
    let ink: Color
    let ground: Color
    let now: Date
    let onThatWasMe: () -> Void
    let onNotMe: () -> Void
    let onDismissRemoved: () -> Void

    public init(alert: EndorsementAlert, isThisDevice: Bool, ink: Color? = nil, ground: Color? = nil,
                now: Date = Date(),
                onThatWasMe: @escaping () -> Void = {}, onNotMe: @escaping () -> Void = {},
                onDismissRemoved: (() -> Void)? = nil) {
        self.alert = alert; self.isThisDevice = isThisDevice; self.ink = ink ?? krPaper; self.ground = ground ?? krTile
        self.now = now; self.onThatWasMe = onThatWasMe; self.onNotMe = onNotMe
        // A caller written before removed alerts existed passes only the two actions: its "That was me" is the
        // acknowledgment, so the removed alert's OK uses it rather than doing nothing.
        self.onDismissRemoved = onDismissRemoved ?? onThatWasMe
    }

    var removed: Bool { alert.deviceStatus == "revoked" }

    var factLine: String {
        removed
            ? ScreenWords.removedFactLine(attestation: alert.attestation, createdAt: alert.createdAt, now: now)
            : ScreenWords.factLine(attestation: alert.attestation, createdAt: alert.createdAt,
                                   isThisDevice: isThisDevice, now: now)
    }

    public var body: some View {
        PhoneScreen(title: removed ? ScreenWords.removedTitle : ScreenWords.alertTitle, step: nil) {
            Spacer(minLength: 0)
            PatternSlot(pattern: alert.pattern, ink: ink, ground: ground, side: 260, tile: true)
            MonoLine(factLine)
            Spacer(minLength: 0)
            PhoneButtons {
                if removed {
                    SecondaryButton(title: ScreenWords.removedOK, action: onDismissRemoved)
                        .accessibilityIdentifier("alert.ok")
                } else {
                    PrimaryButton(title: ScreenWords.alertMe, action: onThatWasMe)
                        .accessibilityIdentifier("alert.me")
                    SecondaryButton(title: ScreenWords.alertNotMe, action: onNotMe)
                        .accessibilityIdentifier("alert.notMe")
                }
            }
        }
    }
}

/// Screens 6, 7 and 7b, from "Not me": "Remove this device?" and its two
/// outcomes. The host drives `phase`: `.confirm` until the person taps "Remove
/// with Face ID" (the host calls `revokeDevice(targetDeviceId:)`, which raises
/// Face ID itself), then `.requested` on success or `.failed` on a thrown
/// error. After a failure the alert stays and the two buttons come back so the
/// person can try again.
///
/// Black, the sett at 260 points on its tile. When the phase lands on
/// `.requested` it plays `.removalRequested`, on `.failed` `.removalFailed`
/// (also on first appear when built already in that phase); `haptics` nil
/// plays them through `SystemPairingHaptics` on iOS.
@available(iOS 15, macOS 13, *)
public struct RevokeScreen: View {
    public enum Phase: Equatable {
        case confirm
        case requested
        case failed
    }

    let alert: EndorsementAlert
    let phase: Phase
    let ink: Color
    let ground: Color
    let haptics: PairingHaptics?
    let onRemove: () -> Void
    let onKeep: () -> Void

    public init(alert: EndorsementAlert, phase: Phase = .confirm, ink: Color? = nil,
                ground: Color? = nil, haptics: PairingHaptics? = nil,
                onRemove: @escaping () -> Void = {}, onKeep: @escaping () -> Void = {}) {
        self.alert = alert; self.phase = phase; self.ink = ink ?? krPaper; self.ground = ground ?? krTile
        self.haptics = haptics; self.onRemove = onRemove; self.onKeep = onKeep
    }

    public var body: some View {
        // One container, so the haptic modifiers attach once and not to each phase's view.
        ZStack {
            switch phase {
            case .requested:
                PhoneScreen(title: ScreenWords.requestedTitle, step: nil) {
                    PhoneBody(ScreenWords.requestedBody)
                    Spacer(minLength: 0)
                }
            case .failed:
                PhoneScreen(title: ScreenWords.failedTitle, step: nil) {
                    PhoneBody(ScreenWords.failedBody)
                    Spacer(minLength: 0)
                    PhoneButtons {
                        PrimaryButton(title: ScreenWords.revokeRemove, action: onRemove)
                        SecondaryButton(title: ScreenWords.revokeKeep, action: onKeep)
                    }
                }
            case .confirm:
                PhoneScreen(title: ScreenWords.revokeTitle, step: nil) {
                    Spacer(minLength: 0)
                    PatternSlot(pattern: alert.pattern, ink: ink, ground: ground, side: 260, tile: true)
                    PhoneBody(ScreenWords.revokeBody)
                    Spacer(minLength: 0)
                    PhoneButtons {
                        PrimaryButton(title: ScreenWords.revokeRemove, action: onRemove)
                        SecondaryButton(title: ScreenWords.revokeKeep, action: onKeep)
                    }
                }
            }
        }
        .onAppear { play(phase) }
        .onChange(of: phase) { play($0) }
    }

    private func play(_ phase: Phase) {
        switch phase {
        case .requested: (haptics ?? defaultPairingHaptics()).play(.removalRequested)
        case .failed:    (haptics ?? defaultPairingHaptics()).play(.removalFailed)
        case .confirm:   break
        }
    }
}
#endif
