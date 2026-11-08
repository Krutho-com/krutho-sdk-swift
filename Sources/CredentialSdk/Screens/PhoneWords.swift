import Foundation

/// The phone's words for the pairing screens (the approved words). The screens and `PhoneScreensTests` hold them verbatim.
extension ScreenWords {
    // MARK: Step strip
    static let phoneSteps = ["Scan", "Approve", "Finish"]

    // MARK: The scanner
    static let scanTitle           = "Scan your Mac"
    static let scanSubtitle        = "Point your camera at the pattern."
    static let scanCancel          = "Cancel"
    static let scanUseQR           = "Scan a QR instead"
    static let scanQRChosen        = "Point the camera at the QR on the Mac"
    static let readerSearching     = "Point at the pattern on your Mac"
    static let readerSearchingHint = "Fill the circle with the pattern."
    static let readerTooFar        = "Move closer"
    static let readerTooFarHint    = "Until the pattern fills the circle."
    static let readerTooClose      = "Move back a little"
    static let readerTooCloseHint  = "Until the whole pattern is inside the circle."
    /// The key keeps its old name; the words are the approved "Hold here".
    static let readerReading       = "Hold here"
    static let readerReadingHint   = "Reading. Hold until the ring is solid."
    static let readerReset         = "Hold still, starting again"
    static let readerResetHint     = "The read was interrupted. Keep the pattern in the circle."
    static let readerRead          = "Pattern read"
    static let readerReadHint      = "Checking with the server."
    static let readerCameraOff     = "Camera access is off. Turn it on in Settings."
    static let readerCameraOffBody = "Pairing uses the camera to read the pattern on your Mac. Nothing is recorded."
    static let readerOpenSettings  = "Open Settings"
    static let readerNoCamera      = "No camera is available."
    static let readerNoCameraBody  = "This device cannot read the pattern. Pair from an iPhone with a back camera."
    static let readerClose         = "Close"

    /// "3 of 8 pieces read".
    static func readerProgress(_ read: Int, of total: Int) -> String { "\(read) of \(total) pieces read" }

    // MARK: Screen 2 . Before Face ID
    /// What the approve screen calls the requesting device, from the server's attestation only: "Mac" for
    /// macosx, "iPhone" for iphoneos, "device" for anything else or no attestation. Never "Mac" by default:
    /// this is the consent screen.
    static func approveNoun(_ attestation: DeviceAttestationFacts?) -> String {
        switch attestation?.platform {
        case "macosx":   return "Mac"
        case "iphoneos": return "iPhone"
        default:         return "device"
        }
    }
    static func approveTitle(_ attestation: DeviceAttestationFacts?) -> String { "Pair this \(approveNoun(attestation))?" }
    static func approveSubtitle(_ attestation: DeviceAttestationFacts?) -> String {
        "Allow this \(approveNoun(attestation)) to act on your behalf."
    }
    static func approveBody(_ attestation: DeviceAttestationFacts?) -> String {
        "Only approve a \(approveNoun(attestation)) you recognize and are using."
    }
    static let approveYes   = "Approve with Face ID"
    static let approveNo    = "Cancel"
    static let askedJustNow = "asked just now"

    /// "Mac app · attested · asked just now" when the request is under 120 s old (or dated ahead of `now`),
    /// "Mac app · attested · asked HH:mm" otherwise. The kind words are `factLine`'s. An empty or unreadable
    /// `createdAt` (an older server) leaves the kind alone.
    static func askedLine(attestation: DeviceAttestationFacts?, createdAt: String, now: Date = Date(),
                          calendar: Calendar = .current) -> String {
        let kindWords = kind(attestation)
        guard let asked = parseDate(createdAt) else { return kindWords }
        if now.timeIntervalSince(asked) < 120 { return kindWords + " · " + askedJustNow }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = calendar
        f.timeZone = calendar.timeZone
        f.dateFormat = "HH:mm"
        return kindWords + " · asked " + f.string(from: asked)
    }

    /// "Requested just now" under 120 s (or dated ahead of `now`), "Requested at HH:mm" otherwise, nil for an
    /// empty or unreadable `createdAt`.
    static func requestedLine(createdAt: String, now: Date = Date(), calendar: Calendar = .current) -> String? {
        guard let asked = parseDate(createdAt) else { return nil }
        if now.timeIntervalSince(asked) < 120 { return "Requested just now" }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = calendar
        f.timeZone = calendar.timeZone
        f.dateFormat = "HH:mm"
        return "Requested at " + f.string(from: asked)
    }

    // MARK: Screen 3 . Verify
    static let confirmSubtitle = "Compare this pattern with the one on your Mac."

    // MARK: Screen 3 . the quiet third option when the pattern cannot be drawn
    static let confirmContinue = "Continue without checking"

    // MARK: After "Yes, it matches"
    static let waitingTitle = "Finish on your Mac"
    static let waitingSubtitle = "Use Touch ID on your Mac to complete pairing."
    static let waitingStatus = "Waiting for your Mac"
    /// Over the sett on "Finish on your Mac": the pattern assigned to the new device (no match is asked).
    static let waitingPatternLabel = "This Mac's pattern"
    /// The quiet way out when the person scanned another Mac's screen.
    static let waitingRemove = "Not my Mac? Remove it"
    static let waitingBody  = "Your iPhone will confirm when pairing is complete."
    static let waitingDone  = "Done"

    // MARK: After "No, remove it" answered .cancelled
    static let stoppedTitle = "Pairing stopped"
    static let stoppedBody  = "This Mac was not added. If you meant to pair the Mac in front of you, start again from the Mac."
    static let stoppedDone  = "Done"

    // MARK: Inspect or endorse refused on the transaction's state
    static let expiredTitle = "That pattern has expired"
    static let expiredBody  = "A pattern lasts ten minutes. Show a new one on the Mac and scan again."
    static let scanAgain    = "Scan again"
    static let macCancelledOnPhoneTitle = "Pairing was cancelled on the Mac"
    static let macCancelledOnPhoneBody  = "Nothing was added. Start again from the Mac if you meant to pair it."

    // MARK: An alert for a device that is already removed
    static let removedTitle = "This device was removed"
    /// Ends the fact line in place of "approved on …" (the listing carries no removal time).
    static let removedFact  = "removed"
    static let removedOK    = "OK"

    /// `<kind> · <when> · removed`: the alert's fact line for a device whose row is revoked.
    static func removedFactLine(attestation: DeviceAttestationFacts?, createdAt: String,
                                now: Date = Date(), calendar: Calendar = .current) -> String {
        var parts: [String] = [kind(attestation)]
        if let when = when(createdAt, now: now, calendar: calendar) { parts.append(when) }
        parts.append(removedFact)
        return parts.joined(separator: " · ")
    }
}
