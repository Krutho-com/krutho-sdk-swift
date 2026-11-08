import Foundation

/// The approved words of the pairing screens (`screen-words.html`, approved
/// with two edits: screen 4's "Check that your iPhone shows the same
/// pattern", and screen 7 split into success and failure). Kept in one place
/// so a test can hold the screens to them verbatim.
enum ScreenWords {
    // MARK: Screen 1 . Mac . Pairing pattern (approved words)
    static let macPairTitle   = "Scan to pair this Mac"
    static let macPairSubtitle = "Hold your iPhone up to the pattern."
    static let macPairBody    = "Keep this window visible while your iPhone approves this Mac."

    // MARK: Screens 3 to 7 . approved earlier
    // 3 . iPhone . After Face ID
    static let confirmTitle   = "Do the patterns match?"
    static let confirmBody    = "Confirm only if both patterns are identical."
    static let confirmYes     = "Yes, they match"
    static let confirmNo      = "No, remove this Mac"

    // 4 . Mac . After finish
    static let macTitle       = "This Mac is endorsed"
    static let macBody        = "This is this Mac's pattern. You'll see it next to this Mac in your devices list."

    // 5 . Every phone . The alert
    static let alertTitle     = "A new device can act as you"
    static let alertMe        = "That was me"
    static let alertNotMe     = "Not me"

    // 6 . iPhone . Not me, before Face ID
    static let revokeTitle    = "Remove this device?"
    static let revokeBody     = "Services stop accepting it once they update their list. What it already did stays done."
    static let revokeRemove   = "Remove with Face ID"
    static let revokeKeep     = "Keep it"

    // 7 . After the request
    static let requestedTitle = "Removal requested"
    static let requestedBody  = "Services stop accepting this device once they update."

    // 7b . If the request fails
    static let failedTitle    = "Couldn't remove it"
    static let failedBody     = "The alert stays so you can try again."

    // MARK: The Mac window (approved words)
    static let macWindowTitle = "Pair this Mac"
    static let macSteps       = ["Scan with iPhone", "Approve on iPhone", "Finish with Touch ID"]
    static let macOpenHint    = "Open the app on your iPhone and choose Add a Mac."
    static let macWaiting     = "Waiting for iPhone approval"
    static let macFinishing   = "Waiting for Touch ID"
    static let macCancel      = "Cancel"
    static let macApprovedTitle = "Your iPhone approved this Mac"
    static let macApprovedBody  = "Finish with Touch ID to add it to your devices."
    static let macTouchIDFailedTitle = "Touch ID didn't complete"
    static let macTouchIDFailedBody  = "This Mac is approved but not yet added. Try again."
    static let macFinish      = "Finish with Touch ID"
    static let macDone        = "Done"
    static let macNotPairedTitle = "Not paired"
    static let macNotPairedBody  = "Your iPhone reported that the patterns did not match, so this Mac was not added. Start again when you are ready."
    static let macTryAgain    = "Try again"
    static let macClose       = "Close"
    static let macExpiredTitle = "This pattern has expired"
    static let macExpiredBody  = "A pattern lasts ten minutes. Nothing was added."
    static let macShowNewPattern = "Show a new pattern"
    static let macCancelledTitle = "Pairing cancelled"
    static let macCancelledBody  = "Nothing was added."
    static let macStartAgain  = "Start again"
    // The backup QR's quiet link, only when the host opts in (qrFallbackPayload)
    static let macWontScan    = "Won't scan?"
    static let macShowPattern = "Show the pattern"

    /// "Expires in 9:41": whole minutes and zero-padded seconds, floored at "0:00".
    static func macExpiresIn(_ remaining: TimeInterval) -> String {
        let total = Int(max(0, remaining))
        return "Expires in \(total / 60):" + (total % 60 < 10 ? "0" : "") + "\(total % 60)"
    }

    /// "Added today 09:41" (via `when`), or "Added <short date>" on another day.
    static func macAdded(_ date: Date, now: Date = Date(), calendar: Calendar = .current) -> String {
        "Added " + when(date, now: now, calendar: calendar)
    }

    // Fallback
    static let unavailableTitle = "Pattern unavailable"
    static let unavailableBody  = "Update the app to see this device's pattern. Pairing still works."

    // Fact line parts (screen 5)
    static let unknownKind    = "type unknown, not attested"
    static let macKind        = "Mac app · attested"
    static let iphoneKind     = "iPhone app · attested"
    static let approvedHere   = "approved on this iPhone"
    static let approvedElsewhere = "approved on another iPhone"

    /// `<kind> · <attested> · <when> · approved on this iPhone` (or "another
    /// iPhone"). `macosx` reads "Mac app · attested", `iphoneos` "iPhone app ·
    /// attested", no attestation "type unknown, not attested". `when` is
    /// "today HH:mm" for the date of `now` and the short date otherwise.
    static func factLine(attestation: DeviceAttestationFacts?, createdAt: String, isThisDevice: Bool,
                         now: Date = Date(), calendar: Calendar = .current) -> String {
        var parts: [String] = [kind(attestation)]
        if let when = when(createdAt, now: now, calendar: calendar) { parts.append(when) }
        parts.append(isThisDevice ? approvedHere : approvedElsewhere)
        return parts.joined(separator: " · ")
    }

    static func kind(_ attestation: DeviceAttestationFacts?) -> String {
        switch attestation?.platform {
        case "macosx":   return macKind
        case "iphoneos": return iphoneKind
        case nil:        return unknownKind
        // An attested device of a platform this build has no word for.
        default:         return "type unknown · attested"
        }
    }

    static func parseDate(_ iso: String) -> Date? {
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = withFraction.date(from: iso) { return d }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: iso)
    }

    static func when(_ iso: String, now: Date, calendar: Calendar) -> String? {
        guard let date = parseDate(iso) else { return nil }
        return when(date, now: now, calendar: calendar)
    }

    static func when(_ date: Date, now: Date, calendar: Calendar) -> String {
        if calendar.isDate(date, inSameDayAs: now) {
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.calendar = calendar
            f.timeZone = calendar.timeZone
            f.dateFormat = "HH:mm"
            return "today " + f.string(from: date)
        }
        let f = DateFormatter()
        f.calendar = calendar
        f.timeZone = calendar.timeZone
        f.dateStyle = .short
        f.timeStyle = .none
        return f.string(from: date)
    }
}
