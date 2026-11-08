import Foundation

/// The backup QR's text (the moving pattern is the pairing channel; the QR is a backup, off in
/// the UI unless the host opts in, because a static QR can be photographed and relayed). The QR is
/// `opened.qrPayload` as it is, the JSON `{"transactionId","origin"}`. Pure Foundation, so tests run it on the Mac.
public enum QRPairingLink {

    /// The pairing JSON for `endorsementInspect(qrPayload:)` from whatever the camera read: a JSON object whose
    /// `transactionId` is a non-empty string (the core checks the rest). nil for anything else.
    public static func qrPayload(fromScanned scanned: String) -> String? {
        let text = scanned.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix("{"),
              let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
              let id = object["transactionId"] as? String, !id.isEmpty else { return nil }
        return text
    }
}
