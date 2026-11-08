import Foundation

extension CredentialSdkError {
    /// The transaction state a 409 `transaction_state` refusal names ("cancelled", "expired", "authorized",
    /// "consumed"), lowercased, or nil for any other error. The core sends the reason as
    /// "transaction_state: <state>", and the finish route "not finishable (<state>)"; the last word, without
    /// brackets or punctuation, is the state. `PairingRefusedScreen` takes "expired" and "cancelled"; the other states are the host's own error.
    public var transactionState: String? {
        guard case let .endorsementRefused(code, reason) = self, code == "transaction_state", let reason else {
            return nil
        }
        let prefix = "transaction_state:"
        let tail = reason.hasPrefix(prefix) ? String(reason.dropFirst(prefix.count)) : reason
        // The finish route says "not finishable (cancelled)": take the last word without its brackets.
        guard let last = tail.split(whereSeparator: { $0.isWhitespace }).last else { return nil }
        let word = last.trimmingCharacters(in: CharacterSet(charactersIn: "()[].,:;"))
        return word.isEmpty ? nil : word.lowercased()
    }
}
