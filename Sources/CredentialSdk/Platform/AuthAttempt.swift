import Foundation
import LocalAuthentication

/// What a waiting signature can be withdrawn through: its `LAContext`, or a fake in tests.
protocol PendingAuthentication: AnyObject {
    func invalidate()
}

extension LAContext: PendingAuthentication {}

/// One `endorsementFinish()` attempt's authority to withdraw its Touch ID prompt.
/// `markCancelled` latches the cancellation; `end` takes the authority away for good, so a watcher's poll that
/// returns after the attempt cannot cancel a later signature.
final class AuthAttempt {
    private let lock = NSLock()
    private var cancelled = false
    private var ended = false

    var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    /// False once the attempt has ended: nothing is cancelled.
    func markCancelled() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if ended { return false }
        cancelled = true
        return true
    }

    func end() {
        lock.lock(); ended = true; lock.unlock()
    }
}
