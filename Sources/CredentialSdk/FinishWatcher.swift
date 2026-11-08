import Foundation

/// Polls the endorsement transaction's status while `endorsementFinish()` waits on the person's biometric, and
/// calls `onEnded` once when the row is cancelled (the phone answered "No") or expired, so the SDK can withdraw
/// the Touch ID prompt. The core is single threaded and blocked in that wait, hence a native poll with the same
/// request (`__sdk_endorsement_status_request_async`). Poll errors are ignored: the server still refuses the
/// finish, the watcher only shortens the wait.
final class FinishWatcher {
    typealias FetchStatus = () async -> String?

    private let fetchStatus: FetchStatus
    private let interval: TimeInterval
    private let onEnded: () -> Void
    private let lock = NSLock()
    private var task: Task<Void, Never>?
    private var ended: String?

    init(interval: TimeInterval = 1.0, fetchStatus: @escaping FetchStatus, onEnded: @escaping () -> Void) {
        self.interval = interval; self.fetchStatus = fetchStatus; self.onEnded = onEnded
    }

    /// "cancelled" or "expired" once the watcher has seen the row end; nil otherwise.
    var endedState: String? {
        lock.lock(); defer { lock.unlock() }
        return ended
    }

    func start() {
        task = Task.detached { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if let status = await self.fetchStatus(), status == "cancelled" || status == "expired" {
                    self.markEnded(status)
                    self.onEnded()
                    return
                }
                try? await Task.sleep(nanoseconds: UInt64(self.interval * 1_000_000_000))
            }
        }
    }

    func stop() { task?.cancel() }

    private func markEnded(_ status: String) {
        lock.lock(); ended = status; lock.unlock()
    }

    /// The status poll's bound, idle and whole-resource: the watcher only shortens the wait, so a slow poll is dropped.
    static let pollTimeout: TimeInterval = 5

    /// A watcher for the core's `{url, authorization}` request JSON, polling through `http`: the SDK's configured
    /// transport, never a session of its own. The bearer therefore travels
    /// only through the session the integrator configured, its delegate (TLS pinning) still answers challenges, and a
    /// redirect is refused: a 3xx is not a 200, so the watcher ignores it like any other poll error.
    static func forStatusRequest(_ json: String, http: URLSessionHttp, onEnded: @escaping () -> Void) -> FinishWatcher? {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let urlString = obj["url"] as? String, let url = URL(string: urlString),
              let authorization = obj["authorization"] as? String else { return nil }
        return FinishWatcher(fetchStatus: {
            guard let (status, body) = await http.statusPoll(url: url, authorization: authorization, timeout: pollTimeout),
                  status == 200,
                  let reply = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return nil }
            return reply["status"] as? String
        }, onEnded: onEnded)
    }
}
