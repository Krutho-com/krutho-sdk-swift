import Foundation

/// The two `URLSessionDataTask` members `run(_:)` actually calls. Exists so
/// a test can substitute a fake task (see `URLSessionHttpTaskFactory`)
/// without needing that fake to conjure a real, unattached
/// `URLSessionDataTask` — its initializers are not public, so only a real
/// `URLSession` can ever produce one. Internal: never exposed outside this
/// module.
protocol URLSessionHttpTask {
    func resume()
    func cancel()
}
extension URLSessionDataTask: URLSessionHttpTask {}

/// Seam for tests: the one piece of `URLSession` `run(_:)` actually calls
/// to start a request. Named `httpDataTask`, not `dataTask`, so the
/// `extension` below is an explicit wrapper around the real
/// `URLSession.dataTask(with:completionHandler:)` rather than an attempt
/// to have that method serve as the protocol witness directly — Swift
/// requires a witness's declared type to match the requirement exactly,
/// and the real method returns the concrete `URLSessionDataTask` (and, on
/// newer SDKs, takes a `@Sendable` closure) where this requires the
/// existential `URLSessionHttpTask` (and a plain `@escaping` closure); an
/// explicit wrapper body converts between them instead. Production
/// default is that real wrapped call. A test can substitute a fake that
/// RETAINS the completion handler instead of invoking it, to
/// deterministically control when (or whether) a "late" response arrives
/// — something a real `URLProtocol`-backed session cannot reliably
/// simulate once a task has been cancelled (`URLSession` may drop
/// protocol events after that). Internal: never exposed outside this
/// module.
protocol URLSessionHttpTaskFactory {
    func httpDataTask(
        for request: URLRequest,
        completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionHttpTask
}
extension URLSession: URLSessionHttpTaskFactory {
    func httpDataTask(
        for request: URLRequest,
        completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionHttpTask {
        dataTask(with: request, completionHandler: completionHandler)
    }
}

/// The build-gate header (A5 batch B): the app's `CFBundleVersion`, sent on the ring handle lookup alone.
let appBuildHeader = "X-Krutho-App-Build"

/// Refuses every redirect and forwards everything else to the delegate the integrator gave the original session.
/// Every request goes to the URL the core named and nowhere else: a 3xx comes back to the caller as the final
/// response (status 3xx), which the core reads as a refusal, and neither a header (`appBuildHeader` included) nor a
/// body (a signed presentation POST) reaches a redirect target on this host or another. The refusal does not depend
/// on any header the request carries.
///
/// The one-shot session that runs each request would otherwise drop an injected delegate, and with it any TLS
/// pinning done in an authentication-challenge callback. So this class implements only the redirect callback and
/// forwards every other selector the original delegate answers (`responds(to:)` and `forwardingTarget(for:)`), at
/// session and task level alike: the challenge reaches the integrator's delegate exactly as on an ordinary request.
final class RefuseRedirects: NSObject, URLSessionTaskDelegate {
    /// The original session's delegate, or nil when it had none.
    let original: URLSessionDelegate?

    init(forwardingTo original: URLSessionDelegate?) {
        self.original = original
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    /// The one-shot session ending is not the integrator's session ending: answered here, never forwarded, so an
    /// integrator delegate that reacts to "my session became invalid" is not told once per request.
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {}

    override func responds(to aSelector: Selector!) -> Bool {
        if super.responds(to: aSelector) { return true }
        return (original as AnyObject?)?.responds(to: aSelector) ?? false
    }

    override func forwardingTarget(for aSelector: Selector!) -> Any? {
        if let original = original as AnyObject?, original.responds(to: aSelector) { return original }
        return super.forwardingTarget(for: aSelector)
    }
}

/// What `URLSessionHttp.fetch(method:url:headers:body:)` throws.
public enum URLSessionHttpError: Error, Equatable, LocalizedError {
    /// The request did not complete: no connection, a timeout, a malformed request. The core reads it as
    /// `network_unreachable`.
    case transport(String)
    /// The server answered with a redirect (301, 302, 303, 307 or 308) and the client refused to follow it. Nothing
    /// was sent to `location`. A refusal, not a transport failure: the core must not retry it as one.
    case redirectRefused(status: Int, location: String?)

    public var errorDescription: String? {
        switch self {
        case .transport(let detail):
            return detail
        case .redirectRefused(let status, let location):
            return "redirect refused: HTTP \(status)" + (location.map { " to \($0)" } ?? "")
        }
    }
}

/// Synchronous URLSession-backed HTTP client for the SDK's Platform interface.
///
/// Threading: the caller (the JS thread) blocks on a `DispatchSemaphore`
/// while `URLSession` drives the request on its own delegate queue. Do not
/// call this from `URLSession`'s delegate thread or you will deadlock.
public final class URLSessionHttp {

    /// Whole-request bound: a stalled or slow-drip server must not hold the
    /// JS thread past this (see the class comment above). Covers `fetch`
    /// and `fetchBinary` alike, since both funnel through `run(_:)`. For
    /// `fetchBinary`, this is also the bound on the whole download, not
    /// just its first byte — fine for snapshot filters, which
    /// are small; a multi-MB filter on a slow link would need a larger
    /// bound for that fetch specifically, which this change does not add.
    static let requestTimeout: TimeInterval = 60

    private let session: URLSession
    /// A test's substitute for starting requests; nil means `session` (or, for a gated request, a one-shot copy of it).
    private let customTaskFactory: URLSessionHttpTaskFactory?
    private let semaphoreTimeout: TimeInterval
    /// True only for the session this class built itself (the no-arg
    /// `init()` below) — never for one a caller injected. Governs whether
    /// `deinit` invalidates `session`: doing that to a caller-owned session
    /// would cancel work the caller may still expect to use elsewhere.
    private let ownsSession: Bool

    /// A dedicated session (never `.shared`, which cannot be reconfigured)
    /// whose request and resource timeouts are both `requestTimeout`.
    /// Internal, not `private`: `URLSessionHttpTests` calls this directly
    /// to pin the production session's actual configuration.
    static func makeDefaultSession() -> URLSession {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = requestTimeout
        config.timeoutIntervalForResource = requestTimeout
        return URLSession(configuration: config)
    }

    public convenience init() {
        self.init(session: Self.makeDefaultSession(), semaphoreTimeout: Self.requestTimeout, ownsSession: true)
    }

    /// The injected session's configuration is unchanged, but each request
    /// has a 60-second idle timeout and the semaphore enforces a
    /// 60-second fallback before cancellation. This class never
    /// invalidates an injected session (see `ownsSession`).
    public convenience init(session: URLSession) {
        self.init(session: session, semaphoreTimeout: Self.requestTimeout, ownsSession: false)
    }

    /// Designated initializer. Test-only entry points (see
    /// `URLSessionHttpTests`):
    /// - `semaphoreTimeout` lets a test shorten the semaphore's fallback
    ///   bound so a stall test does not have to wait out the production
    ///   bound. `session` is still whatever the caller passes
    ///   (production's dedicated session, or a test's stub `URLProtocol`
    ///   on an ephemeral configuration); `ownsSession` defaults to `false`
    ///   here too, since every test-only caller injects a session it
    ///   manages itself.
    /// - `taskFactory` lets a test substitute a fake in place of `session`
    ///   itself for starting requests (see `URLSessionHttpTaskFactory`'s
    ///   doc comment); `nil` (the default, and every non-test caller's
    ///   choice) means `run(_:)` calls `session` directly, as before.
    init(
        session: URLSession,
        semaphoreTimeout: TimeInterval,
        ownsSession: Bool = false,
        taskFactory: URLSessionHttpTaskFactory? = nil
    ) {
        self.session = session
        self.semaphoreTimeout = semaphoreTimeout
        self.ownsSession = ownsSession
        self.customTaskFactory = taskFactory
    }

    /// What makes two `URLSessionHttp` objects one transport policy: the default session this class builds (its
    /// timeouts and no delegate) is the same everywhere; an injected session (which may carry a pinning delegate or
    /// a custom configuration) is the same only as itself, and so is a test's task factory. The Rust engine shares
    /// one core between SDKs only when this matches (`RustEngine.engine`).
    var sharingIdentity: String {
        if customTaskFactory != nil { return "factory:\(ObjectIdentifier(self).hashValue)" }
        let timeout = "timeout=\(semaphoreTimeout)"
        if ownsSession { return "default:\(timeout)" }
        return "session:\(ObjectIdentifier(session).hashValue):\(timeout)"
    }

    deinit {
        if ownsSession {
            session.finishTasksAndInvalidate()
        }
    }

    public func fetch(requestJson: String) -> String {
        guard let req = Self.buildRequest(requestJson: requestJson) else {
            return Self.encodeResponse(status: 0, headers: [:], body: "invalid requestJson")
        }

        let (status, headers, data) = run(req)
        // Text path (JSON request/response bodies, the SDK's default
        // transport): decoded as UTF-8, same as always. A response that is
        // not valid UTF-8 here would previously have silently become "" —
        // that gap is why fetchBinary exists below.
        let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        return Self.encodeResponse(status: status, headers: headers, body: body)
    }

    /// Byte-safe counterpart of `fetch`: the response body
    /// crosses the bridge as base64 of the EXACT bytes received, never
    /// text-decoded — `fetch`'s `String(data:encoding:.utf8)` returns `nil`
    /// (silently emptying the body) for any response that is not valid
    /// UTF-8, which a cascade filter of any real size essentially never is.
    /// The JSON-text request and response shape is the one SDK v1's
    /// JavaScript bridge used; the Rust core's transport adapter calls
    /// `fetch(method:url:headers:body:)` instead (`CoreAdapters.swift`).
    public func fetchBinary(requestJson: String) -> String {
        guard let req = Self.buildRequest(requestJson: requestJson) else {
            return Self.encodeBinaryResponse(status: 0, headers: [:], bodyBase64: "")
        }
        let (status, headers, data) = run(req)
        let bodyBase64 = data.map { $0.base64EncodedString() } ?? ""
        return Self.encodeBinaryResponse(status: status, headers: headers, bodyBase64: bodyBase64)
    }

    /// A response from the typed entry points. Headers are in no particular order (`URLSession` reports them as a dictionary).
    public struct Response {
        public let status: Int
        public let headers: [(name: String, value: String)]
        public let body: Data
    }

    /// The typed form of `fetch`, for the native adapter interface: the request as parts, the
    /// response as bytes (decode them as text or keep them as binary, one call serves `fetch` and `fetch_binary`).
    /// Throws `URLSessionHttpError.transport` where the string form answers status 0, and
    /// `URLSessionHttpError.redirectRefused` where it answers the 3xx.
    public func fetch(method: String, url: String, headers: [(name: String, value: String)] = [],
                      body: String? = nil) throws -> Response {
        guard let target = URL(string: url) else {
            throw URLSessionHttpError.transport("invalid url")
        }
        var req = URLRequest(url: target)
        req.httpMethod = method
        req.timeoutInterval = Self.requestTimeout
        for (name, value) in headers { req.setValue(value, forHTTPHeaderField: name) }
        if let body, !body.isEmpty { req.httpBody = body.data(using: .utf8) }

        let (status, responseHeaders, data) = run(req)
        if status == 0 {
            throw URLSessionHttpError.transport(data.flatMap { String(data: $0, encoding: .utf8) } ?? "network error")
        }
        if Self.redirectStatuses.contains(status) {
            let location = responseHeaders.first { $0.key.lowercased() == "location" }?.value
            throw URLSessionHttpError.redirectRefused(status: status, location: location)
        }
        return Response(status: status,
                        headers: responseHeaders.map { (name: $0.key, value: $0.value) },
                        body: data ?? Data())
    }

    /// The statuses a client follows by default; each is refused here.
    static let redirectStatuses: Set<Int> = [301, 302, 303, 307, 308]

    /// Shared request construction: `{ url, method, headers?, body? }` — the
    /// same parse `fetch` always did, factored out so `fetchBinary` builds
    /// an identical request (a device JWT differs per call regardless).
    private static func buildRequest(requestJson: String) -> URLRequest? {
        guard let reqData = requestJson.data(using: .utf8),
              let reqDict = (try? JSONSerialization.jsonObject(with: reqData)) as? [String: Any],
              let urlStr  = reqDict["url"] as? String,
              let url     = URL(string: urlStr)
        else {
            return nil
        }

        var req = URLRequest(url: url)
        req.httpMethod = (reqDict["method"] as? String) ?? "GET"
        // Set here too, not only on the session's configuration: a caller
        // that injects its own session (tests; any future host app) gets
        // the same idle-timeout bound on every request regardless of that
        // session's own configuration.
        req.timeoutInterval = requestTimeout

        if let headers = reqDict["headers"] as? [String: String] {
            for (k, v) in headers {
                req.setValue(v, forHTTPHeaderField: k)
            }
        }
        if let body = reqDict["body"] as? String, !body.isEmpty {
            req.httpBody = body.data(using: .utf8)
        }
        return req
    }

    /// Runs one request to completion, blocking the caller (see the class
    /// comment). Returns the raw response bytes uninterpreted — callers
    /// decide whether to read them as UTF-8 text (`fetch`) or base64
    /// (`fetchBinary`). `data` is `nil` only on a transport-level failure
    /// (status 0); a successful zero-length body comes back as `Data()`.
    private func run(_ req: URLRequest) -> (status: Int, headers: [String: String], data: Data?) {
        let sem = DispatchSemaphore(value: 0)
        var captured: (status: Int, headers: [String: String], data: Data?) = (0, [:], nil)

        // Every request runs on a one-shot session with the same configuration (so the same protocols, timeouts and
        // cookies) whose delegate refuses redirects and forwards the rest to the original session's delegate. The
        // session the caller gave cannot be changed, so none of its requests may follow a redirect through it.
        let refusingSession = customTaskFactory == nil ? makeRefusingSession() : nil
        defer { refusingSession?.finishTasksAndInvalidate() }
        let factory: URLSessionHttpTaskFactory = customTaskFactory ?? refusingSession ?? session

        let task = factory.httpDataTask(for: req) { data, response, error in
            defer { sem.signal() }
            if let error = error {
                let msg = "network error: \(error.localizedDescription)"
                captured = (0, [:], Data(msg.utf8))
                return
            }
            let http = response as? HTTPURLResponse
            let headers: [String: String] = http.map { resp in
                var out: [String: String] = [:]
                for (k, v) in resp.allHeaderFields {
                    out[String(describing: k)] = String(describing: v)
                }
                return out
            } ?? [:]
            captured = (http?.statusCode ?? 0, headers, data ?? Data())
        }
        task.resume()

        // `semaphoreTimeout` matches the production session's own
        // `requestTimeout` (both `requestTimeout`, `makeDefaultSession()`
        // above), so in production this and `URLSession`'s own timeout are
        // racing to fire at essentially the same moment — whichever wins,
        // the result is the same status-0 shape, so which one actually
        // fires does not matter. Where it does matter: a caller-injected
        // session (`init(session:)`) whose own configuration was not built
        // with `requestTimeout` — there, this is the only bound. Either
        // way, on a timeout here: cancel the task and return that shape —
        // a timed-out request must not surface as anything new. `task`'s
        // completion handler still runs later, off of the cancellation,
        // and signals `sem` then, but nothing is waiting on it by that
        // point.
        if sem.wait(timeout: .now() + semaphoreTimeout) == .timedOut {
            task.cancel()
            let msg = "network error: request exceeded \(Int(semaphoreTimeout))s bound"
            return (0, [:], Data(msg.utf8))
        }

        return captured
    }

    /// A one-shot session with the configured session's configuration (so its protocols, timeouts and cookies) whose
    /// delegate refuses redirects and forwards the rest to the configured session's delegate. `resourceTimeout`, when
    /// given, also caps the whole-resource time; `session.configuration` returns a copy, so the configured session
    /// itself never changes.
    private func makeRefusingSession(resourceTimeout: TimeInterval? = nil) -> URLSession {
        let config = session.configuration
        if let resourceTimeout {
            config.timeoutIntervalForResource = min(config.timeoutIntervalForResource, resourceTimeout)
        }
        return URLSession(configuration: config,
                          delegate: RefuseRedirects(forwardingTo: session.delegate),
                          delegateQueue: session.delegateQueue)
    }

    /// The finish watcher's status poll (`FinishWatcher.forStatusRequest`): one GET under the transaction's bearer, on
    /// this transport and nowhere else. Like every request here it runs on a
    /// one-shot copy of the configured session that keeps the integrator's delegate (TLS pinning in a challenge
    /// callback reaches it) and refuses redirects: a 3xx comes back as the status. Unlike `fetch` it is async and
    /// bounded by `timeout` (idle and whole-resource), so a stalled server cannot hold the poll past the watcher's
    /// interval. Cancelling the calling task cancels the request. Nil on a transport failure.
    func statusPoll(url: URL, authorization: String, timeout: TimeInterval) async -> (status: Int, body: Data)? {
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = timeout
        req.setValue(authorization, forHTTPHeaderField: "Authorization")
        let refusingSession = customTaskFactory == nil ? makeRefusingSession(resourceTimeout: timeout) : nil
        defer { refusingSession?.finishTasksAndInvalidate() }
        let factory: URLSessionHttpTaskFactory = customTaskFactory ?? refusingSession ?? session
        let running = RunningTask()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<(status: Int, body: Data)?, Never>) in
                let task = factory.httpDataTask(for: req) { data, response, error in
                    guard error == nil, let http = response as? HTTPURLResponse else {
                        continuation.resume(returning: nil)
                        return
                    }
                    continuation.resume(returning: (http.statusCode, data ?? Data()))
                }
                running.set(task)
                task.resume()
            }
        } onCancel: {
            running.cancel()
        }
    }

    /// The poll's task, cancellable from `withTaskCancellationHandler`'s handler, which may run before the task exists.
    private final class RunningTask {
        private let lock = NSLock()
        private var task: URLSessionHttpTask?
        private var cancelled = false

        func set(_ task: URLSessionHttpTask) {
            lock.lock()
            self.task = task
            let cancel = cancelled
            lock.unlock()
            if cancel { task.cancel() }
        }

        func cancel() {
            lock.lock()
            cancelled = true
            let task = self.task
            lock.unlock()
            task?.cancel()
        }
    }

    private static func encodeResponse(status: Int, headers: [String: String], body: String) -> String {
        let dict: [String: Any] = [
            "status":  status,
            "headers": headers,
            "body":    body
        ]
        let data = try! JSONSerialization.data(withJSONObject: dict, options: [])
        return String(data: data, encoding: .utf8)!
    }

    private static func encodeBinaryResponse(status: Int, headers: [String: String], bodyBase64: String) -> String {
        let dict: [String: Any] = [
            "status":     status,
            "headers":    headers,
            "bodyBase64": bodyBase64
        ]
        let data = try! JSONSerialization.data(withJSONObject: dict, options: [])
        return String(data: data, encoding: .utf8)!
    }
}
