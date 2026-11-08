import Foundation
import AVFoundation
import QuartzCore
import Combine

/// The phone's side of optical pairing: opens the back camera, finds the finder ring near a guide at the frame
/// centre, decodes each frame (`OpticalDecode`), feeds the CRC-passing frames to the
/// collector, and hands the assembled payload to `onPayload` once: 24 bytes for a pairing pattern (version 1), 12 for a sign-in ring (version 2).
///
/// The reader never contacts the server and never calls the SDK core. The host owns the sequence: `start()`,
/// `onPayload`, `CredentialSdk.endorsementInspectOptical(payload:)`, its own screen 2, `endorse`. A refusal from the
/// SDK ends the attempt; a fresh collection only starts when the host calls `restart()` ("Scan again").
///
/// The backup QR is off unless the host sets `acceptsQR` before the first `start()`: the moving pattern is the
/// pairing channel, and a static QR can be photographed and relayed. With it on, the same camera session also looks
/// for a QR naming a transaction (`QRPairingLink.qrPayload(fromScanned:)`), but takes one only after the person
/// chooses it (`chooseQR()`, the scanner's "Scan a QR instead") in that run: a QR held to the camera never silently
/// replaces the pattern's key commitment. Whichever channel reads first then ends the run, and a QR goes to
/// `onQRPayload` for `CredentialSdk.endorsementInspect(qrPayload:)`.
///
/// Focus and exposure are never locked: a lock made reads worse in testing, so both stay on continuous auto.
/// Build the host in Release: the decoder's hot loops read at camera rate there, and a Debug build may read at
/// about two frames a second.
@available(iOS 15, *)
public final class OpticalPairingReader: ObservableObject {
    /// How the ring in view compares with the guide.
    public enum Fit: Equatable { case searching, tooFar, tooClose, reading }
    public enum Status: Equatable { case idle, scanning, complete, cameraDenied, cameraUnavailable }
    /// Why a collection was discarded.
    public enum ResetReason: String, CaseIterable {
        case conflict   // a held index arrived with a different value
        case idle       // no accepted frame for 1.5 s
        case age        // the collection is 5 s old and not complete
        case left       // the person left the scanner
    }

    /// One run's clock. All times are `CACurrentMediaTime()` seconds, so `complete - firstChunk` is the read time
    /// and `complete - runStarted` is scanner-open to payload. `firstChunk` is the first chunk stored in the run
    /// and is not cleared by a reset, so a read that restarted still reports from its first chunk.
    public struct Timing: Equatable {
        public let runStarted: TimeInterval          // CACurrentMediaTime() at start()/restart()
        public var firstChunk: TimeInterval?         // first stored chunk
        public var complete: TimeInterval?           // last chunk (eighth for version 1, fourth for version 2)
        public var resets: [ResetReason: Int]
    }

    @Published public private(set) var status: Status = .idle
    @Published public private(set) var fit: Fit = .searching
    @Published public private(set) var held: [Bool] = [Bool](repeating: false, count: OpticalFrame.chunkCount)
    @Published public private(set) var lastReset: ResetReason?
    @Published public private(set) var timing: Timing?
    /// Bumps once per processed camera frame, after `held`, `fit` and `timing` are all stored (not on the
    /// completing frame: that one is delivered by `status`). `snapshots` reads coherent state from it.
    @Published private(set) var frame = 0

    /// Called once per run, on the main thread, with the payload: 24 bytes (pairing, version 1) or 12 (sign-in, version 2);
    /// the length tells the host which door to call. The camera is already stopped.
    public var onPayload: ((Data) -> Void)?

    /// Read the backup QR too. Off by default; read when the camera is first set up, so set it before the first
    /// `start()` (a later change does not add or remove the QR reader).
    public var acceptsQR = false

    /// Called once per run, on the main thread, with the pairing JSON from a backup QR (only with `acceptsQR`). The
    /// camera is already stopped and `status` is `.complete`; `timing.complete` stays nil (no chunk completed it).
    public var onQRPayload: ((String) -> Void)?

    /// True once the person chose the QR in this run (`chooseQR()`); a new run clears it. Main thread.
    @Published public private(set) var qrChosen = false

    /// The run the person chose the QR in; `handleScannedCode` takes a QR only for that run. Guarded by `qrLock`
    /// because the camera queue reads it.
    private var qrArmedRun: Int?
    private let qrLock = NSLock()

    /// The person chose the backup QR ("Scan a QR instead"): from now until this run ends, a pairing QR the camera
    /// sees completes it. Does nothing without `acceptsQR` or outside a scanning run. Main thread.
    public func chooseQR() {
        onMain {
            guard self.acceptsQR, self.status == .scanning else { return }
            self.qrLock.lock(); self.qrArmedRun = self.runID; self.qrLock.unlock()
            self.qrChosen = true
        }
    }

    /// For a host's own preview layer.
    public let session = AVCaptureSession()

    private let loop = OpticalScanLoop()
    private let queue = DispatchQueue(label: "krutho.optical.camera", qos: .userInitiated)
    private let videoOutput = AVCaptureVideoDataOutput()
    private var sink: FrameSink?
    private let qrOutput = AVCaptureMetadataOutput()
    private var qrSink: QRSink?
    private var configured = false
    private var runID = 0
    /// Which run owns the camera. Read and written on `queue` only.
    private var cameraGate = OpticalCameraGate()

    public init() {}

    deinit {
        let s = session
        queue.async { if s.isRunning { s.stopRunning() } }
    }

    // MARK: Calls

    /// Asks for camera access if needed, opens the camera, starts a fresh collection. A no-op while scanning.
    public func start() {
        onMain {
            guard self.status != .scanning else { return }
            self.beginRun()
        }
    }

    /// The person leaves: a partial collection is discarded (counted as `.left`) and the camera stops.
    public func stop() {
        onMain {
            let out = self.loop.leave()
            self.stopCamera()
            guard self.status != .complete else { return }
            if let out, self.timing != nil { self.timing?.resets = out.resets }
            self.held = [Bool](repeating: false, count: OpticalFrame.chunkCount)
            self.fit = .searching
            self.status = .idle
        }
    }

    /// "Scan again": a fresh collection, camera on.
    public func restart() {
        onMain {
            _ = self.loop.leave()
            self.stopCamera()
            self.beginRun()
        }
    }

    // MARK: Run lifecycle (main thread)

    private func onMain(_ work: @escaping () -> Void) {
        if Thread.isMainThread { work() } else { DispatchQueue.main.async(execute: work) }
    }

    private func beginRun() {
        runID = loop.newRun()
        qrLock.lock(); qrArmedRun = nil; qrLock.unlock()
        qrChosen = false
        timing = Timing(runStarted: CACurrentMediaTime(), firstChunk: nil, complete: nil,
                        resets: Dictionary(uniqueKeysWithValues: ResetReason.allCases.map { ($0, 0) }))
        held = [Bool](repeating: false, count: OpticalFrame.chunkCount)
        fit = .searching
        lastReset = nil
        status = .scanning
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            runCamera()
        case .notDetermined:
            let id = runID
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    guard self.runID == id, self.status == .scanning else { return }
                    if granted { self.runCamera() } else { self.status = .cameraDenied }
                }
            }
        default:
            status = .cameraDenied
        }
    }

    private func runCamera() {
        let id = runID
        let wantsQR = acceptsQR
        queue.async {
            if !self.configured {
                guard self.configure(qr: wantsQR) else {
                    DispatchQueue.main.async {
                        guard self.runID == id, self.status == .scanning else { return }
                        self.status = .cameraUnavailable
                    }
                    return
                }
                self.configured = true
            }
            self.cameraGate.begin(id)
            if !self.session.isRunning { self.session.startRunning() }
        }
    }

    private func stopCamera() {
        queue.async {
            self.cameraGate.stopped()
            if self.session.isRunning { self.session.stopRunning() }
        }
    }

    /// Camera queue. 1080x1920 portrait luma frames, late frames dropped. No focus or exposure lock. With `qr`, a
    /// metadata output for QR codes on the same session too.
    private func configure(qr: Bool) -> Bool {
        session.beginConfiguration()
        defer { session.commitConfiguration() }
        session.sessionPreset = .hd1920x1080
        guard let dev = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: dev), session.canAddInput(input) else { return false }
        session.addInput(input)
        videoOutput.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange]
        videoOutput.alwaysDiscardsLateVideoFrames = true
        let sink = FrameSink(reader: self)
        self.sink = sink
        videoOutput.setSampleBufferDelegate(sink, queue: queue)
        guard session.canAddOutput(videoOutput) else { return false }
        session.addOutput(videoOutput)
        #if os(iOS)
        if let c = videoOutput.connection(with: .video) {
            if #available(iOS 17.0, *) { c.videoRotationAngle = 90 } else { c.videoOrientation = .portrait }
        }
        #endif
        if qr { addQROutput() }
        return true
    }

    /// Camera queue, inside `configure`. A camera that cannot read QR codes leaves the optical read as it is.
    private func addQROutput() {
        guard session.canAddOutput(qrOutput) else { return }
        session.addOutput(qrOutput)
        // The available types are known only once the output is on a session with an input.
        guard qrOutput.availableMetadataObjectTypes.contains(.qr) else {
            session.removeOutput(qrOutput)
            return
        }
        let sink = QRSink(reader: self)
        qrSink = sink
        qrOutput.setMetadataObjectsDelegate(sink, queue: queue)
        qrOutput.metadataObjectTypes = [.qr]
    }

    // MARK: Frames (camera queue)

    fileprivate func handleFrame(_ luma: OpticalLuma) {
        guard let out = loop.process(luma) else { return }
        let completes = out.events.contains { if case .complete = $0 { return true } else { return false } }
        if completes {
            // Stop the camera first (this block runs after the current callback returns), then tell the host.
            // A newer run may own the camera by now (restart, or stop then start); only the owner stops it.
            queue.async {
                if self.cameraGate.completes(out.run), self.session.isRunning { self.session.stopRunning() }
                DispatchQueue.main.async { self.apply(out) }
            }
        } else {
            DispatchQueue.main.async { self.apply(out) }
        }
    }

    /// A QR's text, on the camera queue. One that names a transaction ends the run like a completed optical read:
    /// the loop stops taking frames (so only one channel ever completes a run), the owner stops the camera, then the
    /// host hears.
    func handleScannedCode(_ text: String) {
        qrLock.lock(); let armed = qrArmedRun; qrLock.unlock()
        guard let armed, let json = QRPairingLink.qrPayload(fromScanned: text),
              let run = loop.finishOutOfBand(ifRun: armed) else { return }
        queue.async {
            if self.cameraGate.completes(run), self.session.isRunning { self.session.stopRunning() }
            DispatchQueue.main.async { self.applyQR(json, run: run) }
        }
    }

    // MARK: Results (main thread)

    /// One coherent view of the reader for the scanner: published on each processed frame and on each status
    /// change. The reader stores `held`, `fit` and `timing` one by one, so a subscriber to those would see
    /// half-updated states (for example, the eighth piece played .piece then .read).
    struct ScanSnapshot: Equatable {
        var status: Status
        var fit: Fit
        var held: [Bool]
        /// The sum of `timing.resets`, leaving out `.left` (the person closing is not a reset to warn about).
        var resets: Int
    }

    var snapshots: AnyPublisher<ScanSnapshot, Never> {
        // `$status` fires before its value is stored, so it carries the new status; everything else is read stored.
        Publishers.Merge($status.map { Optional($0) }, $frame.map { _ in nil })
            .compactMap { [weak self] status -> ScanSnapshot? in
                guard let self else { return nil }
                let resets = self.timing.map { $0.resets.filter { $0.key != .left }.values.reduce(0, +) } ?? 0
                return ScanSnapshot(status: status ?? self.status, fit: self.fit, held: self.held, resets: resets)
            }
            .eraseToAnyPublisher()
    }

    /// Tests only: a scanning run with this id and no camera, so `apply` accepts that run's outputs.
    func beginScanningForTesting(run: Int) {
        runID = run
        status = .scanning
    }

    /// Tests only: a scanning run the loop knows too, and no camera, so `handleScannedCode` can end it.
    func beginLoopRunForTesting() {
        runID = loop.newRun()
        qrLock.lock(); qrArmedRun = nil; qrLock.unlock()
        qrChosen = false
        status = .scanning
    }

    func applyQR(_ json: String, run: Int) {
        guard run == runID, status == .scanning else { return }
        status = .complete
        onQRPayload?(json)
    }

    func apply(_ out: OpticalScanLoop.Output) {
        guard out.run == runID, status == .scanning else { return }
        var payload: Data?
        for event in out.events {
            switch event {
            case .chunk(_, let t):
                if timing?.firstChunk == nil { timing?.firstChunk = t }
            case .reset(let reason, _):
                lastReset = reason
            case .complete(let data, let t):
                timing?.complete = t
                payload = data
            }
        }
        if held != out.held { held = out.held }
        if fit != out.fit { fit = out.fit }
        if timing?.resets != out.resets { timing?.resets = out.resets }
        if payload == nil { frame &+= 1 }
        if let payload {
            status = .complete
            onPayload?(payload)
        }
    }

    /// Receives the camera's sample buffers on the camera queue and copies the luma plane out.
    private final class FrameSink: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
        weak var reader: OpticalPairingReader?
        init(reader: OpticalPairingReader) { self.reader = reader }

        func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
            guard let reader, let pb = CMSampleBufferGetImageBuffer(sampleBuffer),
                  CVPixelBufferGetPlaneCount(pb) >= 1 else { return }
            CVPixelBufferLockBaseAddress(pb, .readOnly)
            defer { CVPixelBufferUnlockBaseAddress(pb, .readOnly) }
            guard let base = CVPixelBufferGetBaseAddressOfPlane(pb, 0) else { return }
            let w = CVPixelBufferGetWidthOfPlane(pb, 0), h = CVPixelBufferGetHeightOfPlane(pb, 0)
            let bpr = CVPixelBufferGetBytesPerRowOfPlane(pb, 0)
            var px = [UInt8](repeating: 0, count: w * h)
            px.withUnsafeMutableBufferPointer { dst in
                let src = base.assumingMemoryBound(to: UInt8.self)
                for y in 0..<h { (dst.baseAddress! + y * w).update(from: src + y * bpr, count: w) }
            }
            reader.handleFrame(OpticalLuma(width: w, height: h, pixels: px))
        }
    }

    /// Receives the metadata output's QR codes on the camera queue.
    private final class QRSink: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        weak var reader: OpticalPairingReader?
        init(reader: OpticalPairingReader) { self.reader = reader }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            guard let reader else { return }
            for case let code as AVMetadataMachineReadableCodeObject in metadataObjects where code.type == .qr {
                if let text = code.stringValue { reader.handleScannedCode(text) }
            }
        }
    }
}

/// Per-frame ring search and decode, feeding the 3a collector. Pure Swift (no camera), so tests drive it with
/// synthetic frames. `process` runs on the camera queue; `newRun`, `leave` and `resetCounts` may be called from
/// the main thread. The lock is never held across the search or the decode.
///
/// Adapted from the reference scanner: the guide ring at 0.70 of the shorter frame side
/// and the 0.55 to 0.90 "in the box" test are kept; the free-running counter and the seeded truth check are gone,
/// the frame's first byte is a header the collector splits.
@available(iOS 15, *)
final class OpticalScanLoop {
    static let targetShare = 0.70          // ring diameter as a share of the shorter frame side the guide asks for
    static let fitShare = 0.55...0.90      // ring shares counted as "in the box"

    typealias Fit = OpticalPairingReader.Fit
    typealias ResetReason = OpticalPairingReader.ResetReason

    enum Event: Equatable {
        case chunk(index: Int, t: Double)                       // a chunk was stored (also the new first chunk after a conflict)
        case reset(ResetReason, t: Double)
        case complete(Data, t: Double)
    }

    struct Output {
        var run: Int
        var events: [Event]
        var held: [Bool]
        var fit: Fit
        var ringShare: Double?
        var resets: [ResetReason: Int]
    }

    private let lock = NSLock()
    private let clock: () -> Double
    private var collector: OpticalCollector
    private var run = 0
    private var active = false
    /// Which polarity decoded last in this run, so the next frame tries it first (a steady scan costs one look a
    /// frame). false = light marks on a dark ground (today's pattern); true = dark marks on a light ground (a
    /// light-mode host). Guarded by `lock`; reset by `newRun`, so a run starts with the normal polarity.
    private var invertedFirst = false

    init(clock: @escaping () -> Double = { CACurrentMediaTime() }) {
        self.clock = clock
        collector = OpticalCollector(now: clock)
    }

    /// A fresh collection for a new run; frames process again. Returns the run's id.
    func newRun() -> Int {
        lock.lock(); defer { lock.unlock() }
        run += 1
        collector = OpticalCollector(now: clock)
        invertedFirst = false
        active = true
        return run
    }

    /// Another channel (the backup QR) read the run: frames stop processing. The run's id, or nil when no run is
    /// active (stopped, left, or already complete), so a run completes once whichever channel reads first.
    func finishOutOfBand(ifRun only: Int? = nil) -> Int? {
        lock.lock(); defer { lock.unlock() }
        guard active, only == nil || only == run else { return nil }
        active = false
        return run
    }

    /// The person left: a partial collection is discarded and counted, and frames stop processing.
    @discardableResult
    func leave() -> Output? {
        lock.lock(); defer { lock.unlock() }
        guard active else { return nil }
        active = false
        let t = clock()
        let r = collector.leave()
        return Output(run: run, events: r.map { [.reset($0, t: t)] } ?? [], held: collector.held, fit: .searching,
                      ringShare: nil, resets: counts())
    }

    func resetCounts() -> [ResetReason: Int] {
        lock.lock(); defer { lock.unlock() }
        return counts()
    }

    private func counts() -> [ResetReason: Int] {
        Dictionary(uniqueKeysWithValues: ResetReason.allCases.map { ($0, collector.resetCount($0)) })
    }

    /// One camera frame. nil when no run is active (stopped, complete, or left).
    func process(_ luma: OpticalLuma) -> Output? {
        var events: [Event] = []
        lock.lock()
        guard active, !collector.finished else { lock.unlock(); return nil }
        let id = run
        let startInverted = invertedFirst
        if let expired = collector.expire() { events.append(.reset(expired, t: clock())) }
        lock.unlock()

        let short = Double(min(luma.width, luma.height))
        let guide = OpticalGuide(cx: Double(luma.width) / 2, cy: Double(luma.height) / 2, r: 0.5 * Self.targetShare * short)
        // The pattern may be drawn inverted (dark marks on a light ground). Finding *a* ring proves nothing: an
        // inverted pattern's light band inside its dark ring passes the normal ring test and decodes to nothing.
        // So try the remembered polarity, and when it does not decode try the other; keep whichever decodes.
        func look(_ l: OpticalLuma) -> (fit: Fit, share: Double?, decoded: OpticalDecodeResult?, found: Bool) {
            guard let ring = opticalAcquireRing(l, guide: guide) else { return (.searching, nil, nil, false) }
            let ratio = ring.w / short
            let fit: Fit = Self.fitShare.contains(ratio) ? .reading : (ratio < Self.fitShare.lowerBound ? .tooFar : .tooClose)
            return (fit, (ratio * 100).rounded() / 100, fit == .reading ? opticalDecode(l, init: ring) : nil, true)
        }
        var pick = look(startInverted ? luma.inverted() : luma)
        var pickedInverted = startInverted
        if pick.decoded?.ok != true {
            let other = look(startInverted ? luma : luma.inverted())
            if other.decoded?.ok == true || !pick.found {
                pick = other
                pickedInverted = !startInverted
            }
        }
        let fit = pick.fit
        let share = pick.share
        let decoded = pick.decoded

        lock.lock(); defer { lock.unlock() }
        guard active, run == id else { return nil }   // a new run or a stop landed while this frame was in the decoder
        if let d = decoded, d.ok {
            invertedFirst = pickedInverted
            let at = clock()
            switch collector.accept(byte0: Int(d.header), value: Int(d.value)) {
            case .stored(let i): events.append(.chunk(index: i, t: at))
            case .restarted(let i):
                events.append(.reset(.conflict, t: at)); events.append(.chunk(index: i, t: at))
            case .complete(let data):
                events.append(.complete(data, t: at))
                active = false
            case .repeated, .rejected, .stopped: break
            }
        }
        return Output(run: id, events: events, held: collector.held, fit: fit, ringShare: share, resets: counts())
    }
}

/// Which scan run owns the camera, so a finished run cannot stop a newer run's camera.
/// Every call happens on the reader's camera queue, in the order the lifecycle actions were queued.
struct OpticalCameraGate {
    private(set) var owner: Int?

    /// The camera starts (or keeps running) for `run`.
    mutating func begin(_ run: Int) { owner = run }

    /// The host stopped the camera; no run owns it.
    mutating func stopped() { owner = nil }

    /// `run` collected its payload. True when it still owns the camera and should stop it.
    mutating func completes(_ run: Int) -> Bool {
        guard owner == run else { return false }
        owner = nil
        return true
    }
}
