import Foundation
#if canImport(SwiftUI)
import SwiftUI

/// The scanner's overlay without the camera: the dimmer outside the circle, the eight-segment ring, the logo and
/// close cross, the stepper (Scan · Approve · Verify) and "Scan your Mac" at the top, and the reader's words, the
/// progress line and "Cancel" at the bottom; for
/// `.cameraDenied` and `.cameraUnavailable` it is the full black screen with "Open Settings" (camera off only)
/// and "Close". For hosts with their own preview, and for render tests on macOS. The ring sits at the centre of
/// the view, where the reader's guide is.
///
/// The ring: searching is dashed and dim, too far or too close dashed and bright, reading is eight orange segments
/// that fill as the pieces arrive, and solid orange is read. `onClose` and `onOpenSettings` nil hide their buttons.
@available(iOS 15, macOS 13, *)
public struct OpticalScannerOverlay: View {
    let output: OpticalScannerPresenter.Output
    let status: OpticalPairingReader.Status
    let ringDiameter: CGFloat
    let onClose: (() -> Void)?
    let onOpenSettings: (() -> Void)?
    let safeInsets: EdgeInsets
    let onChooseQR: (() -> Void)?
    let qrChosen: Bool

    /// `safeInsets`: the device's safe area when the overlay is laid out full screen (ignoring the safe area, as
    /// `OpticalPairingScanner` does so the ring sits at the frame's centre). The header and footer controls are
    /// inset by it; the dimmer and ring are not. Zero when the host already lays the overlay inside the safe area.
    public init(output: OpticalScannerPresenter.Output, status: OpticalPairingReader.Status, ringDiameter: CGFloat,
                onClose: (() -> Void)?, onOpenSettings: (() -> Void)?, safeInsets: EdgeInsets = EdgeInsets(),
                onChooseQR: (() -> Void)? = nil, qrChosen: Bool = false) {
        self.output = output; self.status = status; self.ringDiameter = ringDiameter
        self.onClose = onClose; self.onOpenSettings = onOpenSettings; self.safeInsets = safeInsets
        self.onChooseQR = onChooseQR; self.qrChosen = qrChosen
    }

    public var body: some View {
        switch status {
        case .cameraDenied:
            blocked(title: ScreenWords.readerCameraOff, body: ScreenWords.readerCameraOffBody, settings: true)
        case .cameraUnavailable:
            blocked(title: ScreenWords.readerNoCamera, body: ScreenWords.readerNoCameraBody, settings: false)
        case .idle, .scanning, .complete:
            camera
        }
    }

    private var camera: some View {
        GeometryReader { geo in
            let d = ringDiameter
            let centre = CGPoint(x: geo.size.width / 2, y: geo.size.height / 2)
            ZStack(alignment: .topLeading) {
                Path { p in
                    p.addRect(CGRect(origin: .zero, size: geo.size))
                    p.addEllipse(in: CGRect(x: centre.x - d / 2, y: centre.y - d / 2, width: d, height: d))
                }
                .fill(Color.black.opacity(0.45), style: FillStyle(eoFill: true))
                .allowsHitTesting(false)

                ScannerRing(ring: output.ring)
                    .frame(width: d, height: d)
                    .position(centre)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)

                // Top: the logo and cross, the stepper at Scan, the title; a dark fade keeps them legible on video.
                VStack(alignment: .leading, spacing: 0) {
                    PhoneHeader(onClose: onClose)
                    PhoneStepper(labels: ScreenWords.phoneSteps, now: 1).padding(.top, 18)
                    PhoneTitle(title: ScreenWords.scanTitle, subtitle: ScreenWords.scanSubtitle).padding(.top, 26)
                }
                .padding(.horizontal, 20)
                .padding(.leading, safeInsets.leading)
                .padding(.trailing, safeInsets.trailing)
                .padding(.top, 8 + safeInsets.top)
                .padding(.bottom, 28)
                .background(
                    LinearGradient(colors: [Color.black.opacity(0.85), Color.black.opacity(0.6), .clear],
                                   startPoint: .top, endPoint: .bottom)
                        .ignoresSafeArea(edges: .top)
                )

                // Bottom: what the reader sees now, the pieces read, and Cancel.
                VStack(spacing: 6) {
                    HStack(spacing: 12) {
                        if status == .scanning, case .reading = output.ring { ProgressView().tint(.white) }
                        Text(output.title).font(.system(size: 19, weight: .semibold)).foregroundColor(.white)
                    }
                    .accessibilityElement(children: .combine)
                    Text(output.hint)
                        .font(.system(size: 15))
                        .foregroundColor(Color.white.opacity(0.75))
                        .multilineTextAlignment(.center)
                    if let progress = output.progress {
                        Text(progress)
                            .font(.system(size: 13, weight: .medium).monospacedDigit())
                            .foregroundColor(progressLit ? krSignal : Color.white.opacity(0.7))
                            .padding(.top, 2)
                    }
                    if status == .scanning, qrChosen {
                        Text(ScreenWords.scanQRChosen)
                            .font(.system(size: 13)).foregroundColor(Color.white.opacity(0.7)).padding(.top, 6)
                    } else if status == .scanning, let onChooseQR {
                        Button(ScreenWords.scanUseQR, action: onChooseQR)
                            .font(.system(size: 13, weight: .medium)).foregroundColor(Color.white.opacity(0.7))
                            .padding(.top, 6)
                    }
                    if let onClose {
                        SecondaryButton(title: ScreenWords.scanCancel, action: onClose).padding(.top, 14)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.leading, safeInsets.leading)
                .padding(.trailing, safeInsets.trailing)
                .padding(.bottom, 16 + safeInsets.bottom)
                .padding(.top, 36)
                .background(
                    LinearGradient(colors: [.clear, Color.black.opacity(0.6), Color.black.opacity(0.85)],
                                   startPoint: .top, endPoint: .bottom)
                        .ignoresSafeArea(edges: .bottom)
                )
                .frame(width: geo.size.width, height: geo.size.height, alignment: .bottom)
            }
        }
        .foregroundColor(.white)
        .environment(\.colorScheme, .dark)
    }

    /// Orange once a piece is in or the read is complete; the reset's "0 of 8" stays quiet.
    private var progressLit: Bool {
        switch output.ring {
        case .solid: return true
        case .reading(let held): return held.contains(true)
        case .searching, .unfit: return false
        }
    }

    private func blocked(title: String, body: String, settings: Bool) -> some View {
        DarkScreen(title: title, strip: nil, stripAtBottom: true, maxWidth: 440) {
            Text(body)
                .font(.system(size: 15))
                .foregroundColor(Color.white.opacity(0.7))
                .multilineTextAlignment(.center)
            Spacer(minLength: 0)
            VStack(spacing: 10) {
                if settings, let onOpenSettings {
                    PrimaryButton(title: ScreenWords.readerOpenSettings, action: onOpenSettings)
                }
                if let onClose {
                    SecondaryButton(title: ScreenWords.readerClose, action: onClose)
                }
            }
        }
        .padding(.top, safeInsets.top)
        .padding(.bottom, safeInsets.bottom)
        .background(Color.black)
    }
}

/// The camera-free part of `OpticalScannerView`: the dimmer outside the ring, the eight-segment ring at the centre
/// of its own frame, and at the bottom of the frame the reader's title and hint, the "n of 8" line and the QR
/// choice. No header, stepper, title block, Cancel or fades: the host draws those. For `.cameraDenied` and
/// `.cameraUnavailable` it shows only a short plain message on black, with no buttons. Internal so macOS render
/// tests can lay it out; the camera is iOS only.
@available(iOS 15, macOS 13, *)
struct OpticalScannerFrame: View {
    let output: OpticalScannerPresenter.Output
    let status: OpticalPairingReader.Status
    let ringDiameter: CGFloat
    let onChooseQR: (() -> Void)?
    let qrChosen: Bool

    var body: some View {
        switch status {
        case .cameraDenied: message(ScreenWords.readerCameraOff)
        case .cameraUnavailable: message(ScreenWords.readerNoCamera)
        case .idle, .scanning, .complete: camera
        }
    }

    private func message(_ text: String) -> some View {
        ZStack {
            Color.black
            Text(text)
                .font(.system(size: 17, weight: .medium)).foregroundColor(.white)
                .multilineTextAlignment(.center).padding(.horizontal, 20)
        }
    }

    private var camera: some View {
        GeometryReader { geo in
            let d = ringDiameter
            let centre = CGPoint(x: geo.size.width / 2, y: geo.size.height / 2)
            ZStack(alignment: .topLeading) {
                Path { p in
                    p.addRect(CGRect(origin: .zero, size: geo.size))
                    p.addEllipse(in: CGRect(x: centre.x - d / 2, y: centre.y - d / 2, width: d, height: d))
                }
                .fill(Color.black.opacity(0.45), style: FillStyle(eoFill: true))
                .allowsHitTesting(false)

                ScannerRing(ring: output.ring)
                    .frame(width: d, height: d)
                    .position(centre)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)

                words
                    .frame(width: geo.size.width, height: geo.size.height, alignment: .bottom)
            }
        }
        .foregroundColor(.white)
        .environment(\.colorScheme, .dark)
    }

    private var words: some View {
        VStack(spacing: 6) {
            HStack(spacing: 12) {
                if status == .scanning, case .reading = output.ring { ProgressView().tint(.white) }
                Text(output.title).font(.system(size: 19, weight: .semibold)).foregroundColor(.white)
            }
            .accessibilityElement(children: .combine)
            Text(output.hint)
                .font(.system(size: 15))
                .foregroundColor(Color.white.opacity(0.75))
                .multilineTextAlignment(.center)
            if let progress = output.progress {
                Text(progress)
                    .font(.system(size: 13, weight: .medium).monospacedDigit())
                    .foregroundColor(progressLit ? krSignal : Color.white.opacity(0.7))
                    .padding(.top, 2)
            }
            if status == .scanning, qrChosen {
                Text(ScreenWords.scanQRChosen)
                    .font(.system(size: 13)).foregroundColor(Color.white.opacity(0.7)).padding(.top, 6)
            } else if status == .scanning, let onChooseQR {
                Button(ScreenWords.scanUseQR, action: onChooseQR)
                    .font(.system(size: 13, weight: .medium)).foregroundColor(Color.white.opacity(0.7))
                    .padding(.top, 6)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.black.opacity(0.5)))
        .padding(.horizontal, 12)
        .padding(.bottom, 10)
    }

    private var progressLit: Bool {
        switch output.ring {
        case .solid: return true
        case .reading(let held): return held.contains(true)
        case .searching, .unfit: return false
        }
    }
}

/// The eight 45° segments with 5° gaps and round caps, from the top, clockwise; segment i is chunk i.
@available(iOS 15, macOS 13, *)
struct ScannerRing: View {
    let ring: OpticalScannerPresenter.Ring

    var body: some View {
        ZStack {
            ForEach(0..<8, id: \.self) { i in
                let look = style(i)
                RingSegment(index: i)
                    .stroke(look.color, style: StrokeStyle(lineWidth: look.width, lineCap: .round, dash: look.dash))
            }
        }
    }

    private func style(_ i: Int) -> (color: Color, width: CGFloat, dash: [CGFloat]) {
        switch ring {
        case .searching: return (Color.white.opacity(0.38), 2.5, [4, 7])
        case .unfit: return (Color.white.opacity(0.85), 3, [4, 7])
        case .reading(let held):
            let on = i < held.count && held[i]
            return (on ? krSignal : krSignal.opacity(0.3), 5, [])
        case .solid: return (krSignal, 6, [])
        }
    }
}

@available(iOS 15, macOS 13, *)
struct RingSegment: Shape {
    let index: Int

    func path(in rect: CGRect) -> Path {
        var p = Path()
        let start = -90 + Double(index) * 45 + 2.5
        let end = -90 + Double(index + 1) * 45 - 2.5
        p.addArc(center: CGPoint(x: rect.midX, y: rect.midY), radius: min(rect.width, rect.height) / 2,
                 startAngle: .degrees(start), endAngle: .degrees(end), clockwise: false)
        return p
    }
}
#endif

#if canImport(UIKit) && canImport(SwiftUI)
import UIKit
import AVFoundation
import Combine
import QuartzCore

/// The camera view for `OpticalPairingReader`: the preview with `OpticalScannerOverlay` on it (the dimmer, the
/// eight-segment ring, the words, the progress line, the step strip, "Close" top left), and the camera-off and
/// no-camera screens with "Open Settings". The scanner does not start the reader: the host calls `reader.start()`
/// (for example in `onAppear`) and handles `onPayload`. Close stops the reader (a partial collection is
/// discarded) and then calls `onClose`; with `onClose` nil there is no Close.
///
/// Haptics: one impact when the pattern locks (at most one per 0.8 s), a success when the read completes, a
/// warning on each reset. `haptics` nil plays them through `SystemPairingHaptics`; pass `NoPairingHaptics()` for
/// none. `onOpenSettings` nil opens the app's page in Settings. The words come from `ScreenWords`; the view is
/// dark whatever the host's scheme, as a camera view is.
@available(iOS 15, *)
public struct OpticalPairingScanner: View {
    @ObservedObject private var reader: OpticalPairingReader
    @StateObject private var feed = OpticalScannerFeed()
    private let onClose: (() -> Void)?
    private let haptics: PairingHaptics?
    private let onOpenSettings: (() -> Void)?

    public init(reader: OpticalPairingReader, onClose: (() -> Void)? = nil,
                haptics: PairingHaptics? = nil,
                onOpenSettings: (() -> Void)? = nil) {
        self.reader = reader
        self.onClose = onClose
        self.haptics = haptics
        self.onOpenSettings = onOpenSettings
    }

    public var body: some View {
        // The outer reader respects the safe area only to learn its insets; the inner one fills the screen.
        GeometryReader { safe in
        GeometryReader { geo in
            // The preview is aspect-fill on a 1080x1920 portrait frame, so one point is the smaller of the two
            // ratios in frame pixels; the guide asks for a ring `targetShare` of the frame's width across.
            let pxPerPoint = min(1080 / geo.size.width, 1920 / geo.size.height)
            let d = OpticalScanLoop.targetShare * 1080 / pxPerPoint
            ZStack {
                OpticalCameraPreview(session: reader.session).ignoresSafeArea()
                OpticalScannerOverlay(output: feed.output, status: feed.status, ringDiameter: d,
                                      onClose: close, onOpenSettings: onOpenSettings ?? Self.openSettings,
                                      safeInsets: safe.safeAreaInsets,
                                      onChooseQR: reader.acceptsQR ? { reader.chooseQR() } : nil,
                                      qrChosen: reader.qrChosen)
            }
        }
        .ignoresSafeArea()
        }
        .preferredColorScheme(.dark)
        .onAppear { feed.attach(reader, haptics: haptics ?? SystemPairingHaptics()) }
    }

    private var close: (() -> Void)? {
        guard let onClose else { return nil }
        let reader = reader
        return {
            reader.stop()
            onClose()
        }
    }

    private static func openSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }
}

/// The scanner without the screen around it, for a host that draws its own title, steps, close button and logo:
/// the camera preview (aspect fill, clipped to the frame), the dimmer outside the ring, the eight-segment ring at
/// the centre of this view's own frame, and at the bottom of the frame the reader's title and hint, the "n of 8"
/// line and the QR choice, on a small local scrim. It fills whatever frame the host gives it. It draws no header,
/// logo, close cross, stepper, title block, Cancel, edge fades or safe-area override, and sets no
/// `preferredColorScheme`: the host's screen keeps its own light or dark look. Only this view's own contents draw
/// in the dark scheme, because they sit on live video.
///
/// Size: the ring is `0.7 * 1080 / min(1080 / w, 1920 / h)` points across for a w x h frame, the same formula as
/// `OpticalPairingScanner`. That is 0.7 w in a frame shorter than 1.78 w (360 x 640 gives 252) and about 0.39 h in
/// a taller one. A frame shorter than 0.7 w clips the ring. Give the frame at least ring diameter + 240 in height
/// (about 490 at 360 wide) so the reader's words sit clear of the ring.
///
/// The host starts the reader (`reader.start()`) and stops it (`reader.stop()`) when it leaves, and handles
/// `onPayload`. With the camera off or missing this view shows only a short message and no buttons; the host
/// reads `reader.status` (`.cameraDenied`, `.cameraUnavailable`) to draw its own Settings and Close. `haptics`
/// nil plays `SystemPairingHaptics`; pass `NoPairingHaptics()` for none. The QR choice appears when
/// `reader.acceptsQR`.
@available(iOS 15, *)
public struct OpticalScannerView: View {
    @ObservedObject private var reader: OpticalPairingReader
    @StateObject private var feed = OpticalScannerFeed()
    private let haptics: PairingHaptics?

    public init(reader: OpticalPairingReader, haptics: PairingHaptics? = nil) {
        self.reader = reader
        self.haptics = haptics
    }

    public var body: some View {
        GeometryReader { geo in
            let pxPerPoint = min(1080 / geo.size.width, 1920 / geo.size.height)
            let d = OpticalScanLoop.targetShare * 1080 / pxPerPoint
            ZStack {
                OpticalCameraPreview(session: reader.session)
                OpticalScannerFrame(output: feed.output, status: feed.status, ringDiameter: d,
                                    onChooseQR: reader.acceptsQR ? { reader.chooseQR() } : nil,
                                    qrChosen: reader.qrChosen)
            }
            .frame(width: geo.size.width, height: geo.size.height)
            .clipped()
        }
        .onAppear { feed.attach(reader, haptics: haptics ?? SystemPairingHaptics()) }
    }
}

/// Feeds the presenter from the reader's published state, plays the output's haptic, and re-evaluates once the
/// reset words' hold runs out (the reader may publish nothing in that time). Main thread only.
@available(iOS 15, *)
final class OpticalScannerFeed: ObservableObject {
    @Published private(set) var output: OpticalScannerPresenter.Output
    @Published private(set) var status: OpticalPairingReader.Status = .idle

    private var presenter = OpticalScannerPresenter()
    private var haptics: PairingHaptics = NoPairingHaptics()
    private var subscription: AnyCancellable?
    private weak var reader: OpticalPairingReader?
    private var last: (OpticalPairingReader.Status, OpticalPairingReader.Fit, [Bool], Int)?
    private var recheck: DispatchWorkItem?

    init() {
        var first = OpticalScannerPresenter()
        output = first.update(status: .idle, fit: .searching,
                              held: [Bool](repeating: false, count: OpticalFrame.chunkCount), resets: 0, now: 0)
    }

    func attach(_ reader: OpticalPairingReader, haptics: PairingHaptics) {
        self.haptics = haptics
        guard reader !== self.reader else { return }
        self.reader = reader
        presenter = OpticalScannerPresenter()
        // One coherent snapshot per frame and per status change, so each frame plays at most one haptic in the
        // presenter's precedence (.read, .reset, .lock, .piece), and completion lands before `onPayload`.
        subscription = reader.snapshots
            .sink { [weak self] s in self?.feed(s.status, s.fit, s.held, s.resets) }
    }

    private func feed(_ status: OpticalPairingReader.Status, _ fit: OpticalPairingReader.Fit, _ held: [Bool], _ resets: Int) {
        last = (status, fit, held, resets)
        let out = presenter.update(status: status, fit: fit, held: held, resets: resets, now: CACurrentMediaTime())
        if let haptic = out.haptic { haptics.play(haptic) }
        if self.status != status { self.status = status }
        let shown = OpticalScannerPresenter.Output(ring: out.ring, title: out.title, hint: out.hint,
                                                   progress: out.progress, haptic: nil)
        if output != shown { output = shown }
        recheck?.cancel()
        if out.title == ScreenWords.readerReset {
            let work = DispatchWorkItem { [weak self] in
                guard let self, let last = self.last else { return }
                self.feed(last.0, last.1, last.2, last.3)
            }
            recheck = work
            DispatchQueue.main.asyncAfter(deadline: .now() + presenter.resetWordsHold + 0.05, execute: work)
        }
    }
}

/// An AVCaptureVideoPreviewLayer on the reader's session, aspect-fill.
@available(iOS 15, *)
struct OpticalCameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewView {
        let v = PreviewView()
        v.previewLayer.session = session
        v.previewLayer.videoGravity = .resizeAspectFill
        return v
    }

    func updateUIView(_ uiView: PreviewView, context: Context) {}

    final class PreviewView: UIView {
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }
}
#endif
