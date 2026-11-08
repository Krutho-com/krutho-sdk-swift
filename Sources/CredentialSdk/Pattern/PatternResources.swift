import Foundation

/// Finds the frozen v1 pattern data (`list.json`, `geometry.json`) at runtime: the SDK's only resource.
///
/// SwiftPM generates a different `Bundle.module` accessor per build mode. Under Xcode it searches the host app's
/// Resources directory first. Under `swift build` it searches only the host bundle's root and the absolute path of
/// the build tree, then calls `fatalError`, so an app assembled from `swift build` output ran only on the machine that
/// built it (a host app found this inside its own bundle).
///
/// The SDK therefore looks in the host's standard resource locations itself, in the order Xcode's accessor uses: each
/// root holding the SPM resource bundle (flat under `swift build`, a full bundle under Xcode), then a bare
/// `device-pattern-v1` directory; `Bundle.module` only when no host root holds the file, because a miss in its
/// `swift build` accessor terminates the process. Its build-tree fallback still serves `swift test` and `swift run`.
enum PatternResources {
    static let directoryName = "device-pattern-v1"
    static let resourceBundleName = "CredentialSdk_CredentialSdk.bundle"

    private final class BundleFinder {}

    /// Roots searched, in order: the host app's Resources directory; the Resources directory of the framework
    /// carrying this code, when the SDK is linked into one; the host bundle's root, which covers command-line tools
    /// and apps whose integrator placed the bundle beside the app's Contents directory.
    static var hostRoots: [URL] {
        [Bundle.main.resourceURL,
         Bundle(for: BundleFinder.self).resourceURL,
         Bundle.main.bundleURL].compactMap { $0 }
    }

    static func locate(_ fileName: String, in roots: [URL], fileManager: FileManager = .default) -> URL? {
        for root in roots {
            let bundle = root.appendingPathComponent(resourceBundleName)
            let candidates = [
                bundle.appendingPathComponent(directoryName).appendingPathComponent(fileName),
                bundle.appendingPathComponent("Contents/Resources").appendingPathComponent(directoryName).appendingPathComponent(fileName),
                root.appendingPathComponent(directoryName).appendingPathComponent(fileName),
            ]
            if let hit = candidates.first(where: { fileManager.fileExists(atPath: $0.path) }) {
                return hit
            }
        }
        return nil
    }

    /// Host locations first; `Bundle.module` only when none holds the file. The path and its source are logged so a
    /// transcript can tell the two apart (a relocation check reads this line).
    static func url(for fileName: String) -> URL? {
        if let url = locate(fileName, in: hostRoots) {
            NSLog("[CredentialSdk] pattern resource resolved via host resource root: \(url.path)")
            return url
        }
        let base = (fileName as NSString).deletingPathExtension
        let ext  = (fileName as NSString).pathExtension
        let url = Bundle.module.url(forResource: base, withExtension: ext, subdirectory: directoryName)
        NSLog("[CredentialSdk] pattern resource resolved via Bundle.module: \(url?.path ?? "none")")
        return url
    }

    static func data(_ fileName: String) -> Data? {
        guard let url = url(for: fileName) else { return nil }
        return try? Data(contentsOf: url)
    }
}
