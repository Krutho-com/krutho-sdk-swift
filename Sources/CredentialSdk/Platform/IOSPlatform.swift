import Foundation

/// The iOS and macOS platform the SDK runs on: one of each platform component (`KeychainKeys`, `KeychainStorage`,
/// `URLSessionHttp`, the App Attest runner), which the Rust core reaches through its adapters (`CoreAdapters.swift`).
/// Mirrors `AndroidPlatform.kt`.
///
/// Only the constructor is public API (hosts pass one to `CredentialSdk`).
/// The key handle, which reaches raw signing below the core's invalidation guard, is not; the EnclaveCheck harness
/// reaches `keys` through `@_spi(EnclaveHarness)`.
public final class IOSPlatform {

    @_spi(EnclaveHarness)
    public let keys:    KeychainKeys
    public let storage: KeychainStorage
    public let http:    URLSessionHttp
    let appAttest: AppAttestRunner

    /// `appAttest` takes the `AppAttesting` protocol (not `AppAttestRunner`
    /// directly), so a host never constructs one and a test never reaches
    /// the real `DCAppAttestService`: the default
    /// `defaultAppAttest()` resolves to the real wrapper where the OS
    /// supports `DCAppAttestService` (iOS 14 / macOS 11) and to a
    /// `false`-reporting stand-in below that floor — every test in this
    /// tree injects its own stub instead of relying on either.
    public init(
        keys:    KeychainKeys    = KeychainKeys(),
        storage: KeychainStorage = KeychainStorage(),
        http:    URLSessionHttp  = URLSessionHttp(),
        appAttest: AppAttesting  = defaultAppAttest()
    ) {
        self.keys    = keys
        self.storage = storage
        self.http    = http
        self.appAttest = AppAttestRunner(service: appAttest)
    }
}
