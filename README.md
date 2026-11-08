# Krutho SDK for Swift

The Krutho credential SDK for iOS and macOS, delivered as a Swift package. Each release ships the Swift wrapper source in this repository and the compiled `CredentialSdkCore.xcframework` as a signed GitHub Release asset.

No release is published here yet.

## Add the package

Package URL: `https://github.com/Krutho-com/krutho-sdk-swift`

Pin an exact version. In Xcode, choose File > Add Package Dependencies, enter the URL, set the dependency rule to Exact Version, and add the `CredentialSdk` product to your app target.

In a `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Krutho-com/krutho-sdk-swift", exact: "<version>"),
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "CredentialSdk", package: "krutho-sdk-swift"),
        ]
    ),
]
```

Then `import CredentialSdk` in your code. Swift Package Manager downloads the XCFramework from the release and checks it against the checksum in `Package.swift`. No GitHub account or token is needed.

## Requirements

- iOS 13 or later, macOS 13 or later.
- The Xcode version stated in the release notes.

## Documentation

Integration guides, examples and release notes are for Krutho members at [members.krutho.com](https://members.krutho.com), behind Krutho sign-in.

## Verify before you ship

Every release carries `SHA256SUMS` and an OpenSSH signature over it, `SHA256SUMS.sig`, as release assets. [VERIFY.md](VERIFY.md) gives the steps, and `scripts/verify-public.sh` runs them. The root key fingerprint reaches you from Krutho out of band; never take it from this repository.

## Layout

| Path | What it holds |
|---|---|
| `README.md`, `VERIFY.md` | This guide and the verification steps |
| `KEYS/` | Release root key, signing certificate, revocation list and signed revocation statement ([KEYS/README.md](KEYS/README.md)) |
| `scripts/verify-public.sh` | Verifier for a downloaded release |
| `LICENSE` | Terms of use |
| `SECURITY.md` | How to report a security issue |

## License

See [LICENSE](LICENSE). Use of the SDK requires a Krutho agreement.
