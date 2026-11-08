// swift-tools-version: 5.9
// Krutho credential SDK 2.0.2 (release sdk-v2.0.2).
// The compiled core is a release asset of this repository. Swift Package
// Manager downloads it from the release and refuses it unless its SHA-256
// equals the checksum below.
import PackageDescription

let package = Package(
    name: "CredentialSdk",
    platforms: [.iOS(.v13), .macOS(.v13)],
    products: [
        .library(name: "CredentialSdk", targets: ["CredentialSdk"])
    ],
    targets: [
        .binaryTarget(
            name: "CredentialSdkCore",
            url: "https://github.com/Krutho-com/krutho-sdk-swift/releases/download/sdk-v2.0.2/krutho-credential-sdk-2.0.2-CredentialSdkCore.xcframework.zip",
            checksum: "8c7f77be10134be20707fe48e7a5888098f4296a7db0716ff6bf646f13cad55f"
        ),
        .target(
            name: "CredentialSdkCoreBindings",
            dependencies: ["CredentialSdkCore"],
            path: "Sources/CredentialSdkCoreBindings"
        ),
        .target(
            name: "CredentialSdk",
            dependencies: ["CredentialSdkCoreBindings"],
            path: "Sources/CredentialSdk",
            resources: [
                .copy("Resources/device-pattern-v1")
            ],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("DeviceCheck")
            ]
        )
    ]
)
