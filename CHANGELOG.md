# Changelog

All notable changes to the Krutho credential SDK for iOS and macOS (`CredentialSdk`). Versions follow semantic versioning. Android is not part of 2.0.0, 2.0.1 or 2.0.2.

## 2.0.2 (2026-11-07)

2.0.2 has no behavior change. The source comments are rewritten for public distribution, and 2.0.2 is the first release on the public package, `https://github.com/Krutho-com/krutho-sdk-swift`, which serves iOS and macOS from one package. The API, the behavior and the platforms are the same as 2.0.1. Existing pins on the private releases route keep working.

## 2.0.1 (2026-11-07)

2.0.1 replaces 2.0.0. Krutho withdrew 2.0.0 when its final release check failed, before any customer had access to it. 2.0.1 has no SDK changes from 2.0.0. The source, the API, the behavior and the platforms are the same; only the version number changed. Use 2.0.1 wherever the 2.0.0 entry below applies. The 2.0.0 entry stays as the record of what the 2.0 line contains.

## 2.0.0 (2026-11-06)

The first versioned release. Earlier builds shipped as pinned revisions of the `krutho-credential-sdk` package with no version number; this file calls them 1.x.

### Breaking: a native core replaces the JavaScript engine

- On iOS and macOS the SDK no longer contains a JavaScript engine. 1.x ran its protocol core as bundled JavaScript inside JavaScriptCore. 2.0.0 runs a compiled Rust core, shipped as the binary target `CredentialSdkCore.xcframework` and called through generated Swift bindings (`CredentialSdkCoreBindings`).
- The package no longer links `JavaScriptCore` and no longer carries the `credential-sdk-core.bundle.js` resource. Apps that copied that bundle into `Contents/Resources` when assembling a `swift build` product can drop the step.
- Storage stays compatible. The SDK reads keys and records that 1.x wrote, so no re-enrollment and no key regeneration. This was tested from storage 1.x wrote on the iOS simulator; it has not been tested on physical customer devices.

### Breaking: source changes

| Removed | Replacement |
|---|---|
| `issueMdoc(challenge:tenant:deviceKeyX:deviceKeyY:deviceKeyProof:authenticationContext:)` | `issueMdoc(challenge:tenant:deviceKeyX:deviceKeyY:hostProof:)`. The SDK builds the proof's signing input, opens one authentication scope (one Face ID or Touch ID prompt), and calls `hostProof` once with the scope's `LAContext`. Sign the input with the new mdoc key and return raw `r‖s` (64 bytes). The host no longer builds the proof or evaluates its own context. |
| `CredentialSdk.init(..., engine:)`, `CoreEngine`, `CredentialSdk.engine` (present only in pre-release 2.0 builds) | None. The native core is the only engine. |

`JsBridgeError` keeps all four cases and `CredentialSdkError.jsBridgeError` stays, so existing `switch` statements compile. An error the SDK leaves untyped (a refused transaction, a protocol refusal, a storage failure) still arrives as `JsBridgeError.jsException(message)`, now carrying the native core's message. Every typed `CredentialSdkError` case maps as in 1.x.

### Behavior changes

- **One pending approval per SDK instance, across kinds.** A sign-in inspection replaces a pending endorsement, and the reverse.
- **A failed sign-in send spends the approval.** Once `signInPresent(_:)` fails after the signature exists, a second call refuses ("this approval was already used; scan again"). Inspect the invitation again. 1.x signed again over the same invitation.
- **Biometric scope bound to the transaction.** Each approval opens one `LAContext` with a fixed number of SDK-controlled signing operations and invalidates it on every exit. For `issueMdoc`, the SDK passes the live context to `hostProof` once to sign the proof. The host can use that context for other keys it can access while the callback runs; the SDK cannot count those signatures. The SDK invalidates the context when the scope ends.
- **A changed biometric set invalidates the device key only on measured evidence.** The SDK reports `key_invalidated` (and the core revokes the device) only when the system refuses the key with one of the measured key-unusable errors *and* the recorded biometric set changed. A wrong finger, a lockout or a cancel never destroys a usable key.
- **Redirects are refused.** Every SDK request, the endorsement status poll included, refuses HTTP redirects. The status poll now runs on the transport the host configured (including an injected TLS delegate) instead of a default session.
- **Instances share one core per keychain storage.** Two `CredentialSdk` instances over the same storage share the native core when their configuration, key store, transport and App Attest runner match; a mismatch throws `.unsupported` at `initialize()`. `dispose()` releases an instance's share.
- **Host strings are checked before they cross into the core.** A string with an unpaired UTF-16 surrogate throws `CredentialSdkError.invalidHostString`.

### Added

- `approvalPromptText:` on `init`: the host supplies the words the Face ID or Touch ID prompt shows for each approval (`ApprovalPrompt`: kind, default text, and the details the API already exposes). Nil, empty or whitespace falls back to the core's text; answers longer than 160 characters are cut. The hook changes only the words, never the signed bytes.
- Mac passkey approvals: `prepareMacPasskey(tenant:request:)`, `sendMacPasskey(token:sigPossession:kbSignature:)`, `cancelMacPasskey(token:)`, `reportMacPasskeyKeyUnusable(token:shape:)`, `resolveMacPasskeyHolds()`, with `MacPasskeyPrepared`, `MacPasskeySigner` and keychain-held holds.
- `KeychainKeys` and `KeychainStorage` take an optional `accessGroup:` for a shared keychain access group. Nil (the default) keeps 1.x behavior. A core refuses a second storage with a different group.
- `endSiteSignIn(handle:)`, and `ring_signin` alerts in the device alerts.
- `PasskeyNode` and `PasskeyAlert` carry an optional `DevicePattern`.
- `CredentialSdk.sdkVersion` (`"2.0.0"`).

### Platforms

- iOS 13 or later, macOS 13 or later (unchanged). The iOS simulator slice for Apple silicon requires iOS 14 or later, the first simulator release for that architecture.
- Android: not in this release.

### Known limits

- Storage that 1.x wrote is proven to carry over on iOS simulator snapshots only, not on physical devices. Test an upgrade on your own devices before you ship.
- Android is not in this release.
- The release notes state the minimum server version.
