# KEYS

This directory holds the public material for verifying Krutho releases. Krutho added the files at the release root key ceremony on 2026-11-06. No private key is ever committed here.

| File | Content |
|---|---|
| `release-root.pub` | The release root public key. It certifies signing keys and signs revocation statements and recovery records. Check its fingerprint against the one Krutho sends you out of band. |
| `release-signing-cert*.pub` | Signing key certificates issued by the root key, current and past. Each carries a serial number so the revocation list can name it. |
| `revoked.krl` | OpenSSH key revocation list. Revokes compromised signing keys by key and by certificate serial. |
| `revocation.txt` | Revocation statement: `sequence`, `issued`, `next_update`, `krl_sha256` and one `recovery_sha256` line per recovery record. |
| `revocation.txt.sig` | Root key signature over `revocation.txt`, namespace `krutho-revocation`. |
| `recovery/<tag>.txt`, `recovery/<tag>.txt.sig` | Recovery record for a release whose signing key was later revoked, signed by the root key, namespace `krutho-recovery`. Valid only when `revocation.txt` lists its SHA-256. |

Krutho reissues the revocation statement at every signing certificate renewal and at once on any revocation. Each statement is valid for 13 months from issue.

Always verify with the `KEYS/` from the current `main`, not the copy inside an older release tag: the current statement carries every later revocation. [VERIFY.md](../VERIFY.md) gives the file formats and commands.
