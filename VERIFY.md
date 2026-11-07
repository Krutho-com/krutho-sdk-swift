# Verifying a Krutho SDK release

Each release of this package publishes three assets on its GitHub Release:

- `krutho-credential-sdk-<version>-CredentialSdkCore.xcframework.zip`, the compiled framework that Swift Package Manager downloads;
- `SHA256SUMS`, the SHA-256 of every file in the release;
- `SHA256SUMS.sig`, an OpenSSH signature over `SHA256SUMS`, made with a signing key that the Krutho release root key certifies.

`SHA256SUMS` binds the signature to one tag and one file set. Its first line names the release tag; every other line lists one file:

```
# tag: sdk-v<version>
<64 lowercase hex characters>  <path>
```

Exactly two spaces separate hash and path. Paths under `Binaries/CredentialSdkCore.xcframework/` name the files inside the zip. Paths under `Sources/` name the Swift wrapper files in this repository at the release tag. The line `assets/sdk/<version>/<zip name>` carries the hash of the zip itself.

`scripts/verify-public.sh` runs every check below in order and stops at the first failure. The manual commands match it step for step. Both work offline once the files are downloaded.

## What you need

- OpenSSH `ssh-keygen`, `git`, `bash`, `unzip`, and `shasum` (macOS) or `sha256sum` (Linux).
- The root key fingerprint, which Krutho sends you out of band. Never take it from this repository: a fingerprint read from the repository proves nothing about the repository.

## 1. Download the release and the current keys

```sh
git clone https://github.com/Krutho-com/krutho-sdk-swift.git
cd krutho-sdk-swift
git worktree add ../krutho-sdk-swift-<version> sdk-v<version>
mkdir ../assets-<version>
gh release download sdk-v<version> -R Krutho-com/krutho-sdk-swift -D ../assets-<version> \
  -p '*.xcframework.zip' -p SHA256SUMS -p SHA256SUMS.sig
```

Without the GitHub CLI, download the same three files from the release page. The checkout of `main` supplies the current `KEYS/` and `scripts/`; the worktree supplies `Sources/` and `Package.swift` at the tag. Always use the current `KEYS/`: a tag's own copy predates any later revocation.

## 2. Run the verifier

```sh
scripts/verify-public.sh \
  --assets ../assets-<version> \
  --tag sdk-v<version> \
  --root-fingerprint 'SHA256:<fingerprint from Krutho>' \
  --source ../krutho-sdk-swift-<version>
```

The last line reads `verified` and the exit status is 0. Any failure prints `FAIL:` and the cause and exits 1. A usage error exits 2. In CI, require both exit status 0 and `verified` as the last line.

Options:

- `--keys DIR`: the current `KEYS/` directory. Default: `KEYS/` beside the script's directory.
- `--source DIR`: a checkout of this repository at the release tag. With it, the verifier also checks every `Sources/` line and that the `checksum:` in `Package.swift` equals the zip's hash. Without it, those checks are skipped and the output says so.

## 3. The checks, by hand

Run these from the checkout of `main`, with `A=../assets-<version>`, `SRC=../krutho-sdk-swift-<version>`, `V=<version>`, `ZIP=krutho-credential-sdk-$V-CredentialSdkCore.xcframework.zip` and a scratch directory `W=$(mktemp -d)` that you delete when you finish. On Linux, replace `shasum -a 256` with `sha256sum`.

**Step 1: root key pin.** `KEYS/release-root.pub` holds exactly one key, and its fingerprint must equal the one Krutho sent you.

```sh
ssh-keygen -l -E sha256 -f KEYS/release-root.pub
```

**Step 2: revocation statement signature,** against the root key itself.

```sh
printf 'krutho-root namespaces="krutho-revocation" %s\n' "$(cut -d' ' -f1,2 KEYS/release-root.pub)" > "$W/allowed_root"
ssh-keygen -Y verify -f "$W/allowed_root" -I krutho-root -n krutho-revocation \
  -s KEYS/revocation.txt.sig < KEYS/revocation.txt
```

**Step 3: the revocation list is the one the statement names.** Its hash must equal the `krl_sha256` line of `revocation.txt`, and it must parse as an OpenSSH KRL.

```sh
shasum -a 256 KEYS/revoked.krl
ssh-keygen -Q -l -f KEYS/revoked.krl   # must exit 0
```

**Step 4: freshness.** The current UTC time (`date -u +%Y-%m-%dT%H:%M:%SZ`) must come before `next_update` in `revocation.txt`. An expired statement fails: fetch `main` again, or ask Krutho for the current statement.

**Step 5: the release signature, always with the revocation list.**

```sh
printf 'krutho-release cert-authority,namespaces="krutho-release" %s\n' "$(cut -d' ' -f1,2 KEYS/release-root.pub)" > "$W/allowed_signers"
ssh-keygen -Y verify -f "$W/allowed_signers" -I krutho-release -n krutho-release \
  -s "$A/SHA256SUMS.sig" -r KEYS/revoked.krl < "$A/SHA256SUMS"
```

**Step 6: the tag and the list form.** The first line must read `# tag: sdk-v<version>`. Every other line must be well formed with a safe relative path, and no path may appear twice.

```sh
head -n 1 "$A/SHA256SUMS"
tail -n +2 "$A/SHA256SUMS" > "$W/sums"
grep -v -E '^[0-9a-f]{64}  [A-Za-z0-9._+@-][A-Za-z0-9._+@/-]*$' "$W/sums"   # prints nothing
cut -c67- "$W/sums" | grep -E '(^|/)\.{1,2}(/|$)|//|/$|^SHA256SUMS(\.sig)?$'  # prints nothing
cut -c67- "$W/sums" | LC_ALL=C sort | LC_ALL=C uniq -d                      # prints nothing
```

**Step 7: the zip.** Its hash must equal the `assets/sdk/<version>/<zip name>` line.

```sh
shasum -a 256 "$A/$ZIP"
grep "  assets/sdk/$V/$ZIP\$" "$W/sums"
```

**Step 8: the framework inside the zip.** Every entry must sit under `CredentialSdkCore.xcframework/`, every `Binaries/` line must match, and the zip must hold no unlisted file.

```sh
unzip -Z1 "$A/$ZIP" | grep -v '^CredentialSdkCore\.xcframework/'   # prints nothing
mkdir "$W/x" && unzip -q "$A/$ZIP" -d "$W/x"
grep '  Binaries/' "$W/sums" | sed 's|  Binaries/|  |' > "$W/bin_sums"
(cd "$W/x" && shasum -a 256 -c "$W/bin_sums")                       # every line OK
cut -c67- "$W/bin_sums" | LC_ALL=C sort > "$W/bin_listed"
(cd "$W/x" && find . -type f) | sed 's|^\./||' | LC_ALL=C sort > "$W/bin_present"
LC_ALL=C comm -23 "$W/bin_present" "$W/bin_listed"                    # prints nothing
```

**Step 9: the Swift sources and the package checksum.**

```sh
grep '  Sources/' "$W/sums" > "$W/src_sums"
(cd "$SRC" && shasum -a 256 -c "$W/src_sums")                       # every line OK
cut -c67- "$W/src_sums" | LC_ALL=C sort > "$W/src_listed"
(cd "$SRC" && find Sources -type f) | LC_ALL=C sort > "$W/src_present"
LC_ALL=C comm -23 "$W/src_present" "$W/src_listed"                    # prints nothing
grep 'checksum:' "$SRC/Package.swift"                                # equals the zip hash from step 7
```

`swift package compute-checksum "$A/$ZIP"` prints the same value Swift Package Manager checks at resolve time.

## 4. Match what you verified to what your app builds

Swift Package Manager resolves `<version>` through the tag of that name; this guide verifies `sdk-v<version>`. Both tags point at the same commit. Check that, and that your app's `Package.resolved` pins the same commit:

```sh
git -C "$SRC" rev-parse 'HEAD^{commit}'
git ls-remote https://github.com/Krutho-com/krutho-sdk-swift \
  "refs/tags/sdk-v$V" "refs/tags/sdk-v$V^{}" "refs/tags/$V" "refs/tags/$V^{}"
grep -A8 'krutho-sdk-swift' Package.resolved
```

For an annotated tag, take the line ending `^{}`. All three commits must be equal. If any differs, do not ship: contact Krutho.

## What this does not cover

- **Revocation floor.** This verifier checks that the revocation statement is signed and unexpired. It does not store the highest statement sequence you have accepted, so it cannot refuse an older, unexpired statement. Fetch `KEYS/` from the current `main` each time.
- **Recovery records.** If Krutho revokes a signing key, step 5 fails for every release that key signed. Krutho then publishes a replacement release and notifies customers out of band.
- **Withdrawal.** A withdrawn release still verifies. Krutho marks withdrawals in `CHANGELOG.md` and announces them out of band.
- A passing signature shows that Krutho's release process produced these bytes. It does not independently prove the build or the tests.
