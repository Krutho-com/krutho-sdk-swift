# Verifying a Krutho SDK release

Each release of this package publishes three assets on its GitHub Release:

- `krutho-credential-sdk-<version>-CredentialSdkCore.xcframework.zip`, the compiled framework that Swift Package Manager downloads;
- `SHA256SUMS`, a list of SHA-256 hashes;
- `SHA256SUMS.sig`, an OpenSSH signature over `SHA256SUMS`, made with a signing key that the Krutho release root key certifies.

`SHA256SUMS` binds the signature to one tag and one file set. Its first line names the release tag; every other line lists one file:

```
# tag: sdk-v<version>
<64 lowercase hex characters>  <path>
```

Exactly two spaces separate hash and path. Krutho signs one list for each release, and it also names files of Krutho's own release record that this repository does not carry. The verifier reads three kinds of line and ignores the rest:

- `assets/sdk/<version>/<zip name>`: the hash of the zip;
- `Binaries/CredentialSdkCore.xcframework/...`: the files inside the zip;
- `Sources/...`: the Swift wrapper files in this repository at the release tag.

**What the signature covers.** The zip, the framework files inside it and the `Sources/` files. `Package.swift` is not listed. It is bound to the release by exact comparison: the verifier renders `scripts/Package.swift.expected.in` with the release's tag, version, zip name and zip hash, and `Package.swift` at the tag must equal the result byte for byte. A manifest with any other dependency, target, flag, comment, conditional or string fails. Swift Package Manager also refuses a downloaded zip whose checksum differs from the one in the manifest.

`scripts/verify-public.sh` runs every check below in order and stops at the first failure. Section 3 gives the same checks by hand and says where a manual step is weaker than the script.

## What you need

- OpenSSH `ssh-keygen`, `git`, `bash`, `unzip` and `zipinfo`, and `shasum` (macOS) or `sha256sum` (Linux).
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

Without the GitHub CLI, download the same three files from the release page. Run the verifier and its templates from the current `main`, never from the release checkout: the release checkout is what is being checked. The checkout of `main` supplies the current `KEYS/` and `scripts/`; the worktree supplies `Sources/` and `Package.swift` at the tag. Always use the current `KEYS/`: a tag's own copy predates any later revocation.

## 2. Run the verifier

```sh
scripts/verify-public.sh \
  --assets ../assets-<version> \
  --tag sdk-v<version> \
  --root-fingerprint 'SHA256:<fingerprint from Krutho>' \
  --source ../krutho-sdk-swift-<version>
```

The last line reads `verified` and the exit status is 0. Any failed check, and any unexpected error, prints `FAIL:` and the cause as the last line and exits 1. A usage error exits 2. In CI, require both exit status 0 and `verified` as the last line.

Options:

- `--keys DIR`: the current `KEYS/` directory. Default: `KEYS/` beside the script's directory.
- `--verify-time YYYYMMDD`: check the signing certificate as of that date (see Certificate expiry below). The revocation list still applies.
- `--allow-path-binary`: for an internal check of an older, git-delivered release. Public releases never need it.

## Certificate expiry

The current signing certificate, `KEYS/release-signing-cert-1.pub` (serial 1), is valid until 2027-11-06. Krutho issues a new certificate before then and adds it to `KEYS/`. After that date, step 5 fails for a release signed with serial 1. To check such a release, pass a date inside the certificate's validity, normally the release date:

```sh
scripts/verify-public.sh ... --verify-time 20261107
```

The revocation list applies at every verify time: a revoked signer fails whatever date you pass. Read a certificate's validity with `ssh-keygen -L -f KEYS/release-signing-cert-1.pub`.

## 3. The checks, by hand

Run these from the checkout of `main`, with `A=../assets-<version>`, `SRC=../krutho-sdk-swift-<version>`, `TAG=sdk-v<version>`, `V=<version>`, `ZIP=krutho-credential-sdk-$V-CredentialSdkCore.xcframework.zip` and a scratch directory `W=$(mktemp -d)` that you delete when you finish. On Linux, replace `shasum -a 256` with `sha256sum`.

**Step 1: root key pin.** `KEYS/release-root.pub` holds exactly one key, and its fingerprint must equal the one Krutho sent you.

```sh
grep -c . KEYS/release-root.pub          # prints 1
ssh-keygen -l -E sha256 -f KEYS/release-root.pub
```

**Step 2: revocation statement signature,** against the root key itself.

```sh
printf 'krutho-root namespaces="krutho-revocation" %s\n' "$(cut -d' ' -f1,2 KEYS/release-root.pub)" > "$W/allowed_root"
ssh-keygen -Y verify -f "$W/allowed_root" -I krutho-root -n krutho-revocation \
  -s KEYS/revocation.txt.sig < KEYS/revocation.txt
```

**Step 3: the statement's form and the revocation list.** `revocation.txt` holds exactly these lines, in any order, and nothing else; the first four appear once each:

```
sequence: <integer, 1 or more>
issued: <YYYY-MM-DDTHH:MM:SSZ>
next_update: <YYYY-MM-DDTHH:MM:SSZ, after issued>
krl_sha256: <64 lowercase hex characters>
recovery_sha256: <64 lowercase hex characters>    (zero or more lines)
```

The hash of `KEYS/revoked.krl` must equal `krl_sha256`, and the file must parse as an OpenSSH KRL.

```sh
shasum -a 256 KEYS/revoked.krl
ssh-keygen -Q -l -f KEYS/revoked.krl   # must exit 0
```

**Step 4: freshness.** The current UTC time (`date -u +%Y-%m-%dT%H:%M:%SZ`) must come before `next_update`. An expired statement fails: fetch `main` again, or ask Krutho for the current statement.

**Step 5: the release signature, always with the revocation list.** Add `-O verify-time=YYYYMMDD` for a release whose certificate has since expired.

```sh
printf 'krutho-release cert-authority,namespaces="krutho-release" %s\n' "$(cut -d' ' -f1,2 KEYS/release-root.pub)" > "$W/allowed_signers"
ssh-keygen -Y verify -f "$W/allowed_signers" -I krutho-release -n krutho-release \
  -s "$A/SHA256SUMS.sig" -r KEYS/revoked.krl < "$A/SHA256SUMS"
```

**Step 6: the tag and the list form.** The first line must read `# tag: sdk-v<version>`. Every other line must be well formed with a safe relative path, and no path may appear twice.

```sh
head -n 1 "$A/SHA256SUMS"                                                  # prints: # tag: $TAG
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

**Step 8: the framework inside the zip.** Check the listing before you extract anything. Every entry name must start with `CredentialSdkCore.xcframework/`, contain no `..` component, backslash or doubled slash, and use only the characters `A-Z a-z 0-9 . _ + @ / -`. Every entry must be a regular file (`-`) or a directory (`d`) in the first column of `zipinfo`: a link (`l`), any other type, or an untyped entry (`?`) fails.

```sh
zipinfo -1 "$A/$ZIP" | grep -v '^CredentialSdkCore\.xcframework/'           # prints nothing
zipinfo -1 "$A/$ZIP" | grep -E '(^|/)\.\.(/|$)|^/|\\|//'                    # prints nothing
zipinfo -1 "$A/$ZIP" | grep -v -E '^[A-Za-z0-9._+@/-]+$'                    # prints nothing
zipinfo "$A/$ZIP" | sed '1,2d;$d' | cut -c1 | grep -v '^[-d]$'              # prints nothing
```

Then extract into an empty directory and compare with the `Binaries/` lines. The zip must hold no file that the list omits.

```sh
mkdir "$W/x" && unzip -q "$A/$ZIP" -d "$W/x"
grep '  Binaries/' "$W/sums" | sed 's|  Binaries/|  |' > "$W/bin_sums"
(cd "$W/x" && shasum -a 256 -c "$W/bin_sums")                       # every line OK
cut -c67- "$W/bin_sums" | LC_ALL=C sort > "$W/bin_listed"
(cd "$W/x" && find . -type f) | sed 's|^\./||' | LC_ALL=C sort > "$W/bin_present"
LC_ALL=C comm -23 "$W/bin_present" "$W/bin_listed"                    # prints nothing
```

**Step 9: the Swift sources.** Every `Sources/` line must match, and `Sources/` must hold no unlisted file, symlink or special file.

```sh
grep '  Sources/' "$W/sums" > "$W/src_sums"
(cd "$SRC" && shasum -a 256 -c "$W/src_sums")                       # every line OK
cut -c67- "$W/src_sums" | LC_ALL=C sort > "$W/src_listed"
(cd "$SRC" && find Sources -type f) | LC_ALL=C sort > "$W/src_present"
LC_ALL=C comm -23 "$W/src_present" "$W/src_listed"                    # prints nothing
(cd "$SRC" && find Sources ! -type f ! -type d)                       # prints nothing
```

**Step 10: the top level and `Package.swift`.** First, the checkout may hold only the entries a release writes. Swift Package Manager also reads version-specific manifests (`Package@swift-5.9.swift` and the like), `Plugins/` and `.swiftpm`, so none of those may exist, and no top-level entry may be a symlink. Both commands must print nothing:

```sh
find "$SRC" -mindepth 1 -maxdepth 1 ! \( -name .git -o -name Package.swift -o -name Sources -o -name KEYS \
  -o -name scripts -o -name notes -o -name README.md -o -name VERIFY.md -o -name LICENSE \
  -o -name SECURITY.md -o -name CHANGELOG.md \) -print
find "$SRC" -mindepth 1 -maxdepth 1 -type l -print
```

The script also checks that each directory name is a directory and each file name a regular file. Second, render the canonical manifest and compare it with the file. The template carries five placeholders: `@VERSION@`, `@TAG@`, `@PUBLIC_REPO@` (always `Krutho-com/krutho-sdk-swift`), `@ZIP@` and `@CHECKSUM@` (the zip hash from step 7). The two files must be identical, byte for byte; any difference fails, whatever it is.

```sh
ZIPSUM=$(shasum -a 256 "$A/$ZIP" | cut -d' ' -f1)
sed -e "s|@VERSION@|$V|g" -e "s|@TAG@|$TAG|g" -e "s|@PUBLIC_REPO@|Krutho-com/krutho-sdk-swift|g" \
  -e "s|@ZIP@|$ZIP|g" -e "s|@CHECKSUM@|$ZIPSUM|g" scripts/Package.swift.expected.in > "$W/Package.swift.expected"
grep -c '@[A-Z_]*@' "$W/Package.swift.expected"    # prints 0
cmp "$W/Package.swift.expected" "$SRC/Package.swift"   # prints nothing, exits 0
diff -u "$W/Package.swift.expected" "$SRC/Package.swift"   # shows any difference
```

`swift package compute-checksum "$A/$ZIP"` prints the value Swift Package Manager checks at resolve time; it equals the SHA-256 of the zip.

## 4. Match what you verified to what your app builds

Swift Package Manager resolves `<version>` through the tag of that name; this guide verifies `sdk-v<version>`. Both tags point at the same commit. Check that, and that your app's `Package.resolved` pins the same commit:

```sh
git -C "$SRC" rev-parse 'HEAD^{commit}'
git ls-remote https://github.com/Krutho-com/krutho-sdk-swift \
  "refs/tags/$TAG" "refs/tags/$TAG^{}" "refs/tags/$V" "refs/tags/$V^{}"
grep -A8 'krutho-sdk-swift' Package.resolved
```

For an annotated tag, take the line ending `^{}`. All three commits must be equal. If any differs, do not ship: contact Krutho.

## What this does not cover

- **What the other files hold.** The verifier checks the names of the top-level entries, but not the contents of `README.md`, `scripts/`, `notes/` and the other top-level files, and no other line of `SHA256SUMS`. The contents of `KEYS/` are pinned to the root key you hold.
- **Revocation floor.** The verifier checks that the revocation statement is signed and unexpired. It does not store the highest statement sequence you have accepted, so it cannot refuse an older, unexpired statement. Fetch `KEYS/` from the current `main` each time.
- **Recovery records.** If Krutho revokes a signing key, step 5 fails for every release that key signed. Krutho then publishes a replacement release and notifies customers out of band.
- **Withdrawal.** A withdrawn release still verifies. Krutho announces every withdrawal out of band.
- A passing signature shows that Krutho's release process produced these bytes. It does not independently prove the build or the tests.
