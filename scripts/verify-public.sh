#!/usr/bin/env bash
# Verify a Krutho SDK release downloaded from this repository's GitHub Release.
#
#   scripts/verify-public.sh --assets DIR --tag sdk-vX.Y.Z \
#     --root-fingerprint 'SHA256:<fingerprint from Krutho>' \
#     [--keys DIR] [--source DIR]
#
# --assets  directory holding the release zip, SHA256SUMS and SHA256SUMS.sig
# --keys    the current KEYS/ directory (default: KEYS/ beside scripts/)
# --source  a checkout of this repository at the release tag; checks the
#           Sources/ lines and the Package.swift checksum
#
# Last line `verified` and exit 0 on success. `FAIL: <cause>` and exit 1 on any
# failed check. Exit 2 on a usage error. VERIFY.md gives the same steps by hand.
set -euo pipefail
export LC_ALL=C

fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
usage() { printf 'usage: %s --assets DIR --tag sdk-vX.Y.Z --root-fingerprint SHA256:... [--keys DIR] [--source DIR]\n' "$0" >&2; exit 2; }
step() { printf '%s\n' "$*"; }

assets="" tag="" fpr="" keys="" source_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --assets) [ $# -ge 2 ] || usage; assets="$2"; shift 2 ;;
    --tag) [ $# -ge 2 ] || usage; tag="$2"; shift 2 ;;
    --root-fingerprint) [ $# -ge 2 ] || usage; fpr="$2"; shift 2 ;;
    --keys) [ $# -ge 2 ] || usage; keys="$2"; shift 2 ;;
    --source) [ $# -ge 2 ] || usage; source_dir="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$assets" ] && [ -n "$tag" ] && [ -n "$fpr" ] || usage
[[ "$tag" =~ ^sdk-v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || { echo "tag must look like sdk-v1.2.3" >&2; exit 2; }
version="${BASH_REMATCH[1]}"
[ -n "$keys" ] || keys="$(cd "$(dirname "$0")/.." && pwd)/KEYS"
[ -d "$assets" ] || usage
[ -d "$keys" ] || fail "no KEYS directory at $keys"

if command -v sha256sum >/dev/null 2>&1; then sha256() { sha256sum "$1" | cut -d' ' -f1; }
else sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

zipname="krutho-credential-sdk-${version}-CredentialSdkCore.xcframework.zip"
zip="$assets/$zipname"
sums="$assets/SHA256SUMS"
sig="$assets/SHA256SUMS.sig"
for f in "$zip" "$sums" "$sig"; do
  [ -f "$f" ] && [ ! -L "$f" ] || fail "missing or not a regular file: $f"
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1. Root key pin.
step "1. root key pin"
[ "$(grep -c . "$keys/release-root.pub")" = 1 ] || fail "release-root.pub must hold exactly one key"
got="$(ssh-keygen -l -E sha256 -f "$keys/release-root.pub" | cut -d' ' -f2)"
[ "$got" = "$fpr" ] || fail "root key fingerprint $got does not match $fpr"
rootkey="$(cut -d' ' -f1,2 "$keys/release-root.pub")"

# 2. Revocation statement signature, by the root key itself.
step "2. revocation statement signature"
printf 'krutho-root namespaces="krutho-revocation" %s\n' "$rootkey" > "$work/allowed_root"
ssh-keygen -Y verify -f "$work/allowed_root" -I krutho-root -n krutho-revocation \
  -s "$keys/revocation.txt.sig" < "$keys/revocation.txt" >/dev/null 2>&1 \
  || fail "revocation.txt signature does not verify against the root key"

# 3. The revocation list is the one the statement names, and parses as a KRL.
step "3. revocation list"
bad="$(grep -v -E '^(sequence: [1-9][0-9]*|issued: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z|next_update: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z|krl_sha256: [0-9a-f]{64}|recovery_sha256: [0-9a-f]{64})$' "$keys/revocation.txt" || true)"
[ -z "$bad" ] || fail "revocation.txt has an unexpected line"
for k in sequence issued next_update krl_sha256; do
  [ "$(grep -c "^$k: " "$keys/revocation.txt")" = 1 ] || fail "revocation.txt must carry exactly one $k line"
done
krl_want="$(sed -n 's/^krl_sha256: //p' "$keys/revocation.txt")"
[ "$(sha256 "$keys/revoked.krl")" = "$krl_want" ] || fail "revoked.krl does not match krl_sha256"
ssh-keygen -Q -l -f "$keys/revoked.krl" >/dev/null 2>&1 || fail "revoked.krl is not a valid OpenSSH KRL"

# 4. Freshness.
step "4. statement freshness"
issued="$(sed -n 's/^issued: //p' "$keys/revocation.txt")"
next_update="$(sed -n 's/^next_update: //p' "$keys/revocation.txt")"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[[ "$next_update" > "$issued" ]] || fail "next_update is not after issued"
[[ "$now" < "$next_update" ]] || fail "revocation statement expired at $next_update: fetch the current KEYS/"

# 5. Release signature, always with the revocation list.
step "5. release signature"
printf 'krutho-release cert-authority,namespaces="krutho-release" %s\n' "$rootkey" > "$work/allowed_signers"
ssh-keygen -Y verify -f "$work/allowed_signers" -I krutho-release -n krutho-release \
  -s "$sig" -r "$keys/revoked.krl" < "$sums" >/dev/null 2>&1 \
  || fail "SHA256SUMS.sig does not verify (or its signer is revoked): contact Krutho"

# 6. SHA256SUMS form and tag.
step "6. SHA256SUMS form and tag"
[ "$(head -n 1 "$sums")" = "# tag: $tag" ] || fail "SHA256SUMS is signed for '$(head -n 1 "$sums")', not '# tag: $tag'"
tail -n +2 "$sums" > "$work/sums"
if grep -v -E '^[0-9a-f]{64}  [A-Za-z0-9._+@-][A-Za-z0-9._+@/-]*$' "$work/sums" >/dev/null; then fail "malformed SHA256SUMS line"; fi
if cut -c67- "$work/sums" | grep -E '(^|/)\.{1,2}(/|$)|//|/$|^SHA256SUMS(\.sig)?$' >/dev/null; then fail "unsafe path in SHA256SUMS"; fi
cut -c67- "$work/sums" | sort > "$work/listed"
[ -z "$(uniq -d "$work/listed")" ] || fail "a path appears twice in SHA256SUMS"

# 7. The zip.
step "7. zip"
zipline="assets/sdk/${version}/${zipname}"
want="$(awk -v p="$zipline" 'substr($0,67)==p {print substr($0,1,64)}' "$work/sums")"
[ -n "$want" ] || fail "SHA256SUMS has no line for $zipline"
zipsum="$(sha256 "$zip")"
[ "$zipsum" = "$want" ] || fail "zip hash $zipsum does not match SHA256SUMS ($want)"

# 8. The XCFramework inside the zip against the Binaries/ lines.
step "8. XCFramework contents"
unzip -Z1 "$zip" > "$work/entries" || fail "cannot list the zip"
if grep -v -E '^CredentialSdkCore\.xcframework/' "$work/entries" >/dev/null; then fail "zip entry outside CredentialSdkCore.xcframework/"; fi
if grep -E '(^|/)\.\.(/|$)|^/' "$work/entries" >/dev/null; then fail "unsafe zip entry"; fi
mkdir "$work/x"
unzip -q "$zip" -d "$work/x" || fail "cannot extract the zip"
[ -z "$(cd "$work/x" && find . \( -type l -o \( ! -type f ! -type d \) \) -print)" ] || fail "zip holds a symlink or special file"
grep -E '  Binaries/' "$work/sums" | sed 's|  Binaries/|  |' > "$work/bin_sums"
[ -s "$work/bin_sums" ] || fail "SHA256SUMS has no Binaries/ lines"
(cd "$work/x" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c --quiet "$work/bin_sums"; else shasum -a 256 -c --quiet "$work/bin_sums"; fi) >/dev/null 2>&1 \
  || fail "an XCFramework file does not match its Binaries/ line"
cut -c67- "$work/bin_sums" | sort > "$work/bin_listed"
(cd "$work/x" && find . -type f -print) | sed 's|^\./||' | sort > "$work/bin_present"
[ -z "$(comm -23 "$work/bin_present" "$work/bin_listed")" ] || fail "zip holds a file not listed in SHA256SUMS"

# 9. Sources/ and Package.swift, when a checkout of the tag is given.
if [ -n "$source_dir" ]; then
  step "9. Sources/ and Package.swift"
  [ -d "$source_dir/Sources" ] || fail "no Sources/ in $source_dir"
  grep -E '  Sources/' "$work/sums" > "$work/src_sums" || fail "SHA256SUMS has no Sources/ lines"
  (cd "$source_dir" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c --quiet "$work/src_sums"; else shasum -a 256 -c --quiet "$work/src_sums"; fi) >/dev/null 2>&1 \
    || fail "a Sources/ file does not match its SHA256SUMS line"
  [ -z "$(cd "$source_dir" && find Sources \( -type l -o \( ! -type f ! -type d \) \) -print)" ] || fail "Sources/ holds a symlink or special file"
  cut -c67- "$work/src_sums" | sort > "$work/src_listed"
  (cd "$source_dir" && find Sources -type f -print) | sort > "$work/src_present"
  [ -z "$(comm -23 "$work/src_present" "$work/src_listed")" ] || fail "Sources/ holds a file not listed in SHA256SUMS"
  if grep -q 'checksum: *"' "$source_dir/Package.swift" 2>/dev/null; then
    pkgsum="$(sed -n 's/.*checksum: *"\([0-9a-f]\{64\}\)".*/\1/p' "$source_dir/Package.swift")"
    [ "$pkgsum" = "$zipsum" ] || fail "Package.swift checksum $pkgsum does not match the zip ($zipsum)"
  else
    step "   Package.swift carries no binary checksum; checksum comparison skipped"
  fi
else
  step "9. skipped: no --source checkout given; Sources/ not checked"
fi

echo verified
