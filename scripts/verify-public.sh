#!/usr/bin/env bash
# Verify a Krutho SDK release downloaded from this repository's GitHub Release.
#
#   scripts/verify-public.sh --assets DIR --tag sdk-vX.Y.Z \
#     --root-fingerprint 'SHA256:<fingerprint from Krutho>' \
#     --source DIR [--keys DIR] [--verify-time YYYYMMDD]
#
# --assets       directory holding the release zip, SHA256SUMS and SHA256SUMS.sig
# --source       a checkout of this repository at the release tag
# --keys         the current KEYS/ directory (default: KEYS/ beside scripts/)
# --verify-time  check the signing certificate as of that date, for a release
#                signed by a certificate that has since expired
# --allow-path-binary
#                accept the canonical git-delivered manifest (scripts/
#                Package.swift.expected-path.in), whose binary target is the
#                committed Binaries/ directory, instead of the release zip;
#                for checking an older git-delivered release only
#
# Last line `verified` and exit 0 on success. Any failed check, and any
# unexpected error, prints `FAIL: <cause>` as the last line and exits 1. A usage
# error exits 2. VERIFY.md gives the same steps by hand.
set -eEuo pipefail
export LC_ALL=C

fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
trap 'printf "FAIL: unexpected error at line %s\n" "$LINENO"; exit 1' ERR
usage() { printf 'usage: %s --assets DIR --tag sdk-vX.Y.Z --root-fingerprint SHA256:... --source DIR [--keys DIR] [--verify-time YYYYMMDD] [--allow-path-binary]\n' "$0" >&2; exit 2; }
step() { printf '%s\n' "$*"; }

assets="" tag="" fpr="" keys="" source_dir="" verify_time="" allow_path=0
while [ $# -gt 0 ]; do
  case "$1" in
    --assets) [ $# -ge 2 ] || usage; assets="$2"; shift 2 ;;
    --tag) [ $# -ge 2 ] || usage; tag="$2"; shift 2 ;;
    --root-fingerprint) [ $# -ge 2 ] || usage; fpr="$2"; shift 2 ;;
    --keys) [ $# -ge 2 ] || usage; keys="$2"; shift 2 ;;
    --source) [ $# -ge 2 ] || usage; source_dir="$2"; shift 2 ;;
    --verify-time) [ $# -ge 2 ] || usage; verify_time="$2"; shift 2 ;;
    --allow-path-binary) allow_path=1; shift ;;
    *) usage ;;
  esac
done
[ -n "$assets" ] && [ -n "$tag" ] && [ -n "$fpr" ] && [ -n "$source_dir" ] || usage
[[ "$tag" =~ ^sdk-v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || { echo "tag must look like sdk-v1.2.3" >&2; exit 2; }
version="${BASH_REMATCH[1]}"
if [ -n "$verify_time" ] && ! [[ "$verify_time" =~ ^[0-9]{8}([0-9]{4}([0-9]{2})?)?Z?$ ]]; then
  echo "verify time must be YYYYMMDD[HHMM[SS]][Z]" >&2; exit 2
fi
[ -n "$keys" ] || keys="$(cd "$(dirname "$0")/.." && pwd)/KEYS"
[ -d "$assets" ] || fail "no assets directory at $assets"
[ -d "$source_dir" ] || fail "no source checkout at $source_dir"
[ -d "$keys" ] || fail "no KEYS directory at $keys"
for k in release-root.pub revocation.txt revocation.txt.sig revoked.krl; do
  [ -f "$keys/$k" ] && [ ! -L "$keys/$k" ] || fail "missing or not a regular file: $keys/$k"
done
for t in ssh-keygen unzip zipinfo awk sed sort comm uniq find; do
  command -v "$t" >/dev/null 2>&1 || fail "required tool not found: $t"
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
  sha256_check() { sha256sum -c --quiet "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
  sha256_check() { shasum -a 256 -c --quiet "$1"; }
else
  fail "neither sha256sum nor shasum found"
fi

zipname="krutho-credential-sdk-${version}-CredentialSdkCore.xcframework.zip"
zip="$assets/$zipname"
sums="$assets/SHA256SUMS"
sig="$assets/SHA256SUMS.sig"
for f in "$zip" "$sums" "$sig"; do
  [ -f "$f" ] && [ ! -L "$f" ] || fail "missing or not a regular file: $f"
done

work="$(mktemp -d 2>/dev/null)" || fail "cannot create a temporary directory"
[ -n "$work" ] && [ -d "$work" ] || fail "cannot create a temporary directory"
trap 'rm -rf "$work"' EXIT

# 1. Root key pin.
step "1. root key pin"
[ "$(grep -c . "$keys/release-root.pub" || true)" = 1 ] || fail "release-root.pub must hold exactly one key"
got="$(ssh-keygen -l -E sha256 -f "$keys/release-root.pub" 2>/dev/null | cut -d' ' -f2)" || fail "release-root.pub is not a valid public key"
[ -n "$got" ] || fail "release-root.pub is not a valid public key"
[ "$got" = "$fpr" ] || fail "root key fingerprint $got does not match $fpr"
rootkey="$(cut -d' ' -f1,2 "$keys/release-root.pub")"

# 2. Revocation statement signature, by the root key itself.
step "2. revocation statement signature"
printf 'krutho-root namespaces="krutho-revocation" %s\n' "$rootkey" > "$work/allowed_root"
ssh-keygen -Y verify -f "$work/allowed_root" -I krutho-root -n krutho-revocation \
  -s "$keys/revocation.txt.sig" < "$keys/revocation.txt" >/dev/null 2>&1 \
  || fail "revocation.txt signature does not verify against the root key"

# 3. The statement's form; the revocation list is the one it names and parses as a KRL.
step "3. revocation list"
if grep -v -E '^(sequence: [1-9][0-9]*|issued: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z|next_update: [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z|krl_sha256: [0-9a-f]{64}|recovery_sha256: [0-9a-f]{64})$' "$keys/revocation.txt" >/dev/null; then
  fail "revocation.txt has an unexpected line"
fi
for k in sequence issued next_update krl_sha256; do
  [ "$(grep -c "^$k: " "$keys/revocation.txt" || true)" = 1 ] || fail "revocation.txt must carry exactly one $k line"
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
vt=()
[ -z "$verify_time" ] || vt=(-O "verify-time=$verify_time")
ssh-keygen -Y verify -f "$work/allowed_signers" -I krutho-release -n krutho-release \
  -s "$sig" -r "$keys/revoked.krl" ${vt[@]+"${vt[@]}"} < "$sums" >/dev/null 2>&1 \
  || fail "SHA256SUMS.sig does not verify: signer revoked, certificate expired (see --verify-time), or files changed; contact Krutho"

# 6. SHA256SUMS form and tag.
step "6. SHA256SUMS form and tag"
[ "$(head -n 1 "$sums")" = "# tag: $tag" ] || fail "SHA256SUMS is signed for '$(head -n 1 "$sums")', not '# tag: $tag'"
tail -n +2 "$sums" > "$work/sums"
[ -s "$work/sums" ] || fail "SHA256SUMS lists no files"
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

# 8. The XCFramework inside the zip against the Binaries/ lines. Entries are
#    checked from the listing before anything is extracted.
step "8. XCFramework contents"
zipinfo -1 "$zip" > "$work/entries" 2>/dev/null || fail "cannot list the zip"
[ -s "$work/entries" ] || fail "the zip is empty"
if grep -v -E '^CredentialSdkCore\.xcframework/' "$work/entries" >/dev/null; then fail "zip entry outside CredentialSdkCore.xcframework/"; fi
if grep -E '(^|/)\.\.(/|$)|^/|\\|//' "$work/entries" >/dev/null; then fail "unsafe zip entry name"; fi
if grep -v -E '^[A-Za-z0-9._+@/-]+$' "$work/entries" >/dev/null; then fail "zip entry name with an unexpected character"; fi
zipinfo "$zip" 2>/dev/null | sed '1,2d;$d' | awk '{print substr($1,1,1)}' > "$work/types" || fail "cannot read zip entry types"
[ "$(wc -l < "$work/types")" -eq "$(wc -l < "$work/entries")" ] || fail "zip listing is inconsistent"
if grep -v -E '^[-d]$' "$work/types" >/dev/null; then fail "zip listing holds a symlink, special file or untyped entry"; fi
mkdir "$work/x"
unzip -q "$zip" -d "$work/x" >/dev/null 2>&1 || fail "cannot extract the zip"
[ -z "$(cd "$work/x" && find . \( -type l -o \( ! -type f ! -type d \) \) -print)" ] || fail "zip holds a symlink or special file"
grep -E '  Binaries/' "$work/sums" | sed 's|  Binaries/|  |' > "$work/bin_sums" || fail "SHA256SUMS has no Binaries/ lines"
(cd "$work/x" && sha256_check "$work/bin_sums") >/dev/null 2>&1 \
  || fail "an XCFramework file does not match its Binaries/ line"
cut -c67- "$work/bin_sums" | sort > "$work/bin_listed"
(cd "$work/x" && find . -type f -print) | sed 's|^\./||' | sort > "$work/bin_present"
[ -z "$(comm -23 "$work/bin_present" "$work/bin_listed")" ] || fail "zip holds a file not listed in SHA256SUMS"

# 9. Sources/ at the tag.
step "9. Sources/"
[ -d "$source_dir/Sources" ] || fail "no Sources/ in $source_dir"
grep -E '  Sources/' "$work/sums" > "$work/src_sums" || fail "SHA256SUMS has no Sources/ lines"
(cd "$source_dir" && sha256_check "$work/src_sums") >/dev/null 2>&1 \
  || fail "a Sources/ file does not match its SHA256SUMS line"
[ -z "$(cd "$source_dir" && find Sources \( -type l -o \( ! -type f ! -type d \) \) -print)" ] || fail "Sources/ holds a symlink or special file"
cut -c67- "$work/src_sums" | sort > "$work/src_listed"
(cd "$source_dir" && find Sources -type f -print) | sort > "$work/src_present"
[ -z "$(comm -23 "$work/src_present" "$work/src_listed")" ] || fail "Sources/ holds a file not listed in SHA256SUMS"

# 10. The checkout's top level holds only expected entries, and Package.swift
#     equals the canonical manifest, byte for byte. The manifest is
#     not in SHA256SUMS; scripts/Package.swift.expected.in is rendered with this
#     release's tag, version, zip name and zip hash, and the file must equal it.
#     Nothing else in Package.swift is accepted: no extra dependency, target,
#     flag, comment, conditional or string.
step "10. top-level entries and Package.swift"
# The checkout holds only the entries a release writes. SwiftPM also reads
# Package@swift-X.Y.swift, Plugins/ and .swiftpm, so any other top-level entry,
# any symlink and any other Package*.swift fails.
find "$source_dir" -mindepth 1 -maxdepth 1 -print0 > "$work/top"
while IFS= read -r -d '' entry; do
  name="${entry##*/}"
  [ ! -L "$entry" ] || fail "top-level entry is a symlink: $name"
  case "$name" in
    Package.swift|README.md|VERIFY.md|LICENSE|SECURITY.md|CHANGELOG.md) kind=f ;;
    Sources|KEYS|scripts|notes) kind=d ;;
    .git) kind=g ;;
    CODEOWNERS|releases.json|releases.schema.json|SHA256SUMS|SHA256SUMS.sig) # git-delivered proof tree only
      [ "$allow_path" = 1 ] || fail "unexpected top-level entry in the source checkout: $name"; kind=f ;;
    Binaries|assets|spike)
      [ "$allow_path" = 1 ] || fail "unexpected top-level entry in the source checkout: $name"; kind=d ;;
    *) fail "unexpected top-level entry in the source checkout: $name" ;;
  esac
  case "$kind" in
    f) [ -f "$entry" ] || fail "top-level entry is not a regular file: $name" ;;
    d) [ -d "$entry" ] || fail "top-level entry is not a directory: $name" ;;
  esac
done < "$work/top"
pkg="$source_dir/Package.swift"
[ -f "$pkg" ] && [ ! -L "$pkg" ] || fail "no Package.swift in $source_dir"
script_dir="$(cd "$(dirname "$0")" && pwd)"
render() {
  [ -f "$1" ] && [ ! -L "$1" ] || fail "missing or not a regular file: $1"
  sed -e "s|@VERSION@|${version}|g" -e "s|@TAG@|${tag}|g" -e "s|@PUBLIC_REPO@|Krutho-com/krutho-sdk-swift|g" \
    -e "s|@ZIP@|${zipname}|g" -e "s|@CHECKSUM@|${zipsum}|g" "$1" > "$2"
  ! grep -q '@[A-Z_]*@' "$2" || fail "canonical manifest template holds an unreplaced placeholder"
}
show_diff() { diff -u "$1" "$pkg" | cat -v | head -n 20 >&2 || true; }
render "$script_dir/Package.swift.expected.in" "$work/Package.swift.expected"
if cmp -s "$work/Package.swift.expected" "$pkg"; then
  step "   Package.swift equals the canonical manifest for $tag"
elif [ "$allow_path" = 1 ]; then
  render "$script_dir/Package.swift.expected-path.in" "$work/Package.swift.expected-path"
  if ! cmp -s "$work/Package.swift.expected-path" "$pkg"; then
    show_diff "$work/Package.swift.expected-path"
    fail "Package.swift is neither the canonical manifest nor the canonical path: manifest for $tag"
  fi
  sed 's|  |  Binaries/|' "$work/bin_sums" > "$work/bin_sums.path"
  (cd "$source_dir" && sha256_check "$work/bin_sums.path") >/dev/null 2>&1 \
    || fail "a committed Binaries/ file does not match its SHA256SUMS line"
  (cd "$source_dir" && find Binaries -type f -print) | sed 's|^Binaries/||' | sort > "$work/srcbin_present"
  [ -z "$(comm -23 "$work/srcbin_present" "$work/bin_listed")" ] || fail "Binaries/ holds a file not listed in SHA256SUMS"
  [ -z "$(cd "$source_dir" && find Binaries \( -type l -o \( ! -type f ! -type d \) \) -print)" ] || fail "Binaries/ holds a symlink or special file"
  step "   path: form accepted (--allow-path-binary); committed Binaries/ checked"
else
  show_diff "$work/Package.swift.expected"
  fail "Package.swift differs from the canonical manifest for $tag"
fi

echo verified
