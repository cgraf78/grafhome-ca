#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: scripts/smoke-release.sh <asset-platform>\n' >&2
  exit 2
fi

asset_platform=$1
case "$asset_platform" in
  *unknown*)
    # Smoke tests run against the same label that gets uploaded. Reject target
    # triples here too so a workflow edit cannot package a clean label but smoke
    # a different, Rust-internal archive name by mistake.
    printf 'asset platform must be a public release label, not a Rust target triple: %s\n' "$asset_platform" >&2
    exit 2
    ;;
esac

tag=$(scripts/release-tag.sh)
archive="dist/grafhome-ca-${tag}-${asset_platform}.tar.gz"
if [[ ! -f "$archive" && -f dist/.grafhome-ca-release-version ]]; then
  # Local dry-runs are not anchored by a pushed release tag. Reuse the package
  # script's recorded version so smoke always verifies the archive produced by
  # the immediately preceding package step.
  tag=$(<dist/.grafhome-ca-release-version)
  case "$tag" in
    '' | *[!A-Za-z0-9._-]*)
      printf 'recorded release version is unsafe for asset names: %s\n' "$tag" >&2
      exit 2
      ;;
  esac
  archive="dist/grafhome-ca-${tag}-${asset_platform}.tar.gz"
fi
smoke=$(mktemp -d)

cleanup() {
  rm -rf "$smoke"
}
trap cleanup EXIT

tar -xzf "$archive" -C "$smoke"

# Keep the smoke test intentionally small and user-facing. Unit tests already
# cover policy/schema behavior; this catches packaging mistakes such as a
# missing executable bit, omitted schema/templates, or archive name drift.
test -x "$smoke/bin/grafhome-ca"
test -f "$smoke/.grafhome-ca-install.json"
test -d "$smoke/schemas"
test -d "$smoke/templates"
test -d "$smoke/examples"

if [[ "$asset_platform" == "android-aarch64" ]]; then
  # The Android artifact is cross-built on an x86_64 runner. Validate its
  # architecture and Bionic loader without trying to execute it on glibc.
  readelf -h "$smoke/bin/grafhome-ca" | grep -Eq 'Machine:[[:space:]]+AArch64'
  readelf -l "$smoke/bin/grafhome-ca" | grep -Fq '/system/bin/linker64'
  exit 0
fi

"$smoke/bin/grafhome-ca" version
"$smoke/bin/grafhome-ca" help >/dev/null
