#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: scripts/package-release.sh <rust-target> <asset-platform>\n' >&2
  exit 2
fi

target=$1
asset_platform=$2

case "$asset_platform" in
  '' | *[!A-Za-z0-9._-]*)
    printf 'asset platform contains characters unsafe for asset names: %s\n' "$asset_platform" >&2
    exit 2
    ;;
  *unknown*)
    # Rust target triples include a vendor field (`unknown` for the targets we
    # use), but that is compiler plumbing rather than user-facing release
    # identity. Require the caller to pass the installer-facing platform label
    # from the release matrix so published assets stay readable and stable.
    printf 'asset platform must be a public release label, not a Rust target triple: %s\n' "$asset_platform" >&2
    exit 2
    ;;
esac

tag=$(scripts/release-tag.sh)
commit=${GRAFHOME_CA_BUILD_COMMIT:-${GITHUB_SHA:-}}
if [[ -z "$commit" ]]; then
  commit=$(git rev-parse HEAD)
fi
if [[ ! "$commit" =~ ^[0-9a-fA-F]{8,}$ ]]; then
  printf 'build commit must be a concrete git hash, got %s\n' "$commit" >&2
  exit 1
fi

asset="grafhome-ca-${tag}-${asset_platform}.tar.gz"
dist_dir=dist
staging=$(mktemp -d)

cleanup() {
  rm -rf "$staging"
}
trap cleanup EXIT

# Release archives are consumed by bootstrap paths that may not have a Rust
# toolchain or a source checkout. Package only the executables plus stable
# non-secret runtime assets.
GRAFHOME_CA_BUILD_COMMIT="$commit" GRAFHOME_CA_BUILD_VERSION="$tag" \
  cargo build --release --locked --target "$target"

mkdir -p "$staging/bin"
install -m 0755 "target/${target}/release/grafhome-ca" "$staging/bin/grafhome-ca"
install -m 0644 README.md "$staging/README.md"
install -m 0644 LICENSE "$staging/LICENSE"

for dir in completions examples schemas templates docs man; do
  if [[ -d "$dir" ]]; then
    mkdir -p "$staging/$dir"
    cp -R "$dir/." "$staging/$dir/"
  fi
done

# Include install metadata in the archive so an extracted release can be
# identified without guessing from filesystem shape. Activation code may rewrite
# or enrich this file at install time, but the packaged copy gives bundled-mode
# installer tests a concrete release identity to validate.
cat >"$staging/.grafhome-ca-install.json" <<EOF
{
  "schema": 1,
  "method": "release",
  "artifact_platform": "$asset_platform",
  "version": "$tag",
  "tag": "$tag",
  "commit": "$commit",
  "repo": "cgraf78/grafhome-ca"
}
EOF

mkdir -p "$dist_dir"
# Local package+smoke loops should test the archive that was actually produced,
# even when the caller is using explicit build env or a source snapshot without
# Git metadata. Real tag releases remain governed by the GitHub tag and do not
# depend on this ignored breadcrumb.
printf '%s\n' "$tag" >"${dist_dir}/.grafhome-ca-release-version"
tar -C "$staging" -czf "${dist_dir}/${asset}" .

# GNU coreutils and macOS expose different checksum commands. Prefer
# `sha256sum` when available, but keep local/macOS release dry-runs independent
# of Homebrew bootstrap state.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$dist_dir" && sha256sum "$asset") >"${dist_dir}/${asset}.sha256"
else
  (cd "$dist_dir" && shasum -a 256 "$asset") >"${dist_dir}/${asset}.sha256"
fi

printf '%s\n' "${dist_dir}/${asset}"
