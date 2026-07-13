#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# The standard matrix owns the full test suite. Execute the NDK-built Android
# binary against the public fixture tree inside the real Termux app sandbox.
.termux-ci/grafhome-ca check --config-root examples/site-config

# Termux intentionally names Smallstep's executable `step-cli`. Exercise a
# public-request-only enrollment to prove client discovery and JWK creation use
# the native package without a compatibility symlink.
pkg install -y openssh step-cli
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home"
printf '%s\n' 'termux-ci-renewal-password' >"$tmp/password"
HOME="$tmp/home" .termux-ci/grafhome-ca enroll user \
  --config-root examples/site-config \
  --user alice \
  --host ca-host \
  --password-file "$tmp/password" \
  --request-only >"$tmp/request"
grep -F 'REQUEST:{"version":1' "$tmp/request"
