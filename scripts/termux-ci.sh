#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# The standard matrix owns the full test suite. Execute the NDK-built Android
# binary against the public fixture tree inside the real Termux app sandbox.
.termux-ci/grafhome-ca check --config-root examples/site-config

# Termux intentionally names Smallstep's executable `step-cli`. Exercise an
# interactive public-request-only enrollment to prove client discovery, JWK
# creation, and the Android app-private renewal credential backend all work
# without compatibility shims or systemd.
pkg install -y openssh step-cli
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home"
printf '%s\n' 'termux-ci-renewal-password' | HOME="$tmp/home" .termux-ci/grafhome-ca enroll user \
  --config-root examples/site-config \
  --user alice \
  --host ca-host \
  --request-only >"$tmp/request"
grep -F 'REQUEST:{"version":1' "$tmp/request"

credential="$tmp/home/.config/grafhome-ca/users/alice/hosts/ca-host/renewal-password.secret"
test -s "$credential"
test "$(stat -c '%a' "$credential")" = 600

# Remove the throwaway SSH identity as well as the pending request so the
# noninteractive test does not need /dev/tty for the existing-key prompt. The
# renewal key remains, so this second pass must load the stored password to
# validate and reuse it.
rm "$tmp/home/.config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json"
rm "$tmp/home/.ssh/id_ed25519" "$tmp/home/.ssh/id_ed25519.pub"
HOME="$tmp/home" .termux-ci/grafhome-ca enroll user \
  --config-root examples/site-config \
  --user alice \
  --host ca-host \
  --request-only >"$tmp/restarted-request"
grep -F 'REQUEST:{"version":1' "$tmp/restarted-request"
