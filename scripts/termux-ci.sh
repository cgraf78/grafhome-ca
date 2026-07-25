#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# The standard matrix owns the full test suite. Execute the NDK-built Android
# binary against the public fixture tree inside the real Termux app sandbox.
.termux-ci/grafhome-ca check --config-root examples/site-config

tmp=$(mktemp -d)
sshd_pid=
sshd_dropin=
ssh_dropin=
real_principals_dir=
cleanup() {
  if [[ -n "$sshd_pid" ]]; then
    kill "$sshd_pid" 2>/dev/null || true
    wait "$sshd_pid" 2>/dev/null || true
  fi
  [[ -z "$sshd_dropin" ]] || rm -f "$sshd_dropin"
  [[ -z "$ssh_dropin" ]] || rm -f "$ssh_dropin"
  [[ -z "$real_principals_dir" ]] || rm -rf "$real_principals_dir"
  rm -rf "$tmp"
}
trap cleanup EXIT

# Termux intentionally names Smallstep's executable `step-cli`. Exercise an
# interactive public-request-only enrollment to prove client discovery, JWK
# creation, and the Android app-private renewal credential backend all work
# without compatibility shims or systemd.
pkg install -y openssh step-cli termux-services

# Prove the package's default configs actually load both drop-in directories.
sshd_dropin="$PREFIX/etc/ssh/sshd_config.d/grafhome-ca-ci.conf"
ssh_dropin="$PREFIX/etc/ssh/ssh_config.d/grafhome-ca-ci.conf"
sshd -T >"$tmp/sshd-baseline-config"
if ! grep -iq '^authorizedkeysfile ' "$tmp/sshd-baseline-config"; then
  printf '%s\n' 'Termux OpenSSH baseline did not expose AuthorizedKeysFile' >&2
  exit 1
fi
printf '%s\n' \
  'MaxAuthTries 5' \
  'StrictModes no' \
  'AuthorizedKeysFile none' >"$sshd_dropin"
printf '%s\n' 'ConnectTimeout 17' >"$ssh_dropin"
chmod 0644 "$sshd_dropin" "$ssh_dropin"
if ! sshd -T >"$tmp/sshd-effective-config" 2>"$tmp/sshd-effective-error"; then
  cat "$tmp/sshd-effective-error" >&2
  exit 1
fi
for expected in 'maxauthtries 5' 'strictmodes no'; do
  if ! grep -iqx "$expected" "$tmp/sshd-effective-config"; then
    printf 'missing effective sshd setting: %s\n' "$expected" >&2
    grep -Ei 'maxauthtries|strictmodes|authorizedkeysfile' \
      "$tmp/sshd-effective-config" >&2 || true
    exit 1
  fi
done
# OpenSSH 10 omits this setting from `-T` when its effective value is `none`.
if grep -iq '^authorizedkeysfile ' "$tmp/sshd-effective-config"; then
  printf '%s\n' 'AuthorizedKeysFile none was not effective' >&2
  grep -i '^authorizedkeysfile ' "$tmp/sshd-effective-config" >&2
  exit 1
fi
if ! ssh -G termux-ci.invalid >"$tmp/ssh-effective-config" 2>"$tmp/ssh-effective-error"; then
  cat "$tmp/ssh-effective-error" >&2
  exit 1
fi
if ! grep -iqx 'connecttimeout 17' "$tmp/ssh-effective-config"; then
  grep -i connecttimeout "$tmp/ssh-effective-config" >&2 || true
  exit 1
fi
rm "$sshd_dropin" "$ssh_dropin"
sshd -t

# A quiet, unenrolled host status traverses the real app-owned HOME/PREFIX
# preflight without changing either tree. This exercises package modes,
# executable provenance, and the complete existing OpenSSH subtree.
set +e
TERMUX_VERSION="${TERMUX_VERSION:-ci}" .termux-ci/grafhome-ca status \
  --config-root examples/site-config \
  --host proxy-host \
  --quiet >"$tmp/real-prefix-status.out" 2>"$tmp/real-prefix-status.err"
status_rc=$?
set -e
if [[ "$status_rc" -ne 1 ]] || [[ -s "$tmp/real-prefix-status.out" ]] ||
  [[ -s "$tmp/real-prefix-status.err" ]]; then
  printf 'unexpected quiet real-prefix status result: %s\n' "$status_rc" >&2
  cat "$tmp/real-prefix-status.out" "$tmp/real-prefix-status.err" >&2
  exit 1
fi
mkdir -p "$tmp/home"
printf '%s\n' 'termux-ci-renewal-password' | env -u TERMUX_VERSION HOME="$tmp/home" \
  .termux-ci/grafhome-ca enroll user \
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
env -u TERMUX_VERSION HOME="$tmp/home" .termux-ci/grafhome-ca enroll user \
  --config-root examples/site-config \
  --user alice \
  --host ca-host \
  --request-only >"$tmp/restarted-request"
grep -F 'REQUEST:{"version":1' "$tmp/restarted-request"

# Prove the real Termux OpenSSH server accepts the stable requested login even
# though Android exposes a generated local account. Termux maps the request to
# the app owner; the explicit principals file avoids OpenSSH's %u expansion to
# that device-specific account name.
real_sshd="$tmp/real-sshd"
mkdir -p "$real_sshd"
chmod 0700 "$real_sshd"
ssh-keygen -q -N '' -t ed25519 -f "$real_sshd/host-key"
ssh-keygen -q -N '' -t ed25519 -f "$real_sshd/user-ca"
ssh-keygen -q -N '' -t ed25519 -f "$real_sshd/user-key"
ssh-keygen -q -N '' -t ed25519 -f "$real_sshd/unsigned-key"
ssh-keygen -q -s "$real_sshd/user-ca" -I termux-ci-user -n policyuser \
  -V -1m:+5m "$real_sshd/user-key.pub"
real_principals_dir="$HOME/.ssh/grafhome-ci-$$"
mkdir -p "$real_principals_dir"
chmod 0700 "$real_principals_dir"
printf '%s\n' policyuser >"$real_principals_dir/termux-owner"
chmod 0644 "$real_principals_dir/termux-owner"
port=$((20000 + ($$ % 20000)))
cat >"$real_sshd/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
PidFile $real_sshd/sshd.pid
HostKey $real_sshd/host-key
TrustedUserCAKeys $real_sshd/user-ca.pub
AuthorizedPrincipalsFile $real_principals_dir/termux-owner
AuthorizedKeysFile none
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
EOF
sshd -D -e -f "$real_sshd/sshd_config" >"$real_sshd/sshd.log" 2>&1 &
sshd_pid=$!
connected=false
for _ in $(seq 1 40); do
  if ssh -F /dev/null -p "$port" \
    -i "$real_sshd/user-key" \
    -o CertificateFile="$real_sshd/user-key-cert.pub" \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes \
    policyuser@127.0.0.1 "test \"\$(id -u)\" = \"$(id -u)\""; then
    connected=true
    break
  fi
  kill -0 "$sshd_pid" 2>/dev/null || break
  sleep 0.25
done
if [[ "$connected" != true ]]; then
  cat "$real_sshd/sshd.log" >&2
  exit 1
fi
set +e
ssh -F /dev/null -p "$port" \
  -i "$real_sshd/unsigned-key" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes \
  policyuser@127.0.0.1 true
unsigned_key_rc=$?
set -e
if [[ "$unsigned_key_rc" -eq 0 ]]; then
  printf '%s\n' 'Termux sshd accepted an unsigned static key' >&2
  exit 1
fi
printf '%s\n' 'ok: Termux sshd accepted the CA certificate and rejected a static key'
kill "$sshd_pid" 2>/dev/null || true
wait "$sshd_pid" 2>/dev/null || true
sshd_pid=

# Revoke the underlying user key, restart the real Termux sshd with the KRL,
# and prove that neither the existing certificate nor a renewed certificate
# for that same key can authenticate.
ssh-keygen -q -k -f "$real_sshd/revoked.krl" "$real_sshd/user-key.pub"
printf 'RevokedKeys %s\n' "$real_sshd/revoked.krl" >>"$real_sshd/sshd_config"
sshd -t -f "$real_sshd/sshd_config"
sshd -D -e -f "$real_sshd/sshd_config" >"$real_sshd/sshd.log" 2>&1 &
sshd_pid=$!
listener_ready=false
for _ in $(seq 1 40); do
  if ssh-keyscan -p "$port" 127.0.0.1 >/dev/null 2>&1; then
    listener_ready=true
    break
  fi
  kill -0 "$sshd_pid" 2>/dev/null || break
  sleep 0.25
done
if [[ "$listener_ready" != true ]]; then
  cat "$real_sshd/sshd.log" >&2
  exit 1
fi
for certificate_id in existing renewed; do
  if [[ "$certificate_id" == renewed ]]; then
    ssh-keygen -q -s "$real_sshd/user-ca" -I termux-ci-user-renewed \
      -n policyuser -V -1m:+5m "$real_sshd/user-key.pub"
  fi
  set +e
  ssh -F /dev/null -p "$port" \
    -i "$real_sshd/user-key" \
    -o CertificateFile="$real_sshd/user-key-cert.pub" \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes \
    policyuser@127.0.0.1 true
  revoked_key_rc=$?
  set -e
  if [[ "$revoked_key_rc" -eq 0 ]]; then
    printf 'Termux sshd accepted the %s certificate for a revoked key\n' \
      "$certificate_id" >&2
    exit 1
  fi
done
printf '%s\n' 'ok: Termux sshd KRL rejected existing and renewed certificates for the revoked key'
kill "$sshd_pid" 2>/dev/null || true
wait "$sshd_pid" 2>/dev/null || true
sshd_pid=

# Exercise the rootless Termux SSH-server backend with an isolated app prefix.
# Command shims keep this deterministic while the Android binary owns path
# localization, host enrollment state, rendered OpenSSH policy, and reload
# selection exactly as it does on a phone.
termux_home="$tmp/server-home"
termux_prefix="$tmp/server-prefix"
termux_bin="$termux_prefix/bin"
termux_ssh="$termux_prefix/etc/ssh"
termux_log="$tmp/server.log"
hostile_bin="$tmp/hostile-bin"
hostile_log="$tmp/hostile.log"
mkdir -p "$termux_home" "$termux_bin" "$termux_ssh" "$hostile_bin"
chmod 0700 "$termux_home" "$termux_prefix" "$termux_prefix/etc" \
  "$termux_bin" "$termux_ssh" "$hostile_bin"
cp -R examples/site-config "$termux_home/site-config"
termux_config="$termux_home/site-config"
chmod -R go-w "$termux_config"
printf '%s\n' 'host-private' >"$termux_ssh/ssh_host_ed25519_key"
printf '%s\n' 'ssh-ed25519 AAAAhostpublic termux-ci' \
  >"$termux_ssh/ssh_host_ed25519_key.pub"
chmod 0600 "$termux_ssh/ssh_host_ed25519_key"
chmod 0644 "$termux_ssh/ssh_host_ed25519_key.pub"

cat >"$termux_bin/step-cli" <<'SH'
#!/data/data/com.termux/files/usr/bin/sh
set -eu
printf 'step args=%s\n' "$*" >>"$TERMUX_SERVER_LOG"
case "$1 $2" in
  'crypto jwk')
    printf '%s\n' '{"kty":"OKP","crv":"Ed25519","x":"public"}' >"$4"
    printf '%s\n' '{"kty":"OKP","crv":"Ed25519","x":"public","d":"private"}' >"$5"
    ;;
  'ssh config')
    case " $* " in
      *' --host '*) printf '%s\n' 'ssh-ed25519 AAAAhostca grafhome-host-ca' ;;
      *) printf '%s\n' 'ssh-ed25519 AAAAuserca grafhome-user-ca' ;;
    esac
    ;;
  'ssh needs-renewal') exit 0 ;;
  'ca token') printf '%s\n' 'termux-host-token' ;;
  'ssh certificate')
    public_key="$4"
    printf '%s\n' 'termux-host-certificate' >"${public_key%.pub}-cert.pub"
    /data/data/com.termux/files/usr/bin/chmod 0666 \
      "${public_key%.pub}-cert.pub"
    ;;
esac
SH

cat >"$termux_bin/ssh-keygen" <<'SH'
#!/data/data/com.termux/files/usr/bin/sh
set -eu
printf 'ssh-keygen args=%s\n' "$*" >>"$TERMUX_SERVER_LOG"
if [ "$1" = "-k" ]; then
  out=""
  source=""
  previous=""
  for argument in "$@"; do
    if [ "$previous" = "-f" ]; then out="$argument"; fi
    source="$argument"
    previous="$argument"
  done
  if [ ! -e "$out" ]; then printf 'FAKE-KRL\n' >"$out"; fi
  while IFS= read -r key || [ -n "$key" ]; do
    [ -z "$key" ] || printf '%s\n' "$key" >>"$out"
  done <"$source"
elif [ "$1" = "-Q" ]; then
  krl=""
  source=""
  previous=""
  list=0
  for argument in "$@"; do
    if [ "$argument" = "-l" ]; then list=1; fi
    if [ "$previous" = "-f" ]; then krl="$argument"; fi
    source="$argument"
    previous="$argument"
  done
  header=""
  IFS= read -r header <"$krl" || true
  [ "$header" = "FAKE-KRL" ] || exit 44
  [ "$list" -eq 0 ] || exit 0
  while IFS= read -r key || [ -n "$key" ]; do
    [ -n "$key" ] || continue
    found=0
    while IFS= read -r candidate || [ -n "$candidate" ]; do
      if [ "$candidate" = "$key" ]; then found=1; fi
    done <"$krl"
    [ "$found" -eq 1 ] || exit 0
  done <"$source"
  exit 1
fi
SH

cat >"$termux_bin/ssh" <<'SH'
#!/data/data/com.termux/files/usr/bin/sh
set -eu
printf 'ssh args=%s\n' "$*" >>"$TERMUX_SERVER_LOG"
SH

cat >"$termux_bin/sshd" <<'SH'
#!/data/data/com.termux/files/usr/bin/sh
set -eu
printf 'sshd args=%s\n' "$*" >>"$TERMUX_SERVER_LOG"
SH

cat >"$termux_bin/sv" <<'SH'
#!/data/data/com.termux/files/usr/bin/sh
set -eu
printf 'sv args=%s\n' "$*" >>"$TERMUX_SERVER_LOG"
SH
chmod 0755 "$termux_bin/step-cli" "$termux_bin/ssh" "$termux_bin/ssh-keygen" \
  "$termux_bin/sshd" "$termux_bin/sv"

for executable in step-cli ssh ssh-keygen sshd sv; do
  cat >"$hostile_bin/$executable" <<'SH'
#!/data/data/com.termux/files/usr/bin/sh
printf '%s\n' "$0" >>"$TERMUX_HOSTILE_LOG"
exit 99
SH
  chmod 0755 "$hostile_bin/$executable"
done

termux_env=(
  env
  HOME="$termux_home"
  PREFIX="$termux_prefix"
  TERMUX_VERSION="ci"
  PATH="$hostile_bin:$termux_bin"
  TERMUX_SERVER_LOG="$termux_log"
  TERMUX_HOSTILE_LOG="$hostile_log"
)

# CA-origin mutation remains a real-root boundary. The app-owner exception is
# limited to host lifecycle operations even inside the Termux sandbox.
if "${termux_env[@]}" .termux-ci/grafhome-ca apply ca \
  --config-root "$termux_config" >"$tmp/termux-apply-ca.out" 2>"$tmp/termux-apply-ca.err"; then
  printf '%s\n' 'Termux app owner unexpectedly passed the CA mutation root guard' >&2
  exit 1
fi
if ! grep -Fq 'must be run as root' "$tmp/termux-apply-ca.err"; then
  printf '%s\n' 'unexpected Termux CA mutation rejection:' >&2
  cat "$tmp/termux-apply-ca.err" >&2
  exit 1
fi
test ! -s "$tmp/termux-apply-ca.out"
test ! -e "$termux_log"
test ! -e "$hostile_log"
printf '%s\n' 'ok: Termux CA mutation requires real root'

# Host renewal credentials must never traverse a symlink out of the private
# Termux home, even when every process involved runs as the app owner.
bad_home="$tmp/bad-server-home"
exposed="$tmp/exposed"
mkdir -p "$bad_home/.config" "$exposed"
chmod 0700 "$bad_home" "$bad_home/.config"
cp -R examples/site-config "$bad_home/site-config"
chmod -R go-w "$bad_home/site-config"
ln -s "$exposed" "$bad_home/.config/grafhome"
if env \
  HOME="$bad_home" \
  PREFIX="$termux_prefix" \
  TERMUX_VERSION=ci \
  PATH="$termux_bin" \
  TERMUX_SERVER_LOG="$termux_log" \
  .termux-ci/grafhome-ca enroll host \
  --host proxy-host \
  --config-root "$bad_home/site-config" \
  --request-only >"$tmp/bad-host-request" 2>"$tmp/bad-host-error"; then
  printf '%s\n' 'Termux server flow accepted a symlinked credential path' >&2
  exit 1
fi
if ! grep -Fq 'must not contain symlinks' "$tmp/bad-host-error"; then
  printf '%s\n' 'unexpected symlink-path rejection:' >&2
  cat "$tmp/bad-host-error" >&2
  exit 1
fi
test ! -e "$exposed/host-step"
printf '%s\n' 'ok: Termux host credentials reject symlinked paths'

"${termux_env[@]}" .termux-ci/grafhome-ca enroll host \
  --host proxy-host \
  --config-root "$termux_config" \
  --request-only >"$tmp/host-request"
grep -F 'REQUEST:{"version":1' "$tmp/host-request"

host_step="$termux_home/.config/grafhome/host-step"
test -s "$host_step/secrets/hosts/proxy-host/provisioner.priv.json"
test -s "$host_step/secrets/hosts/proxy-host/renewal-password"
for private_dir in \
  "$termux_home/.config" \
  "$termux_home/.config/grafhome" \
  "$host_step" \
  "$host_step/secrets" \
  "$host_step/secrets/hosts" \
  "$host_step/secrets/hosts/proxy-host"; do
  test "$(stat -c '%a' "$private_dir")" = 700
done
test "$(stat -c '%a' "$host_step/secrets/hosts/proxy-host/provisioner.priv.json")" = 600
test "$(stat -c '%a' "$host_step/secrets/hosts/proxy-host/provisioner.pub.json")" = 644
test "$(stat -c '%a' "$host_step/secrets/hosts/proxy-host/renewal-password")" = 600
mkdir -p "$host_step/certs"
chmod 0700 "$host_step/certs"
printf '%s\n' 'root' >"$host_step/certs/root_ca.crt"
chmod 0644 "$host_step/certs/root_ca.crt"

(
  umask 000
  "${termux_env[@]}" .termux-ci/grafhome-ca apply host \
    --host proxy-host \
    --config-root "$termux_config"
)
server_config="$termux_ssh/sshd_config.d/grafhome-ca.conf"
client_config="$termux_ssh/ssh_config.d/grafhome-ca.conf"
grep -F "HostCertificate $termux_ssh/ssh_host_ed25519_key-cert.pub" "$server_config"
grep -F "TrustedUserCAKeys $termux_ssh/grafhome/user_ca_keys.pem" "$server_config"
grep -F "RevokedKeys $termux_ssh/grafhome/revoked_user_certs" "$server_config"
grep -F "RevokedHostKeys $termux_ssh/grafhome/revoked_host_keys" "$client_config"
test "$(cat "$termux_home/.ssh/grafhome/termux-owner")" = alice
test "$(stat -c '%a' "$termux_home/.ssh")" = 700
test "$(stat -c '%a' "$termux_home/.ssh/grafhome")" = 700
test "$(stat -c '%a' "$termux_ssh/grafhome")" = 700
test "$(stat -c '%a' "$termux_ssh/sshd_config.d")" = 700
test "$(stat -c '%a' "$termux_ssh/ssh_config.d")" = 700
for krl in revoked_user_certs revoked_host_keys; do
  test "$(stat -c '%a' "$termux_ssh/grafhome/$krl")" = 644
  test "$(head -n 1 "$termux_ssh/grafhome/$krl")" = FAKE-KRL
done

"${termux_env[@]}" .termux-ci/grafhome-ca renew host \
  --host proxy-host \
  --config-root "$termux_config"
test -s "$termux_ssh/ssh_host_ed25519_key-cert.pub"
test "$(stat -c '%a' "$termux_ssh/ssh_host_ed25519_key-cert.pub")" = 644
grep -F 'sshd args=-t' "$termux_log"
grep -F 'ssh args=-G -F' "$termux_log"
grep -F 'sv args=hup sshd' "$termux_log"
test ! -e "$hostile_log"
if grep -Fq 'systemctl' "$termux_log"; then
  printf '%s\n' 'Termux server flow unexpectedly invoked systemctl' >&2
  exit 1
fi
