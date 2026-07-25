use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[cfg(unix)]
const USER_ENROLLMENT_CA_JSON: &str = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-user-enrollment","key":{"kid":"enrollment-kid","kty":"EC"},"encryptedKey":"encrypted-enrollment","claims":{"defaultUserSSHCertDuration":"24h","maxUserSSHCertDuration":"2562047h","enableSSHCA":true}}]}}"#;
#[cfg(unix)]
const HOST_BOOTSTRAP_CA_JSON: &str = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-host-bootstrap","key":{"kid":"bootstrap-kid","kty":"EC"},"encryptedKey":"encrypted-bootstrap","claims":{"defaultHostSSHCertDuration":"168h","maxHostSSHCertDuration":"720h","enableSSHCA":true}}]}}"#;
#[cfg(unix)]
const VALID_SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOF9AFZbHgCPqUAtsZo9RLg6Fg4R+6rKThonym0jI0x3 fixture";
#[cfg(unix)]
const VALID_SSH_KEY_TWO: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/YQ6c6N8hXDSaeqEQ1UvUgrymxo5vYQNy/1KO4HPpw test@fixture";

fn example_config_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/site-config")
}

fn legacy_config_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/legacy-site-config")
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let source = entry.path();
        let target = to.join(entry.file_name());
        if source.is_dir() {
            copy_dir(&source, &target);
        } else {
            fs::copy(&source, &target).unwrap();
        }
    }
}

#[cfg(unix)]
fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
fn prepend_path(dir: &Path) -> String {
    let old = std::env::var_os("PATH")
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{}:{old}", dir.display())
}

#[cfg(unix)]
fn trusted_tempdir() -> tempfile::TempDir {
    if rustix::process::geteuid().is_root() {
        tempfile::Builder::new()
            .prefix(".grafhome-ca-test-")
            .tempdir_in("/root")
            .unwrap()
    } else {
        tempdir().unwrap()
    }
}

#[cfg(unix)]
struct ExecFixture {
    config_root: PathBuf,
    fake_bin: PathBuf,
    log: PathBuf,
    host_key: PathBuf,
}

#[cfg(unix)]
fn exec_fixture() -> (tempfile::TempDir, ExecFixture) {
    let dir = trusted_tempdir();
    let config_root = dir.path().join("grafhome-ca");
    let fake_bin = dir.path().join("bin");
    let state = dir.path().join("state");
    let server_step = dir.path().join("server-step");
    let host_key = dir.path().join("ssh_host_ed25519_key");
    let password = state.join("secrets/intermediate_ca_password");
    let log = dir.path().join("calls.log");

    copy_dir(&example_config_root(), &config_root);
    fs::write(
        config_root.join("policy/revocations.toml"),
        "format_version = 1\n",
    )
    .unwrap();
    let origin_host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    if origin_host != "ca-host" {
        let ca_policy = config_root.join("policy/ca.toml");
        let policy = fs::read_to_string(&ca_policy).unwrap().replacen(
            "target = \"ca-host\"",
            &format!("target = \"{origin_host}\""),
            1,
        );
        fs::write(ca_policy, policy).unwrap();
        if origin_host != "proxy-host" {
            fs::write(
                config_root
                    .join("policy/hosts")
                    .join(format!("{origin_host}.toml")),
                format!("ssh_roles = []\nprincipals = [\"test-origin-{origin_host}\"]\n"),
            )
            .unwrap();
        }
    }
    fs::create_dir_all(&fake_bin).unwrap();
    fs::create_dir_all(state.join("step/certs")).unwrap();
    fs::create_dir_all(password.parent().unwrap()).unwrap();
    fs::write(state.join("step/certs/root_ca.crt"), "root\n").unwrap();
    fs::write(&password, "ca-password\n").unwrap();
    let enrollment_keys = state.join("secrets/provisioners");
    fs::create_dir_all(&enrollment_keys).unwrap();
    for (name, kid, coordinate) in [
        ("grafhome-host-bootstrap", "bootstrap-kid", "bootstrap"),
        ("grafhome-user-enrollment", "enrollment-kid", "enrollment"),
    ] {
        fs::write(
            enrollment_keys.join(format!("{name}.pub.json")),
            format!(
                r#"{{"kid":"{kid}","kty":"EC","crv":"P-256","x":"{coordinate}-x","y":"{coordinate}-y"}}"#
            ),
        )
        .unwrap();
        fs::write(
            enrollment_keys.join(format!("{name}.priv.json")),
            format!(
                r#"{{"protected":"encrypted-{name}","iv":"iv","ciphertext":"{name}","tag":"tag","encrypted_key":"key"}}
"#
            ),
        )
        .unwrap();
        fs::write(
            enrollment_keys.join(format!("{name}.password")),
            format!("independent-{name}-password\n"),
        )
        .unwrap();
        fs::set_permissions(
            enrollment_keys.join(format!("{name}.priv.json")),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::set_permissions(
            enrollment_keys.join(format!("{name}.password")),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    fs::write(&host_key, "host-private\n").unwrap();
    fs::write(
        format!("{}.pub", host_key.display()),
        format!("{VALID_SSH_KEY}\n"),
    )
    .unwrap();

    let deployment = fs::read_to_string(config_root.join("config/deployment.env")).unwrap();
    let deployment = deployment
        .replace(
            "GRAFHOME_CA_STATE_DIR=/srv/example-ca",
            &format!("GRAFHOME_CA_STATE_DIR={}", state.display()),
        )
        .replace(
            "GRAFHOME_CA_SERVER_STEPPATH=/etc/step/grafhome",
            &format!("GRAFHOME_CA_SERVER_STEPPATH={}", server_step.display()),
        )
        .replace(
            "GRAFHOME_CA_ROOT_STEP_BIN=/root/.local/bin/step",
            &format!(
                "GRAFHOME_CA_ROOT_STEP_BIN={}",
                fake_bin.join("step").display()
            ),
        )
        .replace(
            "GRAFHOME_CA_HELPER_BIN=/root/.local/bin/grafhome-ca",
            &format!(
                "GRAFHOME_CA_HELPER_BIN={}",
                fake_bin.join("grafhome-ca").display()
            ),
        )
        .replace(
            "GRAFHOME_CA_HOST_KEY_PATH=/etc/ssh/ssh_host_ed25519_key",
            &format!("GRAFHOME_CA_HOST_KEY_PATH={}", host_key.display()),
        )
        .replace(
            "GRAFHOME_CA_PASSWORD_FILE=/srv/example-ca/secrets/intermediate_ca_password",
            &format!("GRAFHOME_CA_PASSWORD_FILE={}", password.display()),
        );
    fs::write(config_root.join("config/deployment.env"), deployment).unwrap();

    write_executable(
        &fake_bin.join("step"),
        r#"#!/bin/sh
set -eu
printf 'step STEPPATH=%s args=%s\n' "${STEPPATH:-}" "$*" >> "$FAKE_LOG"
case "$1 $2" in
  "certificate fingerprint")
    printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
    ;;
  "ca token")
    if [ "${FAKE_REQUIRE_RESTART_BEFORE_TOKEN:-}" = "1" ] && [ ! -e "$FAKE_LOG.restarted" ]; then
      printf 'token minted before CA restart completed\n' >&2
      exit 47
    fi
    if [ "${FAKE_STEP_FAIL:-}" = "ca-token" ]; then
      printf 'simulated token failure\n' >&2
      exit 46
    fi
    if [ "${FAKE_ENFORCE_ISSUER:-}" = "1" ]; then
      issuer=""
      previous=""
      for argument in "$@"; do
        if [ "$previous" = "--issuer" ]; then issuer="$argument"; fi
        previous="$argument"
      done
      if [ -n "$issuer" ] && ! grep -Fq "\"name\": \"$issuer\"" "$FAKE_CA_JSON"; then
        printf 'unknown issuer: %s\n' "$issuer" >&2
        exit 45
      fi
    fi
    printf 'token-for-%s\n' "$3"
    ;;
  "ca bootstrap")
    mkdir -p "$STEPPATH/certs" "$STEPPATH/config"
    printf 'root\n' > "$STEPPATH/certs/root_ca.crt"
    printf 'bootstrapped\n'
    ;;
  "ca health")
    if [ "${FAKE_STEP_HEALTH_FAIL_ONCE:-}" = "1" ] && [ ! -e "$FAKE_LOG.health_failed" ]; then
      touch "$FAKE_LOG.health_failed"
      printf 'failed decoding CA error response: transient proxy response\n' >&2
      exit 44
    fi
    printf 'ok\n'
    ;;
  "ca provisioner")
    printf '%s\n' "${FAKE_PROVISIONER_LIST:-[]}"
    ;;
  "ssh needs-renewal")
    if [ "${FAKE_CERT_FRESH:-}" = "1" ]; then exit 1; fi
    exit 0
    ;;
  "ssh certificate")
    token=""
    previous=""
    for argument in "$@"; do
      if [ "$previous" = "--token" ]; then token="$argument"; fi
      previous="$argument"
    done
    if [ "${FAKE_STEP_FAIL:-}" = "ssh-certificate" ] || [ "${FAKE_STEP_FAIL_TOKEN:-}" = "$token" ]; then
      printf 'simulated failure token=%s\n' "$token" >&2
      exit 42
    fi
    pub="$4"
    cert="${pub%.pub}-cert.pub"
    if [ "${FAKE_REQUIRE_PRIOR_HOST_CERT_MODE:-}" = "1" ] && [ -e "$cert" ]; then
      permissions=$(LC_ALL=C ls -ld "$cert" | cut -c 1-10)
      if [ "$permissions" != "-rw-r--r--" ]; then
        printf 'prior host certificate mode was %s, expected -rw-r--r--\n' "$permissions" >&2
        exit 43
      fi
    fi
    printf 'cert token=%s\n' "$token" > "$cert"
    chmod 0666 "$cert"
    printf 'signed %s\n' "$cert"
    ;;
  "ssh config")
    if printf '%s\n' "$*" | grep -q -- '--host'; then
      printf 'ssh-ed25519 AAAAhostca grafhome-host-ca\n'
    else
      printf 'ssh-ed25519 AAAAuserca grafhome-user-ca\n'
    fi
    ;;
  "crypto jwk")
    pub="$4"
    priv="$5"
    printf '{"kty":"OKP","crv":"Ed25519","x":"public"}\n' > "$pub"
    printf '{"kty":"OKP","crv":"Ed25519","x":"public","d":"private"}\n' > "$priv"
    printf 'jwk\n'
    ;;
  "crypto key")
    source="$4"
    out=""
    previous=""
    for argument in "$@"; do
      if [ "$previous" = "--out" ]; then out="$argument"; fi
      previous="$argument"
    done
    case "$*" in
      *--no-password*)
        if grep -q 'bootstrap' "$source" 2>/dev/null; then
          printf '{"kty":"EC","crv":"P-256","x":"bootstrap-x","y":"bootstrap-y","d":"private"}\n' > "$out"
        elif grep -q 'enrollment' "$source" 2>/dev/null; then
          printf '{"kty":"EC","crv":"P-256","x":"enrollment-x","y":"enrollment-y","d":"private"}\n' > "$out"
        else
          cp "$source" "$out"
        fi
        ;;
      *)
        if grep -q 'bootstrap' "$source" 2>/dev/null; then name='grafhome-host-bootstrap'; else name='grafhome-user-enrollment'; fi
        printf '{"protected":"encrypted-%s","iv":"iv","ciphertext":"%s","tag":"tag","encrypted_key":"key"}\n' "$name" "$name" > "$out"
        ;;
    esac
    ;;
  "crypto rand")
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n'
    ;;
  "crypto jwe")
    cat >/dev/null
    printf '{"kty":"OKP","d":"private"}\n'
    ;;
esac
"#,
    );
    write_executable(&fake_bin.join("grafhome-ca"), "#!/bin/sh\nexit 0\n");
    write_executable(
        &fake_bin.join("ssh-keygen"),
        r#"#!/bin/sh
set -eu
printf 'ssh-keygen args=%s\n' "$*" >> "$FAKE_LOG"
if [ "$1" = "-t" ]; then
  out=""
  prev=""
  for arg in "$@"; do
    if [ "$prev" = "-f" ]; then out="$arg"; fi
    prev="$arg"
  done
  printf 'private\n' > "$out"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/YQ6c6N8hXDSaeqEQ1UvUgrymxo5vYQNy/1KO4HPpw test@fixture\n' > "$out.pub"
elif [ "$1" = "-L" ]; then
  test -s "$3"
  printf 'inspect %s\n' "$3"
elif [ "$1" = "-k" ]; then
  out=""
  source=""
  previous=""
  for argument in "$@"; do
    if [ "$previous" = "-f" ]; then out="$argument"; fi
    source="$argument"
    previous="$argument"
  done
  if [ "${FAKE_KRL_GENERATION_FAIL:-}" = "1" ]; then
    printf 'simulated KRL generation failure\n' >&2
    exit 49
  fi
  if [ ! -e "$out" ]; then printf 'FAKE-KRL\n' > "$out"; fi
  while IFS= read -r key || [ -n "$key" ]; do
    printf '%s\n' "$key" >> "$out"
  done < "$source"
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
  IFS= read -r header < "$krl" || true
  if [ "$header" != "FAKE-KRL" ]; then exit 44; fi
  if [ "$list" = "1" ]; then exit 0; fi
  while IFS= read -r key || [ -n "$key" ]; do
    [ -z "$key" ] && continue
    found=0
    while IFS= read -r revoked || [ -n "$revoked" ]; do
      if [ "$revoked" = "$key" ]; then found=1; fi
    done < "$krl"
    if [ "$found" -ne 1 ]; then exit 0; fi
  done < "$source"
  exit 1
fi
"#,
    );
    write_executable(
        &fake_bin.join("ssh"),
        r#"#!/bin/sh
set -eu
printf 'ssh args=%s\n' "$*" >> "$FAKE_LOG"
if [ "${FAKE_SSH_CONFIG_FAIL:-}" = "1" ]; then
  printf 'simulated ssh client validation failure\n' >&2
  exit 50
fi
"#,
    );
    write_executable(
        &fake_bin.join("sshd"),
        r#"#!/bin/sh
set -eu
printf 'sshd args=%s\n' "$*" >> "$FAKE_LOG"
if [ "${FAKE_SSHD_FAIL_ONCE:-}" = "1" ] && [ ! -e "$FAKE_LOG.sshd_failed" ]; then
  touch "$FAKE_LOG.sshd_failed"
  printf 'simulated sshd validation failure\n' >&2
  exit 48
fi
"#,
    );
    write_executable(
        &fake_bin.join("systemctl"),
        r#"#!/bin/sh
set -eu
printf 'systemctl args=%s\n' "$*" >> "$FAKE_LOG"
if [ -n "${FAKE_SYSTEMCTL_RESTART_DELAY:-}" ] && [ "$1" = "restart" ]; then
  sleep "$FAKE_SYSTEMCTL_RESTART_DELAY"
fi
if [ "${FAKE_SYSTEMCTL_RESTART_FAIL_ONCE:-}" = "1" ] && [ "$1" = "restart" ] && [ ! -e "$FAKE_LOG.restart_failed" ]; then
  touch "$FAKE_LOG.restart_failed"
  exit 43
fi
if [ "${FAKE_SYSTEMCTL_SSHD_MISSING:-}" = "1" ] && [ "$1" = "reload" ] && [ "$2" = "sshd.service" ]; then
  printf 'Failed to reload sshd.service: Unit sshd.service not found.\n' >&2
  exit 5
fi
if [ "${FAKE_SYSTEMCTL_RELOAD_FAIL_PAIR:-}" = "1" ] && [ "$1" = "reload" ]; then
  count_file="$FAKE_LOG.reload_failures"
  count=0
  if [ -e "$count_file" ]; then count=$(cat "$count_file"); fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$count_file"
  if [ "$count" -le 2 ]; then exit 44; fi
fi
if [ "$1" = "restart" ]; then touch "$FAKE_LOG.restarted"; fi
if [ "$1" = "is-active" ]; then printf 'active\n'; fi
"#,
    );
    write_executable(
        &fake_bin.join("launchctl"),
        r#"#!/bin/sh
set -eu
printf 'launchctl args=%s\n' "$*" >> "$FAKE_LOG"
if [ "${FAKE_LAUNCHCTL_KICKSTART_FAIL:-}" = "1" ] && [ "$1" = "kickstart" ]; then
  printf 'Could not kickstart service "system/com.openssh.sshd": 3: No such process\n' >&2
  exit 3
fi
if [ "${FAKE_LAUNCHCTL_KICKSTART_FAIL_ONCE:-}" = "1" ] && [ "$1" = "kickstart" ] && [ ! -e "$FAKE_LOG.kickstart_failed" ]; then
  touch "$FAKE_LOG.kickstart_failed"
  printf 'Could not kickstart service "system/com.openssh.sshd": 3: No such process\n' >&2
  exit 3
fi
"#,
    );
    write_executable(
        &fake_bin.join("sv"),
        r#"#!/bin/sh
set -eu
printf 'sv args=%s\n' "$*" >> "$FAKE_LOG"
"#,
    );
    write_executable(
        &fake_bin.join("chown"),
        r#"#!/bin/sh
set -eu
printf 'chown args=%s\n' "$*" >> "$FAKE_LOG"
"#,
    );
    write_executable(
        &fake_bin.join("chmod"),
        r#"#!/bin/sh
set -eu
printf 'chmod args=%s\n' "$*" >> "$FAKE_LOG"
"#,
    );
    write_executable(&fake_bin.join("secret-tool"), "#!/bin/sh\nexit 1\n");
    write_executable(
        &fake_bin.join("systemd-creds"),
        r#"#!/bin/sh
set -eu
printf 'systemd-creds args=%s\n' "$*" >> "$FAKE_LOG"
has_user=0
has_tpm=0
for arg in "$@"; do
  if [ "$arg" = "--user" ]; then has_user=1; fi
  if [ "$arg" = "--with-key=tpm2" ]; then has_tpm=1; fi
done
if [ "${FAKE_SYSTEMD_CREDS_REJECT_USER:-}" = "1" ] && [ "$has_user" = "1" ]; then
  printf "systemd-creds: unrecognized option '--user'\n" >&2
  exit 2
fi
if [ "${FAKE_SYSTEMD_CREDS_REJECT_TPM:-}" = "1" ] && [ "$has_tpm" = "1" ]; then
  printf 'Failed to create TPM2 context: Permission denied\n' >&2
  exit 3
fi
case "$1" in
  encrypt)
    for output in "$@"; do :; done
    cat > "$output"
    ;;
  decrypt)
    if [ "${FAKE_SYSTEMD_CREDS_REJECT_DECRYPT:-}" = "1" ]; then
      printf 'Credential decryption unavailable\n' >&2
      exit 5
    fi
    if [ "${FAKE_SYSTEMD_CREDS_USER_DECRYPT_FAIL:-}" = "1" ] && [ "$has_user" = "1" ]; then
      printf 'Credential scope does not match\n' >&2
      exit 4
    fi
    for input in "$@"; do
      if [ -f "$input" ]; then cat "$input"; exit 0; fi
    done
    exit 1
    ;;
esac
"#,
    );
    write_executable(
        &fake_bin.join("security"),
        r#"#!/bin/sh
set -eu
case "$1" in
  -i)
    command=$(cat)
    printf 'security interactive store\n' >> "$FAKE_LOG"
    case "$command" in
      *"-a alice@ca-host -s net.grafhome.ca.renewal -X 757365722d6f776e65642d70617373776f7264"*)
        printf 'user-owned-password' > "$FAKE_LOG.keychain"
        ;;
      *)
        printf 'unexpected interactive security command\n' >&2
        exit 1
        ;;
    esac
    ;;
  find-generic-password)
    printf 'security find args=%s\n' "$*" >> "$FAKE_LOG"
    if [ "${FAKE_KEYCHAIN_DENIED:-}" = "1" ]; then
      printf 'security: SecKeychainSearchCopyNext: User interaction is not allowed.\n' >&2
      exit 51
    fi
    test -f "$FAKE_LOG.keychain"
    cat "$FAKE_LOG.keychain"
    ;;
  *)
    exit 1
    ;;
esac
"#,
    );

    (
        dir,
        ExecFixture {
            config_root,
            fake_bin,
            log,
            host_key,
        },
    )
}

#[cfg(target_os = "macos")]
fn prepare_macos_user_renewal(home: &Path, fixture: &ExecFixture, with_credential: bool) {
    let root = home.join(".config/grafhome/step/certs/root_ca.crt");
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::write(root, "root\n").unwrap();

    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();

    let public_key = home.join(".ssh/id_ed25519.pub");
    fs::create_dir_all(public_key.parent().unwrap()).unwrap();
    fs::write(public_key, format!("{VALID_SSH_KEY_TWO}\n")).unwrap();

    if with_credential {
        fs::write(
            format!("{}.keychain", fixture.log.display()),
            "user-owned-password",
        )
        .unwrap();
    }
}

#[cfg(target_os = "macos")]
fn macos_user_renew_command(fixture: &ExecFixture, home: &Path) -> Command {
    let mut command = Command::cargo_bin("grafhome-ca").expect("binary exists");
    command
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--if-enrolled",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log);
    command
}

#[cfg(unix)]
fn configure_unreachable_ca(fixture: &ExecFixture) {
    let path = fixture.config_root.join("policy/ca.toml");
    let text = fs::read_to_string(&path).unwrap();
    let text = text
        .replacen("address = \"198.51.100.21\"", "address = \"127.0.0.1\"", 1)
        .replacen("port = 443", "port = 1", 1);
    fs::write(path, text).unwrap();
}

#[cfg(target_os = "linux")]
fn user_enroll_request_command(fixture: &ExecFixture, home: &Path) -> Command {
    let mut command = Command::cargo_bin("grafhome-ca").expect("binary exists");
    command
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--request-only",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log);
    command
}

#[cfg(target_os = "linux")]
fn user_renew_command(fixture: &ExecFixture, home: &Path) -> Command {
    let mut command = Command::cargo_bin("grafhome-ca").expect("binary exists");
    command
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log);
    command
}

#[cfg(target_os = "linux")]
fn reset_user_enrollment_request(home: &Path) {
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::remove_file(material.join("pending-enrollment.json")).unwrap();
    fs::remove_file(home.join(".ssh/id_ed25519")).unwrap();
    fs::remove_file(home.join(".ssh/id_ed25519.pub")).unwrap();
}

#[cfg(unix)]
fn configure_step_path_fallback(dir: &tempfile::TempDir, fixture: &ExecFixture) -> String {
    let path_bin = dir.path().join("path-bin");
    fs::create_dir(&path_bin).unwrap();
    fs::copy(fixture.fake_bin.join("step"), path_bin.join("step")).unwrap();
    fs::set_permissions(path_bin.join("step"), fs::Permissions::from_mode(0o755)).unwrap();
    let deployment_path = fixture.config_root.join("config/deployment.env");
    let deployment = fs::read_to_string(&deployment_path).unwrap().replace(
        &format!(
            "GRAFHOME_CA_ROOT_STEP_BIN={}",
            fixture.fake_bin.join("step").display()
        ),
        &format!(
            "GRAFHOME_CA_ROOT_STEP_BIN={}",
            fixture.fake_bin.join("missing-step").display()
        ),
    );
    fs::write(deployment_path, deployment).unwrap();
    format!("{}:{}", path_bin.display(), prepend_path(&fixture.fake_bin))
}

#[cfg(unix)]
fn prepare_termux_host_runtime(
    dir: &tempfile::TempDir,
    fixture: &ExecFixture,
) -> (PathBuf, PathBuf, PathBuf) {
    let home = dir.path().join("termux-home");
    let prefix = dir.path().join("termux-prefix");
    let bin = prefix.join("bin");
    let ssh = prefix.join("etc/ssh");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&ssh).unwrap();
    for executable in ["ssh", "ssh-keygen", "sshd", "sv"] {
        fs::copy(fixture.fake_bin.join(executable), bin.join(executable)).unwrap();
        fs::set_permissions(bin.join(executable), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::copy(fixture.fake_bin.join("step"), bin.join("step-cli")).unwrap();
    fs::set_permissions(bin.join("step-cli"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(ssh.join("ssh_host_ed25519_key"), "host-private\n").unwrap();
    fs::write(
        ssh.join("ssh_host_ed25519_key.pub"),
        format!("{VALID_SSH_KEY}\n"),
    )
    .unwrap();
    (home, prefix, bin)
}

#[cfg(unix)]
fn prepare_apply_host(fixture: &ExecFixture) {
    let root = fixture.config_root.join("../server-step/certs/root_ca.crt");
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::write(root, "root\n").unwrap();
}

#[cfg(unix)]
fn prepare_host_renewal(fixture: &ExecFixture, host: &str) {
    prepare_apply_host(fixture);
    let material = fixture
        .config_root
        .join("../server-step/secrets/hosts")
        .join(host);
    fs::create_dir_all(&material).unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();
}

#[cfg(unix)]
fn prepare_apply_ca(fixture: &ExecFixture) -> PathBuf {
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec_pretty(&serde_json::json!({
            "authority": {
                "provisioners": [
                    {
                        "type": "JWK",
                        "name": "grafhome-user-enrollment",
                        "key": {"kid": "static"},
                        "encryptedKey": "preserve-secret",
                        "claims": {
                            "defaultUserSSHCertDuration": "12h",
                            "maxUserSSHCertDuration": "168h"
                        }
                    },
                    {
                        "type": "JWK",
                        "name": "grafhome-user-616c696365-63612d686f7374",
                        "key": {"kid": "client"},
                        "claims": {"maxUserSSHCertDuration": "168h"}
                    },
                    {
                        "type": "JWK",
                        "name": "operator-owned",
                        "claims": {"maxUserSSHCertDuration": "1h"}
                    }
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    ca_json
}

#[cfg(unix)]
fn apply_ca_command(fixture: &ExecFixture) -> Command {
    let mut command = Command::cargo_bin("grafhome-ca").unwrap();
    command
        .args(["apply", "ca", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOSTNAME", "ca-host.example.test")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log);
    command
}

#[cfg(unix)]
fn apply_host_command(fixture: &ExecFixture, install_root: &Path) -> Command {
    let mut command = Command::cargo_bin("grafhome-ca").unwrap();
    command
        .args(["apply", "host", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOSTNAME", "proxy-host.example.test")
        .env("GRAFHOME_CA_INSTALL_ROOT", install_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log);
    command
}

#[test]
fn check_validates_example_config() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("check")
        .arg("--config-root")
        .arg(example_config_root())
        .assert()
        .success()
        .stdout(predicate::str::contains("ca_api=https://ca.example.test"))
        .stdout(predicate::str::contains(
            "ca_origin=https://ca-origin.example.test:8443",
        ));
}

#[test]
fn check_uses_xdg_config_home_by_default() {
    let dir = tempdir().unwrap();
    copy_dir(&example_config_root(), &dir.path().join("grafhome-ca"));
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("check")
        .env("XDG_CONFIG_HOME", dir.path())
        .env_remove("HOME")
        .assert()
        .success()
        .stdout(predicate::str::contains("ca_api=https://ca.example.test"));
}

#[test]
fn version_prints_the_generated_build_version() {
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(r"^grafhome-ca [0-9]{8}-[0-9]{6}-[0-9a-f]{8}\n$").unwrap(),
        );
}

#[test]
fn help_exposes_only_supported_commands() {
    let output = Command::cargo_bin("grafhome-ca")
        .unwrap()
        .arg("help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();

    for command in [
        "version",
        "check",
        "render",
        "export",
        "materialize",
        "migrate",
        "apply",
        "approve",
        "enroll",
        "renew",
        "revoke",
        "status",
    ] {
        assert!(
            text.contains(command),
            "missing supported command {command}"
        );
    }
    for obsolete in [
        "approve-host",
        "approve-user",
        "enroll-host",
        "enroll-user",
        "renew-host",
        "ssh-ensure",
        "revoke-host",
        "revoke-user",
        "doctor",
        "init-ca ",
        "bootstrap-client",
        "bootstrap-host-trust",
        "add-user-device-provisioner",
        "grant-host",
        "endpoints ",
        "export-public",
        "materialize-runtime-provisioners",
        "plan ",
        "ca-fingerprint",
        "enrollment-status",
    ] {
        assert!(
            !text.contains(obsolete),
            "found obsolete command {obsolete}"
        );
    }

    for verb in ["approve", "enroll", "renew", "revoke"] {
        let output = Command::cargo_bin("grafhome-ca")
            .unwrap()
            .args([verb, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        for noun in ["host", "user"] {
            assert!(text.contains(noun), "missing `{verb} {noun}` command");
        }
    }

    let output = Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["migrate", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("policy"));
    assert!(text.contains("enrollment-provisioner-keys"));
}

#[test]
fn approve_user_rejects_conflicting_certificate_lifetime_flags() {
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "approve",
            "user",
            "--cert-ttl",
            "24h",
            "--effectively-infinite",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot be used with '--effectively-infinite'",
        ));
}

#[cfg(unix)]
#[test]
fn system_host_and_ca_commands_reject_non_root_callers() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let config_root = example_config_root();
    let commands: &[&[&str]] = &[
        &["apply", "ca", "--dry-run"],
        &["apply", "host", "--dry-run"],
        &[
            "materialize",
            "--live-ca-json",
            "/nonexistent/live.json",
            "--staged-ca-json",
            "/nonexistent/staged.json",
            "--jwk-dir",
            "/nonexistent/jwks",
            "--out-file",
            "/nonexistent/out.json",
        ],
        &["migrate", "enrollment-provisioner-keys"],
        &["approve", "host", "--yes"],
        &["approve", "user", "--yes"],
        &["enrollment", "import"],
        &["enroll", "host", "--request-only"],
        &["renew", "host"],
        &["revoke", "host", "--host", "proxy-host"],
        &["revoke", "user", "--user", "alice"],
    ];

    for args in commands {
        Command::cargo_bin("grafhome-ca")
            .unwrap()
            .args(*args)
            .arg("--config-root")
            .arg(&config_root)
            .assert()
            .failure()
            .stderr(predicate::str::contains("must be run as root"));
    }
}

#[cfg(unix)]
#[test]
fn ca_mutation_root_guard_precedes_policy_and_request_reads() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = tempdir().unwrap();
    let config_root = dir.path().join("grafhome-ca");
    let missing = dir.path().join("must-not-be-read.json");
    copy_dir(&example_config_root(), &config_root);
    fs::write(config_root.join("policy/ca.toml"), "not valid TOML\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--request-file"])
        .arg(&missing)
        .arg("--config-root")
        .arg(&config_root)
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be run as root"))
        .stderr(predicate::str::contains("must-not-be-read").not())
        .stderr(predicate::str::contains("TOML").not());
}

#[cfg(unix)]
#[test]
fn apply_host_dry_run_does_not_write_or_reload() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("create\t"))
        .stdout(predicate::str::contains(
            "Would apply 7 host policy change(s) for proxy-host",
        ));

    assert!(!install_root.exists());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(!log.contains("sshd args=-t"));
    assert!(!log.contains("systemctl args=reload"));
}

#[cfg(unix)]
#[test]
fn apply_host_explicit_host_overrides_the_policy_identity_environment() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .args(["--host", "proxy-host", "--dry-run"])
        .env("GRAFHOME_CA_LOCAL_HOST", "wrong-host")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Would apply 7 host policy change(s) for proxy-host",
        ));
}

// macOS has its own reload branch (`launchctl kickstart`, not `systemctl`),
// so this and its sibling tests below are excluded here and duplicated with
// a `target_os = "macos"` twin that asserts on the launchd invocation.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_installs_fresh_local_policy() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Applied 7 host policy change(s) for proxy-host",
        ));

    assert_eq!(
        fs::read_to_string(install_root.join("etc/ssh/auth_principals/alice")).unwrap(),
        "alice\n"
    );
    assert!(
        fs::read_to_string(install_root.join("etc/ssh/grafhome/ssh_known_hosts"))
            .unwrap()
            .contains("@cert-authority")
    );
    assert!(
        fs::read_to_string(install_root.join("etc/ssh/grafhome/user_ca_keys.pem"))
            .unwrap()
            .contains("AAAAuserca")
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("systemctl args=reload sshd.service"));
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_compiles_role_scoped_krls_and_reuses_them_when_unchanged() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);
    fs::write(
        fixture.config_root.join("policy/revocations.toml"),
        r#"format_version = 1

[[ssh_keys]]
kind = "host"
host = "retired-host"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOF9AFZbHgCPqUAtsZo9RLg6Fg4R+6rKThonym0jI0x3"
fingerprint = "SHA256:PwiHaeoThsUMMEFnpgXFZOaOM3GD6Jkn0rlVu+srKkI"
renewal_fingerprint = "SHA256:6nWqP5b7mBpArY0rPWTKT6lPhnZJYekV74X2Hdh8zCg"
revoked_at = "2026-07-24T20:14:15Z"

[[ssh_keys]]
kind = "user"
user = "alice"
client_host = "retired-host"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/YQ6c6N8hXDSaeqEQ1UvUgrymxo5vYQNy/1KO4HPpw"
fingerprint = "SHA256:+3AjrkPFtS9Wir1XpfmKixs1yTrmIGU28cbbOnEMW+o"
renewal_fingerprint = "SHA256:grNhYzQm8G7RLKOUx2vpN4lqVj0aFJsYYfM1GxKXDnE"
revoked_at = "2026-07-24T20:14:15Z"
"#,
    )
    .unwrap();

    apply_host_command(&fixture, &install_root)
        .assert()
        .success();

    let trust = install_root.join("etc/ssh/grafhome");
    assert!(
        fs::read(trust.join("revoked_user_certs"))
            .unwrap()
            .starts_with(b"FAKE-KRL\n")
    );
    assert!(
        fs::read(trust.join("revoked_host_keys"))
            .unwrap()
            .starts_with(b"FAKE-KRL\n")
    );
    let client =
        fs::read_to_string(install_root.join("etc/ssh/ssh_config.d/grafhome-ca.conf")).unwrap();
    assert!(client.contains("RevokedHostKeys /etc/ssh/grafhome/revoked_host_keys"));
    let first_log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(first_log.matches("ssh-keygen args=-k").count(), 2);
    assert!(first_log.contains("ssh args=-G -F"));

    fs::write(&fixture.log, "").unwrap();
    apply_host_command(&fixture, &install_root)
        .assert()
        .success()
        .stdout(predicate::str::contains("Host policy already current"));
    let second_log = fs::read_to_string(&fixture.log).unwrap();
    assert!(!second_log.contains("ssh-keygen args=-k"));
    assert!(!second_log.contains("systemctl args=reload"));
}

// KRL compilation is the only host-policy step that needs scratch space
// outside the install root, so pin where that scratch space comes from.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_compiles_krls_inside_the_resolved_scratch_root() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).unwrap();
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .env("TMPDIR", &scratch)
        .assert()
        .success();

    let log = fs::read_to_string(&fixture.log).unwrap();
    let compiled = log
        .lines()
        .filter(|line| line.starts_with("ssh-keygen args=-k "))
        .collect::<Vec<_>>();
    assert_eq!(compiled.len(), 2, "{log}");
    for line in compiled {
        assert!(
            line.contains(&format!("-f {}/", scratch.display())),
            "{line}"
        );
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_krl_generation_failure_writes_no_managed_files() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .env("FAKE_KRL_GENERATION_FAIL", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("simulated KRL generation failure"));

    let trust = install_root.join("etc/ssh/grafhome");
    assert!(trust.join(".apply.lock").is_file());
    assert!(!trust.join("revoked_user_certs").exists());
    assert!(!trust.join("revoked_host_keys").exists());
    assert!(
        !install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .exists()
    );
    assert!(
        !install_root
            .join("etc/ssh/ssh_config.d/grafhome-ca.conf")
            .exists()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ssh-keygen args=-k"));
    assert!(!log.contains("sshd args=-t"));
    assert!(!log.contains("systemctl args=reload"));
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_reloads_sshd_when_removing_the_server_role() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);
    apply_host_command(&fixture, &install_root)
        .assert()
        .success();

    fs::write(
        fixture
            .config_root
            .join("policy/hosts/proxy-host.toml"),
        "ssh_roles = [\"client\"]\nprincipals = [\"proxy-host\", \"ca.example.test\"]\n\n[user_access.alice]\nenrollment = true\n",
    )
    .unwrap();
    fs::write(&fixture.log, "").unwrap();

    apply_host_command(&fixture, &install_root)
        .assert()
        .success();

    assert!(
        !install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .exists()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("systemctl args=reload sshd.service"));
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_normalizes_public_ssh_directories_under_a_restrictive_umask() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);
    let binary = assert_cmd::cargo::cargo_bin("grafhome-ca");
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("umask 077; exec \"$@\"")
        .arg("grafhome-ca-umask-test")
        .arg(binary)
        .args(["apply", "host", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOSTNAME", "proxy-host.example.test")
        .env("GRAFHOME_CA_INSTALL_ROOT", &install_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (path, expected_mode) in [
        ("etc/ssh", 0o755),
        ("etc/ssh/grafhome", 0o755),
        ("etc/ssh/ssh_config.d", 0o755),
        ("etc/ssh/sshd_config.d", 0o700),
        ("etc/ssh/auth_principals", 0o700),
    ] {
        assert_eq!(
            fs::metadata(install_root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            expected_mode,
            "{path}"
        );
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_preserves_existing_secure_server_directory_modes() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);
    for path in ["etc/ssh/sshd_config.d", "etc/ssh/auth_principals"] {
        let directory = install_root.join(path);
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    }

    apply_host_command(&fixture, &install_root)
        .assert()
        .success();

    for path in ["etc/ssh/sshd_config.d", "etc/ssh/auth_principals"] {
        assert_eq!(
            fs::metadata(install_root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750,
            "{path}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn apply_host_installs_fresh_local_policy_macos() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Applied 7 host policy change(s) for proxy-host",
        ));

    assert_eq!(
        fs::read_to_string(install_root.join("etc/ssh/auth_principals/alice")).unwrap(),
        "alice\n"
    );
    assert!(
        fs::read_to_string(install_root.join("etc/ssh/grafhome/ssh_known_hosts"))
            .unwrap()
            .contains("@cert-authority")
    );
    assert!(
        fs::read_to_string(install_root.join("etc/ssh/grafhome/user_ca_keys.pem"))
            .unwrap()
            .contains("AAAAuserca")
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("launchctl args=kickstart -k system/com.openssh.sshd"));
}

#[cfg(unix)]
#[test]
fn apply_host_if_enrolled_silently_skips_an_unenrolled_host() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");

    apply_host_command(&fixture, &install_root)
        .args(["--if-enrolled", "--quiet"])
        .assert()
        .success()
        .stdout("")
        .stderr("");

    assert!(!install_root.exists());
    assert!(!fixture.log.exists());
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn quiet_apply_host_reconciles_an_enrolled_host_without_routine_output() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_host_renewal(&fixture, "proxy-host");

    apply_host_command(&fixture, &install_root)
        .args(["--if-enrolled", "--quiet"])
        .assert()
        .success()
        .stdout("")
        .stderr("");

    assert!(
        install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .is_file()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("systemctl args=reload sshd.service"));
}

#[cfg(target_os = "macos")]
#[test]
fn quiet_apply_host_reconciles_an_enrolled_host_without_routine_output_macos() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_host_renewal(&fixture, "proxy-host");

    apply_host_command(&fixture, &install_root)
        .args(["--if-enrolled", "--quiet"])
        .assert()
        .success()
        .stdout("")
        .stderr("");

    assert!(
        install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .is_file()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("launchctl args=kickstart -k system/com.openssh.sshd"));
}

#[cfg(all(unix, target_os = "android"))]
#[test]
fn termux_owner_applies_host_policy_under_the_app_prefix() {
    let (dir, fixture) = exec_fixture();
    let (home, prefix, bin) = prepare_termux_host_runtime(&dir, &fixture);
    let config_root = home.join("grafhome-ca");
    copy_dir(&fixture.config_root, &config_root);

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["apply", "host", "--config-root"])
        .arg(&config_root)
        .env("HOME", &home)
        .env("PREFIX", &prefix)
        .env("TERMUX_VERSION", "0.118-test")
        .env("GRAFHOME_CA_LOCAL_HOST", "proxy-host")
        .env("PATH", &bin)
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Applied 7 host policy change(s) for proxy-host",
        ));

    let ssh_dir = prefix.join("etc/ssh");
    let server_config = fs::read_to_string(ssh_dir.join("sshd_config.d/grafhome-ca.conf")).unwrap();
    assert!(server_config.contains(&format!(
        "HostCertificate {}/etc/ssh/ssh_host_ed25519_key-cert.pub",
        prefix.display()
    )));
    assert!(server_config.contains(&format!(
        "TrustedUserCAKeys {}/etc/ssh/grafhome/user_ca_keys.pem",
        prefix.display()
    )));
    assert!(server_config.contains(&format!(
        "AuthorizedPrincipalsFile {}/.ssh/grafhome/termux-owner",
        home.display()
    )));
    assert!(server_config.contains("StrictModes no"));
    assert!(server_config.contains("AuthorizedKeysFile none"));
    assert_eq!(
        fs::read_to_string(home.join(".ssh/grafhome/termux-owner")).unwrap(),
        "alice\n"
    );
    assert!(ssh_dir.join("ssh_config.d/grafhome-ca.conf").is_file());

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("step STEPPATH="));
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("sv args=hup sshd"));
    assert!(!log.contains("systemctl args="));
}

#[cfg(all(unix, target_os = "android"))]
#[test]
fn termux_owner_creates_and_renews_host_enrollment_under_home() {
    let (dir, fixture) = exec_fixture();
    let (home, prefix, bin) = prepare_termux_host_runtime(&dir, &fixture);
    let config_root = home.join("grafhome-ca");
    copy_dir(&fixture.config_root, &config_root);
    let mut enroll = Command::cargo_bin("grafhome-ca").unwrap();
    enroll
        .args(["enroll", "host", "--request-only", "--config-root"])
        .arg(&config_root)
        .env("HOME", &home)
        .env("PREFIX", &prefix)
        .env("TERMUX_VERSION", "0.118-test")
        .env("GRAFHOME_CA_LOCAL_HOST", "proxy-host")
        .env("PATH", &bin)
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"));

    let host_step = home.join(".config/grafhome/host-step");
    let material = host_step.join("secrets/hosts/proxy-host");
    assert!(material.join("pending-enrollment.json").is_file());
    assert!(material.join("provisioner.priv.json").is_file());
    assert!(material.join("renewal-password").is_file());
    fs::create_dir_all(host_step.join("certs")).unwrap();
    fs::write(host_step.join("certs/root_ca.crt"), "root\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["renew", "host", "--config-root"])
        .arg(&config_root)
        .env("HOME", &home)
        .env("PREFIX", &prefix)
        .env("TERMUX_VERSION", "0.118-test")
        .env("GRAFHOME_CA_LOCAL_HOST", "proxy-host")
        .env("PATH", &bin)
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    assert!(
        prefix
            .join("etc/ssh/ssh_host_ed25519_key-cert.pub")
            .is_file()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("step STEPPATH="));
    assert!(log.contains("ca token proxy-host --ssh --host"));
    assert!(log.contains("sv args=hup sshd"));
    assert!(!log.contains("systemctl args="));
}

#[cfg(all(unix, not(target_os = "android")))]
#[test]
fn termux_environment_alone_does_not_enable_desktop_owner_mode() {
    let (dir, fixture) = exec_fixture();
    let (home, prefix, bin) = prepare_termux_host_runtime(&dir, &fixture);
    let install_root = dir.path().join("desktop-install-root");

    let mut command = Command::cargo_bin("grafhome-ca").unwrap();
    command
        .args(["apply", "host", "--config-root"])
        .arg(&fixture.config_root)
        .arg("--dry-run")
        .env("HOME", &home)
        .env("PREFIX", &prefix)
        .env("TERMUX_VERSION", "injected")
        .env("GRAFHOME_CA_INSTALL_ROOT", &install_root)
        .env("GRAFHOME_CA_LOCAL_HOST", "proxy-host")
        .env("PATH", &bin)
        .env("FAKE_LOG", &fixture.log);

    if rustix::process::geteuid().as_raw() == 0 {
        command.assert().success().stdout(predicate::str::contains(
            install_root.join("etc/ssh").display().to_string(),
        ));
    } else {
        command
            .assert()
            .failure()
            .stderr(predicate::str::contains("must be run as root"));
    }

    let log = fs::read_to_string(&fixture.log).unwrap_or_default();
    assert!(!log.contains("sv args="));
    assert!(!log.contains("sshd args="));
    assert!(!log.contains("systemctl args="));
    assert!(
        !prefix
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .exists()
    );
    assert!(
        !install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .exists()
    );
}

// macOS has a single launchd job, not a sshd.service/ssh.service pair, so
// there is no fallback behavior to mirror here.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_silently_falls_back_to_ssh_service() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .env("FAKE_SYSTEMCTL_SSHD_MISSING", "1")
        .assert()
        .success()
        .stderr(predicate::str::is_empty());

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("systemctl args=reload sshd.service"));
    assert!(log.contains("systemctl args=reload ssh.service"));
}

#[cfg(unix)]
#[test]
fn apply_exposes_only_supported_local_nouns() {
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ca"))
        .stdout(predicate::str::contains("host"));

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["apply", "user"])
        .assert()
        .failure();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["apply", "ca", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--dry-run"))
        .stdout(predicate::str::contains(
            "affected authority and provisioner policy",
        ));

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["apply", "host", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--dry-run"))
        .stdout(predicate::str::contains("--if-enrolled"))
        .stdout(predicate::str::contains("--quiet"))
        .stdout(predicate::str::contains("--if-reachable").not())
        .stdout(predicate::str::contains("--host"));

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["apply", "host", "--dry-run", "--quiet"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[cfg(unix)]
#[test]
fn apply_ca_dry_run_reports_changes_without_writing_or_restarting() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = prepare_apply_ca(&fixture);
    let original = fs::read(&ca_json).unwrap();

    apply_ca_command(&fixture)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Would apply CA authority policy and policy for 2 provisioner(s)",
        ));

    assert_eq!(fs::read(ca_json).unwrap(), original);
    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn apply_ca_updates_live_claims_and_skips_a_second_restart() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = prepare_apply_ca(&fixture);

    apply_ca_command(&fixture)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Applied CA authority policy and policy for 2 provisioner(s)",
        ));

    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    let provisioners = value["authority"]["provisioners"].as_array().unwrap();
    assert_eq!(
        provisioners[0]["claims"]["maxUserSSHCertDuration"],
        "2562047h"
    );
    assert_eq!(provisioners[1]["claims"]["maxUserSSHCertDuration"], "48h");
    for provisioner in &provisioners[..2] {
        assert_eq!(provisioner["claims"]["defaultUserSSHCertDuration"], "24h");
    }
    assert_eq!(provisioners[2]["claims"]["maxUserSSHCertDuration"], "1h");
    assert_eq!(provisioners[0]["encryptedKey"], "preserve-secret");
    let first_log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        first_log
            .matches("systemctl args=restart step-ca.service")
            .count(),
        1
    );

    apply_ca_command(&fixture)
        .assert()
        .success()
        .stdout(predicate::str::contains("CA policy already current"));

    let second_log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        second_log
            .matches("systemctl args=restart step-ca.service")
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn apply_ca_updates_authority_policy_only_and_removes_retired_principals() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = prepare_apply_ca(&fixture);
    apply_ca_command(&fixture).assert().success();
    fs::write(&fixture.log, "").unwrap();

    let mut stale: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    stale["authority"]["policy"]["ssh"]["host"]["allow"]["dns"] =
        serde_json::json!(["retired-host"]);
    stale["authority"]["policy"]["operatorOwned"] = serde_json::json!({"preserve": true});
    fs::write(&ca_json, serde_json::to_vec_pretty(&stale).unwrap()).unwrap();
    let stale_bytes = fs::read(&ca_json).unwrap();

    apply_ca_command(&fixture)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("update\tauthority.policy"))
        .stdout(predicate::str::contains("Would apply CA authority policy."))
        .stdout(predicate::str::contains("provisioner(s)").not());
    assert_eq!(fs::read(&ca_json).unwrap(), stale_bytes);
    assert_eq!(fs::read_to_string(&fixture.log).unwrap(), "");

    apply_ca_command(&fixture)
        .assert()
        .success()
        .stdout(predicate::str::contains("Applied CA authority policy."));

    let updated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    let dns = updated["authority"]["policy"]["ssh"]["host"]["allow"]["dns"]
        .as_array()
        .unwrap();
    assert!(dns.contains(&serde_json::json!("proxy-host")));
    assert!(!dns.contains(&serde_json::json!("retired-host")));
    assert_eq!(
        updated["authority"]["policy"]["operatorOwned"],
        serde_json::json!({"preserve": true})
    );
    assert_eq!(
        fs::read_to_string(&fixture.log)
            .unwrap()
            .matches("systemctl args=restart step-ca.service")
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn apply_ca_restores_previous_policy_when_restart_fails() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = prepare_apply_ca(&fixture);
    let original = fs::read(&ca_json).unwrap();

    apply_ca_command(&fixture)
        .env("FAKE_SYSTEMCTL_RESTART_FAIL_ONCE", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("restored previous ca.json"));

    assert_eq!(fs::read(ca_json).unwrap(), original);
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        log.matches("systemctl args=restart step-ca.service")
            .count(),
        2
    );
}

#[cfg(unix)]
#[test]
fn apply_ca_rejects_a_non_origin_host() {
    let (_dir, fixture) = exec_fixture();
    prepare_apply_ca(&fixture);
    let ca_policy = fixture.config_root.join("policy/ca.toml");
    let local_host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    let policy = fs::read_to_string(&ca_policy).unwrap().replacen(
        &format!("target = \"{local_host}\""),
        "target = \"off-origin\"",
        1,
    );
    fs::write(ca_policy, policy).unwrap();
    fs::write(
        fixture.config_root.join("policy/hosts/off-origin.toml"),
        "ssh_roles = []\nprincipals = [\"test-off-origin\"]\n",
    )
    .unwrap();

    apply_ca_command(&fixture)
        .env("GRAFHOME_CA_LOCAL_HOST", "off-origin")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "must be run on CA origin off-origin",
        ));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn ca_mutations_reject_off_origin_before_inputs_or_state_changes() {
    let (dir, fixture) = exec_fixture();
    let missing = dir.path().join("must-not-be-read.json");
    let materialized = dir.path().join("must-not-be-written.json");
    let ca_policy = fixture.config_root.join("policy/ca.toml");
    let local_host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    let off_origin = format!("off-origin-{}", std::process::id());
    let policy = fs::read_to_string(&ca_policy).unwrap().replacen(
        &format!("target = \"{local_host}\""),
        &format!("target = \"{off_origin}\""),
        1,
    );
    fs::write(ca_policy, policy).unwrap();
    fs::write(
        fixture
            .config_root
            .join("policy/hosts")
            .join(format!("{off_origin}.toml")),
        format!("ssh_roles = []\nprincipals = [\"test-{off_origin}\"]\n"),
    )
    .unwrap();
    let revocations = fixture.config_root.join("policy/revocations.toml");
    let original_revocations = fs::read(&revocations).unwrap();
    let enrollment_keys = dir.path().join("state/secrets/provisioners");
    let snapshot_enrollment_keys = || {
        let mut entries = fs::read_dir(&enrollment_keys)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    };
    let original_enrollment_keys = snapshot_enrollment_keys();

    let cases = vec![
        ("apply ca", vec!["apply", "ca"], false),
        (
            "materialize",
            vec![
                "materialize",
                "--live-ca-json",
                missing.to_str().unwrap(),
                "--staged-ca-json",
                missing.to_str().unwrap(),
                "--jwk-dir",
                missing.to_str().unwrap(),
                "--out-file",
                materialized.to_str().unwrap(),
            ],
            false,
        ),
        (
            "migrate enrollment keys",
            vec!["migrate", "enrollment-provisioner-keys"],
            false,
        ),
        ("approve host", vec!["approve", "host", "--yes"], true),
        ("approve user", vec!["approve", "user", "--yes"], true),
        (
            "revoke host",
            vec!["revoke", "host", "--host", "proxy-host"],
            false,
        ),
        (
            "revoke user",
            vec!["revoke", "user", "--user", "alice"],
            false,
        ),
        ("enrollment import", vec!["enrollment", "import"], true),
    ];
    for (name, args, reads_input) in &cases {
        let mut command = Command::cargo_bin("grafhome-ca").unwrap();
        command.args(args);
        if *reads_input {
            command.arg("--request-file").arg(&missing);
        }
        command
            .arg("--config-root")
            .arg(&fixture.config_root)
            .env("PATH", prepend_path(&fixture.fake_bin))
            .env("FAKE_LOG", &fixture.log)
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "must be run on CA origin {off_origin}"
            )))
            .stderr(predicate::str::contains("must-not-be-read").not());

        assert!(!fixture.log.exists(), "{name} ran an external command");
        assert!(!materialized.exists(), "{name} wrote materialized state");
        assert_eq!(
            fs::read(&revocations).unwrap(),
            original_revocations,
            "{name} changed revocation state"
        );
        assert_eq!(
            snapshot_enrollment_keys(),
            original_enrollment_keys,
            "{name} changed enrollment keys"
        );
    }
}

#[cfg(unix)]
#[test]
fn apply_host_corrects_unsafe_special_mode_bits() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let principals = install_root.join("etc/ssh/auth_principals/alice");
    prepare_apply_host(&fixture);
    apply_host_command(&fixture, &install_root)
        .assert()
        .success();
    fs::set_permissions(&principals, fs::Permissions::from_mode(0o4644)).unwrap();

    apply_host_command(&fixture, &install_root)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "update\t{}",
            principals.display()
        )));

    assert_eq!(
        fs::metadata(principals).unwrap().permissions().mode() & 0o7777,
        0o644
    );
}

#[cfg(unix)]
#[test]
fn apply_host_removes_stale_principal_files() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let auth_dir = install_root.join("etc/ssh/auth_principals");
    prepare_apply_host(&fixture);
    fs::create_dir_all(&auth_dir).unwrap();
    fs::write(auth_dir.join("departed"), "departed\n").unwrap();

    apply_host_command(&fixture, &install_root)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "remove\t{}",
            auth_dir.join("departed").display()
        )));

    assert!(!auth_dir.join("departed").exists());
    assert_eq!(
        fs::read_to_string(auth_dir.join("alice")).unwrap(),
        "alice\n"
    );
}

#[cfg(unix)]
#[test]
fn apply_host_preserves_custom_trust_and_principals_paths() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let deployment_path = fixture.config_root.join("config/deployment.env");
    let deployment = fs::read_to_string(&deployment_path)
        .unwrap()
        .replace(
            "GRAFHOME_CA_SSH_TRUST_DIR=/etc/ssh/grafhome",
            "GRAFHOME_CA_SSH_TRUST_DIR=/var/lib/grafhome/trust",
        )
        .replace(
            "GRAFHOME_CA_AUTH_PRINCIPALS_DIR=/etc/ssh/auth_principals",
            "GRAFHOME_CA_AUTH_PRINCIPALS_DIR=/var/lib/grafhome/principals",
        );
    fs::write(deployment_path, deployment).unwrap();
    prepare_apply_host(&fixture);

    let binary = assert_cmd::cargo::cargo_bin("grafhome-ca");
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("umask 077; exec \"$@\"")
        .arg("grafhome-ca-custom-path-umask-test")
        .arg(binary)
        .args(["apply", "host", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOSTNAME", "proxy-host.example.test")
        .env("GRAFHOME_CA_INSTALL_ROOT", &install_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .is_file()
    );
    assert!(
        install_root
            .join("var/lib/grafhome/trust/user_ca_keys.pem")
            .is_file()
    );
    assert_eq!(
        fs::read_to_string(install_root.join("var/lib/grafhome/principals/alice")).unwrap(),
        "alice\n"
    );
    for (path, expected_mode) in [
        ("var/lib/grafhome", 0o755),
        ("var/lib/grafhome/trust", 0o755),
        ("var/lib/grafhome/principals", 0o700),
    ] {
        assert_eq!(
            fs::metadata(install_root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            expected_mode,
            "{path}"
        );
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_rejects_a_writable_custom_trust_parent() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let deployment_path = fixture.config_root.join("config/deployment.env");
    let deployment = fs::read_to_string(&deployment_path).unwrap().replace(
        "GRAFHOME_CA_SSH_TRUST_DIR=/etc/ssh/grafhome",
        "GRAFHOME_CA_SSH_TRUST_DIR=/var/lib/grafhome/trust",
    );
    fs::write(deployment_path, deployment).unwrap();
    let writable = install_root.join("var/lib/grafhome");
    fs::create_dir_all(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    prepare_apply_host(&fixture);

    apply_host_command(&fixture, &install_root)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "managed SSH parent must be operator-owned and protected from non-owner writes",
        ));
}

#[cfg(unix)]
#[test]
fn apply_host_skips_validation_and_reload_when_current() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    prepare_apply_host(&fixture);
    apply_host_command(&fixture, &install_root)
        .assert()
        .success();
    fs::write(&fixture.log, "").unwrap();

    apply_host_command(&fixture, &install_root)
        .assert()
        .success()
        .stdout("Host policy already current: proxy-host\n");

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(!log.contains("sshd args=-t"));
    assert!(!log.contains("systemctl args=reload"));

    apply_host_command(&fixture, &install_root)
        .arg("--quiet")
        .assert()
        .success()
        .stdout("")
        .stderr("");
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(!log.contains("sshd args=-t"));
    assert!(!log.contains("systemctl args=reload"));
}

#[cfg(unix)]
#[test]
fn apply_host_restores_previous_policy_when_sshd_validation_fails() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let auth_dir = install_root.join("etc/ssh/auth_principals");
    let sshd_config = install_root.join("etc/ssh/sshd_config.d/grafhome-ca.conf");
    prepare_apply_host(&fixture);
    fs::create_dir_all(&auth_dir).unwrap();
    fs::create_dir_all(sshd_config.parent().unwrap()).unwrap();
    fs::write(auth_dir.join("departed"), "departed\n").unwrap();
    fs::write(&sshd_config, "previous config\n").unwrap();

    apply_host_command(&fixture, &install_root)
        .arg("--quiet")
        .env("FAKE_SSHD_FAIL_ONCE", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "restored the previous host policy",
        ));

    assert_eq!(
        fs::read_to_string(auth_dir.join("departed")).unwrap(),
        "departed\n"
    );
    assert!(!auth_dir.join("alice").exists());
    assert_eq!(
        fs::read_to_string(sshd_config).unwrap(),
        "previous config\n"
    );
    assert!(
        !install_root
            .join("etc/ssh/grafhome/user_ca_keys.pem")
            .exists()
    );
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn apply_host_restores_previous_policy_when_ssh_reload_fails() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let sshd_config = install_root.join("etc/ssh/sshd_config.d/grafhome-ca.conf");
    prepare_apply_host(&fixture);
    fs::create_dir_all(sshd_config.parent().unwrap()).unwrap();
    fs::write(&sshd_config, "previous config\n").unwrap();

    apply_host_command(&fixture, &install_root)
        .env("FAKE_SYSTEMCTL_RELOAD_FAIL_PAIR", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "neither sshd.service nor ssh.service could be reloaded",
        ))
        .stderr(predicate::str::contains(
            "restored the previous host policy",
        ));

    assert_eq!(
        fs::read_to_string(sshd_config).unwrap(),
        "previous config\n"
    );
    assert_eq!(
        fs::read_to_string(format!("{}.reload_failures", fixture.log.display())).unwrap(),
        "3\n"
    );
}

// macOS twin of the test above: the initial reload fails once, and
// rollback's own reload (the second `launchctl kickstart` invocation)
// succeeds, so this proves the fix's actual purpose end-to-end — a
// transient reload failure results in a clean, successfully-reported
// restore rather than the double-failure path covered separately below.
#[cfg(target_os = "macos")]
#[test]
fn apply_host_restores_previous_policy_when_macos_ssh_reload_fails_once() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let sshd_config = install_root.join("etc/ssh/sshd_config.d/grafhome-ca.conf");
    prepare_apply_host(&fixture);
    fs::create_dir_all(sshd_config.parent().unwrap()).unwrap();
    fs::write(&sshd_config, "previous config\n").unwrap();

    apply_host_command(&fixture, &install_root)
        .env("FAKE_LAUNCHCTL_KICKSTART_FAIL_ONCE", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "could not restart the macOS sshd launchd job",
        ))
        .stderr(predicate::str::contains(
            "restored the previous host policy",
        ));

    assert_eq!(
        fs::read_to_string(sshd_config).unwrap(),
        "previous config\n"
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        log.matches("launchctl args=kickstart -k system/com.openssh.sshd")
            .count(),
        2
    );
}

// Unlike the systemd fail-pair fixture (which eventually succeeds and lets
// rollback's own reload go through), this fake fails every invocation, so
// rollback's reload attempt fails too. That's a real, previously untested
// path: policy files still get restored (the write step precedes the
// reload step in the rollback closure), but the reported error must surface
// both the original failure and the rollback failure rather than claiming a
// clean restore.
#[cfg(target_os = "macos")]
#[test]
fn apply_host_reports_rollback_failure_when_macos_reload_fails_twice() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let sshd_config = install_root.join("etc/ssh/sshd_config.d/grafhome-ca.conf");
    prepare_apply_host(&fixture);
    fs::create_dir_all(sshd_config.parent().unwrap()).unwrap();
    fs::write(&sshd_config, "previous config\n").unwrap();

    apply_host_command(&fixture, &install_root)
        .env("FAKE_LAUNCHCTL_KICKSTART_FAIL", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "could not restart the macOS sshd launchd job",
        ))
        .stderr(predicate::str::contains("rollback failed"));

    // The file write half of rollback still runs (and succeeds) even though
    // the trailing reload it also attempts fails.
    assert_eq!(
        fs::read_to_string(sshd_config).unwrap(),
        "previous config\n"
    );
    // One call for the failed apply attempt, one for the failed rollback
    // attempt.
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        log.matches("launchctl args=kickstart -k system/com.openssh.sshd")
            .count(),
        2
    );
}

#[cfg(unix)]
#[test]
fn apply_host_rejects_non_file_in_managed_principals_directory() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install");
    let unexpected = install_root.join("etc/ssh/auth_principals/unexpected-directory");
    prepare_apply_host(&fixture);
    fs::create_dir_all(&unexpected).unwrap();

    apply_host_command(&fixture, &install_root)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "principals directory may contain only regular files",
        ));

    assert!(unexpected.is_dir());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(!log.contains("sshd args=-t"));
    assert!(!log.contains("systemctl args=reload"));
}

#[cfg(unix)]
#[test]
fn apply_host_rejects_locally_writable_policy() {
    let (dir, fixture) = exec_fixture();
    let policy = fixture.config_root.join("policy/hosts/ca-host.toml");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).unwrap();

    apply_host_command(&fixture, &dir.path().join("install"))
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("config provenance"))
        .stderr(predicate::str::contains("ca-host.toml"))
        .stderr(predicate::str::contains("permits group or world writes"));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approve_host_rejects_locally_writable_policy() {
    let (_dir, fixture) = exec_fixture();
    let policy = fixture.config_root.join("policy/hosts/ca-host.toml");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("config provenance"))
        .stderr(predicate::str::contains("ca-host.toml"));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approve_user_rejects_locally_writable_policy() {
    let (_dir, fixture) = exec_fixture();
    let policy = fixture.config_root.join("policy/hosts/ca-host.toml");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "user", "--yes", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("config provenance"))
        .stderr(predicate::str::contains("ca-host.toml"));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approve_host_rejects_off_origin_before_reading_the_request() {
    let (dir, fixture) = exec_fixture();
    let missing = dir.path().join("must-not-be-read.json");
    let ca_policy = fixture.config_root.join("policy/ca.toml");
    let local_host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    let policy = fs::read_to_string(&ca_policy).unwrap().replacen(
        &format!("target = \"{local_host}\""),
        "target = \"off-origin\"",
        1,
    );
    fs::write(ca_policy, policy).unwrap();
    fs::write(
        fixture.config_root.join("policy/hosts/off-origin.toml"),
        "ssh_roles = []\nprincipals = [\"test-off-origin\"]\n",
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--request-file"])
        .arg(&missing)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("GRAFHOME_CA_LOCAL_HOST", "off-origin")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "must be run on CA origin off-origin",
        ))
        .stderr(predicate::str::contains("must-not-be-read").not());

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn enrollment_import_rejects_off_origin_before_reading_the_export() {
    let (dir, fixture) = exec_fixture();
    let missing = dir.path().join("must-not-be-read.json");
    let ca_policy = fixture.config_root.join("policy/ca.toml");
    let local_host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    let policy = fs::read_to_string(&ca_policy).unwrap().replacen(
        &format!("target = \"{local_host}\""),
        "target = \"off-origin\"",
        1,
    );
    fs::write(ca_policy, policy).unwrap();
    fs::write(
        fixture.config_root.join("policy/hosts/off-origin.toml"),
        "ssh_roles = []\nprincipals = [\"test-off-origin\"]\n",
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment", "import", "--request-file"])
        .arg(&missing)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("GRAFHOME_CA_LOCAL_HOST", "off-origin")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "must be run on CA origin off-origin",
        ))
        .stderr(predicate::str::contains("must-not-be-read").not());

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn enrollment_export_reads_existing_public_material_without_changing_state() {
    let (dir, fixture) = exec_fixture();
    let host_material = fixture
        .config_root
        .join("../server-step/secrets/hosts/proxy-host");
    fs::create_dir_all(&host_material).unwrap();
    fs::write(
        host_material.join("provisioner.pub.json"),
        r#"{"kty":"EC","crv":"P-256","x":"host-x","y":"host-y"}"#,
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enrollment",
            "export",
            "host",
            "--host",
            "proxy-host",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ENROLLMENT:{\"version\":1,\"kind\":\"grafhome-host-enrollment-request\"",
        ))
        .stdout(predicate::str::contains("private").not())
        .stdout(predicate::str::contains("secret").not());

    let home = dir.path().join("home");
    let user_material = home.join(".config/grafhome-ca/users/alice/hosts/laptop-a");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::create_dir_all(&user_material).unwrap();
    fs::write(home.join(".ssh/id_ed25519.pub"), VALID_SSH_KEY_TWO).unwrap();
    fs::write(
        user_material.join("provisioner.pub.json"),
        r#"{"kty":"EC","crv":"P-256","x":"user-x","y":"user-y"}"#,
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enrollment",
            "export",
            "user",
            "--user",
            "alice",
            "--host",
            "laptop-a",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ENROLLMENT:{\"version\":1,\"kind\":\"grafhome-user-enrollment-request\"",
        ))
        .stdout(predicate::str::contains("private").not());

    assert!(!host_material.join("pending-enrollment.json").exists());
    assert!(!user_material.join("pending-enrollment.json").exists());
    assert!(!enrollment_registry_path(&fixture).exists());
    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn enrollment_import_binds_a_live_host_key_before_activating_the_registry() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    let request_file = fixture.config_root.join("host-export.json");
    let renewal_key = serde_json::json!({
        "kid": "ignored-metadata",
        "kty": "EC",
        "crv": "P-256",
        "x": "host-x",
        "y": "host-y"
    });
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec(&serde_json::json!({
            "authority": {
                "provisioners": [{
                    "type": "JWK",
                    "name": "grafhome-host-70726f78792d686f7374",
                    "key": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "host-x",
                        "y": "host-y"
                    },
                    "options": {
                        "x509": {"template": "legacy-x509"},
                        "ssh": {"template": "{\"type\":\"host\",\"keyId\":{{ toJson .KeyID }},\"principals\":[\"proxy-host\"]}"}
                    }
                }]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &request_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "grafhome-host-enrollment-request",
            "host": "proxy-host",
            "ssh_public_key": VALID_SSH_KEY,
            "renewal_public_jwk": renewal_key
        }))
        .unwrap(),
    )
    .unwrap();

    let original_ca = fs::read(&ca_json).unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment", "import", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_SYSTEMCTL_RESTART_FAIL_ONCE", "1")
        .assert()
        .failure();
    assert_eq!(fs::read(&ca_json).unwrap(), original_ca);
    assert!(!enrollment_registry_path(&fixture).exists());

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment", "import", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported host proxy-host"));

    let registry_path = fixture
        .config_root
        .join("../state/enrollments/registry.json");
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(&registry_path).unwrap()).unwrap();
    assert_eq!(registry["format_version"], 1);
    assert_eq!(registry["records"].as_array().unwrap().len(), 1);
    assert_eq!(registry["records"][0]["status"], "active");
    assert_eq!(registry["records"][0]["host"], "proxy-host");
    assert_eq!(
        registry["records"][0]["ssh_public_key"],
        VALID_SSH_KEY
            .split_once(" fixture")
            .map(|(key, _)| key)
            .unwrap()
    );
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&registry_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let config: serde_json::Value = serde_json::from_slice(&fs::read(&ca_json).unwrap()).unwrap();
    let template = config["authority"]["provisioners"][0]["options"]["ssh"]["template"]
        .as_str()
        .unwrap();
    let key_blob = VALID_SSH_KEY.split_whitespace().nth(1).unwrap();
    assert!(template.contains(&format!("grafhome-ca-ssh-key:{key_blob}")));
    assert!(template.contains(".Insecure.CR.Key.Marshal"));
    assert!(template.ends_with(
        "{\"type\":\"host\",\"keyId\":{{ toJson .KeyID }},\"principals\":[\"proxy-host\"]}"
    ));
    let log = fs::read_to_string(&fixture.log).unwrap_or_default();
    assert!(log.contains("systemctl args=restart step-ca.service"));
    assert!(log.contains("systemctl args=is-active step-ca.service"));
    assert!(log.contains("ca health"));

    fs::write(&fixture.log, "").unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment", "import", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    assert!(fs::read_to_string(&fixture.log).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn enrollment_import_backfills_a_live_host_after_policy_removal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    let request_file = fixture.config_root.join("departed-host-export.json");
    let renewal_key = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": "departed-x", "y": "departed-y"
    });
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec(&serde_json::json!({
            "authority": {"provisioners": [{
                "type": "JWK",
                "name": "grafhome-host-6465706172746564",
                "key": renewal_key,
                "options": {
                    "x509": {"template": "legacy-x509"},
                    "ssh": {"template": "{\"type\":\"host\",\"keyId\":{{ toJson .KeyID }},\"principals\":[\"departed\"]}"}
                }
            }]}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &request_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "grafhome-host-enrollment-request",
            "host": "departed",
            "ssh_public_key": VALID_SSH_KEY,
            "renewal_public_jwk": renewal_key
        }))
        .unwrap(),
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment", "import", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported host departed"));

    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert_eq!(registry["records"][0]["host"], "departed");
    assert_eq!(registry["records"][0]["status"], "active");
}

#[cfg(unix)]
#[test]
fn enrollment_export_reads_host_and_user_material_after_policy_removal() {
    let (dir, fixture) = exec_fixture();
    let host_material = fixture
        .config_root
        .join("../server-step/secrets/hosts/departed");
    fs::create_dir_all(&host_material).unwrap();
    fs::write(host_material.join("provisioner.priv.json"), "private\n").unwrap();
    fs::write(
        host_material.join("provisioner.pub.json"),
        r#"{"kty":"EC","crv":"P-256","x":"host-x","y":"host-y"}"#,
    )
    .unwrap();
    fs::write(host_material.join("renewal-password"), "secret\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enrollment",
            "export",
            "host",
            "--host",
            "departed",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .assert()
        .success()
        .stdout(predicate::str::contains("\"host\":\"departed\""));

    let home = dir.path().join("home");
    let user_material = home.join(".config/grafhome-ca/users/departed/hosts/retired-client");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::create_dir_all(&user_material).unwrap();
    fs::write(home.join(".ssh/id_ed25519"), "private\n").unwrap();
    fs::write(home.join(".ssh/id_ed25519.pub"), VALID_SSH_KEY_TWO).unwrap();
    fs::write(user_material.join("provisioner.priv.json"), "private\n").unwrap();
    fs::write(
        user_material.join("provisioner.pub.json"),
        r#"{"kty":"EC","crv":"P-256","x":"user-x","y":"user-y"}"#,
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enrollment",
            "export",
            "user",
            "--user",
            "departed",
            "--host",
            "retired-client",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .assert()
        .success()
        .stdout(predicate::str::contains("\"user\":\"departed\""))
        .stdout(predicate::str::contains("\"host\":\"retired-client\""));
}

#[cfg(unix)]
#[test]
fn enrollment_import_backfills_a_live_user_after_policy_removal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    let request_file = fixture.config_root.join("departed-user-export.json");
    let renewal_key = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": "departed-user-x", "y": "departed-user-y"
    });
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec(&serde_json::json!({
            "authority": {"provisioners": [{
                "type": "JWK",
                "name": "grafhome-user-6465706172746564-726574697265642d636c69656e74",
                "key": renewal_key,
                "options": {
                    "x509": {"template": "legacy-x509"},
                    "ssh": {"template": "{\"type\":\"user\",\"keyId\":{{ toJson .KeyID }},\"principals\":[\"departed\"]}"}
                }
            }]}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &request_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "grafhome-user-enrollment-request",
            "user": "departed",
            "host": "retired-client",
            "ssh_public_key": VALID_SSH_KEY_TWO,
            "renewal_public_jwk": renewal_key
        }))
        .unwrap(),
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment", "import", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Imported user departed@retired-client",
        ));

    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert_eq!(registry["records"][0]["user"], "departed");
    assert_eq!(registry["records"][0]["client_host"], "retired-client");
}

#[cfg(unix)]
#[test]
fn enrollment_import_rejects_an_ssh_key_already_in_tracked_revocations() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    let request_file = fixture.config_root.join("host-export.json");
    let renewal_key = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "replacement-host-x",
        "y": "replacement-host-y"
    });
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec(&serde_json::json!({
            "authority": {
                "provisioners": [{
                    "type": "JWK",
                    "name": "grafhome-host-70726f78792d686f7374",
                    "key": renewal_key
                }]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.config_root.join("policy/revocations.toml"),
        r#"format_version = 1

[[ssh_keys]]
kind = "host"
host = "retired-host"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOF9AFZbHgCPqUAtsZo9RLg6Fg4R+6rKThonym0jI0x3"
fingerprint = "SHA256:PwiHaeoThsUMMEFnpgXFZOaOM3GD6Jkn0rlVu+srKkI"
renewal_fingerprint = "SHA256:6nWqP5b7mBpArY0rPWTKT6lPhnZJYekV74X2Hdh8zCg"
revoked_at = "2026-07-24T20:14:15Z"
"#,
    )
    .unwrap();
    fs::write(
        &request_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "grafhome-host-enrollment-request",
            "host": "proxy-host",
            "ssh_public_key": VALID_SSH_KEY,
            "renewal_public_jwk": renewal_key
        }))
        .unwrap(),
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment", "import", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("previously revoked SSH key"));

    assert!(!enrollment_registry_path(&fixture).exists());
}

#[cfg(unix)]
#[test]
fn approval_rejects_an_ssh_key_already_in_tracked_revocations() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    let request_file = fixture.config_root.join("host-request.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, HOST_BOOTSTRAP_CA_JSON).unwrap();
    fs::write(
        fixture.config_root.join("policy/revocations.toml"),
        r#"format_version = 1

[[ssh_keys]]
kind = "host"
host = "retired-host"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOF9AFZbHgCPqUAtsZo9RLg6Fg4R+6rKThonym0jI0x3"
fingerprint = "SHA256:PwiHaeoThsUMMEFnpgXFZOaOM3GD6Jkn0rlVu+srKkI"
renewal_fingerprint = "SHA256:6nWqP5b7mBpArY0rPWTKT6lPhnZJYekV74X2Hdh8zCg"
revoked_at = "2026-07-24T20:14:15Z"
"#,
    )
    .unwrap();
    fs::write(
        &request_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "grafhome-host-enrollment-request",
            "host": "proxy-host",
            "ssh_public_key": VALID_SSH_KEY,
            "renewal_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "replacement-host-x",
                "y": "replacement-host-y"
            }
        }))
        .unwrap(),
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("previously revoked SSH key"));

    assert!(!enrollment_registry_path(&fixture).exists());
    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approval_rejects_a_renewal_key_already_in_tracked_revocations() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    let request_file = fixture.config_root.join("host-request.json");
    let renewal_key = serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": "reused-renewal-x", "y": "reused-renewal-y"
    });
    let (_, renewal_fingerprint) =
        grafhome_ca::enrollment_registry::canonical_jwk(&renewal_key).unwrap();
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, HOST_BOOTSTRAP_CA_JSON).unwrap();
    fs::write(
        fixture.config_root.join("policy/revocations.toml"),
        format!(
            r#"format_version = 1

[[ssh_keys]]
kind = "host"
host = "retired-host"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/YQ6c6N8hXDSaeqEQ1UvUgrymxo5vYQNy/1KO4HPpw"
fingerprint = "SHA256:+3AjrkPFtS9Wir1XpfmKixs1yTrmIGU28cbbOnEMW+o"
renewal_fingerprint = "{renewal_fingerprint}"
revoked_at = "2026-07-24T20:14:15Z"
"#,
        ),
    )
    .unwrap();
    fs::write(
        &request_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "grafhome-host-enrollment-request",
            "host": "proxy-host",
            "ssh_public_key": VALID_SSH_KEY,
            "renewal_public_jwk": renewal_key
        }))
        .unwrap(),
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("previously revoked renewal key"));

    assert!(!enrollment_registry_path(&fixture).exists());
    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approval_requires_import_for_a_live_unregistered_enrollment() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    let request_file = fixture.config_root.join("host-request.json");
    let renewal_key = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "host-x",
        "y": "host-y"
    });
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec(&serde_json::json!({
            "authority": {
                "provisioners": [
                    {
                        "type": "JWK",
                        "name": "grafhome-host-bootstrap",
                        "key": {"kid": "bootstrap-kid", "kty": "EC"},
                        "encryptedKey": "encrypted-bootstrap",
                        "claims": {
                            "defaultHostSSHCertDuration": "168h",
                            "maxHostSSHCertDuration": "720h",
                            "enableSSHCA": true
                        }
                    },
                    {
                        "type": "JWK",
                        "name": "grafhome-host-70726f78792d686f7374",
                        "key": renewal_key
                    }
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &request_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "kind": "grafhome-host-enrollment-request",
            "host": "proxy-host",
            "ssh_public_key": VALID_SSH_KEY,
            "renewal_public_jwk": renewal_key
        }))
        .unwrap(),
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--request-file"])
        .arg(&request_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("enrollment import"));

    assert!(!enrollment_registry_path(&fixture).exists());
    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn revoke_host_tracks_host_and_user_keys_through_the_policy_symlink() {
    let (dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-host-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"host-x","y":"host-y"}},{"name":"grafhome-user-616c696365-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"user-x","y":"user-y"}},{"name":"keep-me"}]}}"#,
    )
    .unwrap();
    let host_request = grafhome_ca::enrollment::HostRequest::new(
        "proxy-host",
        VALID_SSH_KEY,
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "host-x", "y": "host-y"
        }),
    );
    let user_request = grafhome_ca::enrollment::UserRequest::new(
        "alice",
        "proxy-host",
        VALID_SSH_KEY_TWO,
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "user-x", "y": "user-y"
        }),
    );
    let mut registry = grafhome_ca::enrollment_registry::EnrollmentRegistry::default();
    let now = "2026-07-24T20:14:15Z";
    let host_record =
        grafhome_ca::enrollment_registry::EnrollmentRecord::pending_host(&host_request, now)
            .unwrap();
    let user_record =
        grafhome_ca::enrollment_registry::EnrollmentRecord::pending_user(&user_request, now)
            .unwrap();
    registry.activate(host_record).unwrap();
    registry.activate(user_record).unwrap();
    registry.save(&enrollment_registry_path(&fixture)).unwrap();

    let deployed = fixture.config_root.join("policy/revocations.toml");
    let tracked = dir.path().join("tracked-revocations.toml");
    fs::rename(&deployed, &tracked).unwrap();
    std::os::unix::fs::symlink(&tracked, &deployed).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "revoke",
            "host",
            "--host",
            "proxy-host",
            "--reason",
            "device replaced",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "recorded 2 SSH keys for active revocation",
        ));

    assert!(
        fs::symlink_metadata(&deployed)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let policy = fs::read_to_string(&tracked).unwrap();
    assert_eq!(policy.matches("[[ssh_keys]]").count(), 2);
    assert_eq!(policy.matches("renewal_fingerprint = ").count(), 2);
    assert!(policy.contains("kind = \"host\""));
    assert!(policy.contains("kind = \"user\""));
    assert!(policy.contains("reason = \"device replaced\""));
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert!(
        registry["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["status"] == "revoked")
    );
    let ca = fs::read_to_string(ca_json).unwrap();
    assert!(!ca.contains("grafhome-host-70726f78792d686f7374"));
    assert!(!ca.contains("grafhome-user-616c696365-70726f78792d686f7374"));
    assert!(ca.contains("keep-me"));
}

#[cfg(unix)]
#[test]
fn revoke_host_does_not_treat_a_reused_name_tombstone_as_live_registry_coverage() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-host-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"replacement-x","y":"replacement-y"}},{"name":"keep-me"}]}}"#,
    )
    .unwrap();

    let request = grafhome_ca::enrollment::HostRequest::new(
        "proxy-host",
        VALID_SSH_KEY,
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "retired-x", "y": "retired-y"
        }),
    );
    let mut registry = grafhome_ca::enrollment_registry::EnrollmentRegistry::default();
    let record = grafhome_ca::enrollment_registry::EnrollmentRecord::pending_host(
        &request,
        "2026-07-24T20:14:15Z",
    )
    .unwrap();
    registry.activate(record).unwrap();
    let selected = registry.live_for_host("proxy-host");
    registry.mark_revoked(&selected, "2026-07-24T20:15:15Z");
    registry.save(&enrollment_registry_path(&fixture)).unwrap();
    fs::write(
        fixture.config_root.join("policy/revocations.toml"),
        r#"format_version = 1

[[ssh_keys]]
kind = "host"
host = "proxy-host"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOF9AFZbHgCPqUAtsZo9RLg6Fg4R+6rKThonym0jI0x3"
fingerprint = "SHA256:PwiHaeoThsUMMEFnpgXFZOaOM3GD6Jkn0rlVu+srKkI"
renewal_fingerprint = "SHA256:6nWqP5b7mBpArY0rPWTKT6lPhnZJYekV74X2Hdh8zCg"
revoked_at = "2026-07-24T20:15:15Z"
"#,
    )
    .unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("enrollment import"));

    let ca = fs::read_to_string(ca_json).unwrap();
    assert!(ca.contains("grafhome-host-70726f78792d686f7374"));
    assert!(ca.contains("replacement-x"));
}

#[cfg(unix)]
#[test]
fn revoke_host_keeps_tracked_keys_staged_when_ca_activation_fails_and_retries_cleanly() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-host-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"proxy-host-host-x","y":"host-y"}},{"name":"grafhome-user-616c696365-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"proxy-host-user-x","y":"user-y"}},{"name":"keep-me"}]}}"#,
    )
    .unwrap();
    seed_host_and_user_registry(&fixture, "proxy-host", "alice");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_SYSTEMCTL_RESTART_FAIL_ONCE", "1")
        .assert()
        .failure();

    let policy = fs::read_to_string(fixture.config_root.join("policy/revocations.toml")).unwrap();
    assert_eq!(policy.matches("[[ssh_keys]]").count(), 2);
    let ca = fs::read_to_string(&ca_json).unwrap();
    assert!(ca.contains("grafhome-host-70726f78792d686f7374"));
    assert!(ca.contains("grafhome-user-616c696365-70726f78792d686f7374"));
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert!(
        registry["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["status"] == "active")
    );

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let policy = fs::read_to_string(fixture.config_root.join("policy/revocations.toml")).unwrap();
    assert_eq!(policy.matches("[[ssh_keys]]").count(), 2);
    let ca = fs::read_to_string(ca_json).unwrap();
    assert!(!ca.contains("grafhome-host-70726f78792d686f7374"));
    assert!(!ca.contains("grafhome-user-616c696365-70726f78792d686f7374"));
}

#[cfg(unix)]
#[test]
fn revoke_host_restarts_ca_when_disk_is_already_pruned_but_registry_is_active() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"keep-me"}]}}"#,
    )
    .unwrap();
    seed_host_and_user_registry(&fixture, "proxy-host", "alice");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("systemctl args=restart step-ca.service"));
    assert!(log.contains("ca health"));
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert!(
        registry["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["status"] == "revoked")
    );
}

#[cfg(unix)]
#[test]
fn revoke_host_reports_a_repaired_ledger_for_existing_tombstones() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"keep-me"}]}}"#,
    )
    .unwrap();
    seed_host_and_user_registry(&fixture, "proxy-host", "alice");
    let registry_path = enrollment_registry_path(&fixture);
    let mut registry =
        grafhome_ca::enrollment_registry::EnrollmentRegistry::load(&registry_path).unwrap();
    let selected = registry.records_for_host("proxy-host");
    registry.mark_revoked(&selected, "2026-07-24T20:15:15Z");
    registry.save(&registry_path).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Restored active revocation tracking for host proxy-host: recorded 2 SSH keys.",
        ))
        .stdout(predicate::str::contains("Commit and distribute"))
        .stdout(predicate::str::contains("already revoked").not());

    let policy = fs::read_to_string(fixture.config_root.join("policy/revocations.toml")).unwrap();
    assert_eq!(policy.matches("[[ssh_keys]]").count(), 2);
}

#[cfg(unix)]
fn enrollment_registry_path(fixture: &ExecFixture) -> PathBuf {
    fixture
        .config_root
        .join("../state/enrollments/registry.json")
}

#[cfg(unix)]
fn seed_host_and_user_registry(fixture: &ExecFixture, host: &str, user: &str) {
    let mut registry = grafhome_ca::enrollment_registry::EnrollmentRegistry::default();
    let now = "2026-07-24T20:14:15Z";
    let host_request = grafhome_ca::enrollment::HostRequest::new(
        host,
        VALID_SSH_KEY,
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": format!("{host}-host-x"), "y": "host-y"
        }),
    );
    let user_request = grafhome_ca::enrollment::UserRequest::new(
        user,
        host,
        VALID_SSH_KEY_TWO,
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": format!("{host}-user-x"), "y": "user-y"
        }),
    );
    let host_record =
        grafhome_ca::enrollment_registry::EnrollmentRecord::pending_host(&host_request, now)
            .unwrap();
    let user_record =
        grafhome_ca::enrollment_registry::EnrollmentRecord::pending_user(&user_request, now)
            .unwrap();
    registry.activate(host_record).unwrap();
    registry.activate(user_record).unwrap();
    registry.save(&enrollment_registry_path(fixture)).unwrap();
}

#[cfg(unix)]
fn seed_two_user_clients_registry(
    fixture: &ExecFixture,
    user: &str,
    first_host: &str,
    second_host: &str,
) {
    let mut registry = grafhome_ca::enrollment_registry::EnrollmentRegistry::default();
    let now = "2026-07-24T20:14:15Z";
    for (host, key, x) in [
        (first_host, VALID_SSH_KEY, "first-user-x"),
        (second_host, VALID_SSH_KEY_TWO, "second-user-x"),
    ] {
        let request = grafhome_ca::enrollment::UserRequest::new(
            user,
            host,
            key,
            serde_json::json!({
                "kty": "EC", "crv": "P-256", "x": x, "y": "user-y"
            }),
        );
        let record =
            grafhome_ca::enrollment_registry::EnrollmentRecord::pending_user(&request, now)
                .unwrap();
        registry.activate(record).unwrap();
    }
    registry.save(&enrollment_registry_path(fixture)).unwrap();
}

#[cfg(unix)]
fn seed_user_registry_record(
    fixture: &ExecFixture,
    user: &str,
    host: &str,
    ssh_public_key: &str,
    renewal_public_jwk: serde_json::Value,
) {
    let request =
        grafhome_ca::enrollment::UserRequest::new(user, host, ssh_public_key, renewal_public_jwk);
    let record = grafhome_ca::enrollment_registry::EnrollmentRecord::pending_user(
        &request,
        "2026-07-24T20:14:15Z",
    )
    .unwrap();
    let mut registry = grafhome_ca::enrollment_registry::EnrollmentRegistry::default();
    registry.activate(record).unwrap();
    registry.save(&enrollment_registry_path(fixture)).unwrap();
}

#[cfg(unix)]
#[test]
fn revoke_host_rejects_locally_writable_policy() {
    let (_dir, fixture) = exec_fixture();
    let policy = fixture.config_root.join("policy/hosts/ca-host.toml");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("config provenance"))
        .stderr(predicate::str::contains("ca-host.toml"));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn revoke_user_rejects_locally_writable_policy() {
    let (_dir, fixture) = exec_fixture();
    let policy = fixture.config_root.join("policy/hosts/ca-host.toml");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "user", "--user", "alice", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("config provenance"))
        .stderr(predicate::str::contains("ca-host.toml"));

    assert!(!fixture.log.exists());
}

#[test]
fn check_rejects_unknown_canonical_provisioner_role() {
    let dir = tempdir().unwrap();
    let config_root = dir.path().join("grafhome-ca");
    copy_dir(&example_config_root(), &config_root);
    let provisioners = config_root.join("policy/ca.toml");
    let mut text = fs::read_to_string(&provisioners).unwrap();
    text.push_str(
        "\n[provisioners.host_renew]\nname = \"grafhome-host-renew\"\n\
         default_ttl = \"168h\"\nmax_ttl = \"720h\"\n",
    );
    fs::write(provisioners, text).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .arg("check")
        .arg("--config-root")
        .arg(config_root)
        .assert()
        .failure()
        .stderr(predicate::str::contains("provisioners.host_renew"))
        .stderr(predicate::str::contains("unknown provisioner role"));
}

#[test]
fn migrate_policy_creates_a_valid_host_centric_tree() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("policy");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["migrate", "policy", "--config-root"])
        .arg(legacy_config_root())
        .arg("--out-dir")
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("migrated canonical policy"));

    let policy = grafhome_ca::policy::Policy::load(dir.path()).expect("migrated policy loads");
    assert_eq!(policy.hosts.len(), 4);
    assert_eq!(policy.user_clients.len(), 4);
    assert_eq!(policy.user_remotes.len(), 4);
    assert!(output.join("ca.toml").is_file());
    assert!(output.join("users.toml").is_file());
    assert!(output.join("hosts/ca-host.toml").is_file());
    assert!(!output.join("hosts.toml").exists());

    let ca = fs::read_to_string(output.join("ca.toml")).unwrap();
    let users = fs::read_to_string(output.join("users.toml")).unwrap();
    let edge_host = fs::read_to_string(output.join("hosts/edge-host.toml")).unwrap();
    assert!(!ca.contains("status = \"active\""));
    assert!(!ca.contains("type ="));
    assert!(!ca.contains("renewal_default_ttl"));
    assert_eq!(ca.matches("renewal_max_ttl").count(), 1);
    assert!(!users.contains("principal = \"alice\""));
    assert!(!users.contains("status = \"active\""));
    let edge_document = edge_host.parse::<toml::Value>().unwrap();
    assert_eq!(
        edge_document["ssh_roles"],
        toml::Value::Array(vec![
            toml::Value::String("server".to_owned()),
            toml::Value::String("client".to_owned()),
        ])
    );
    assert!(edge_host.contains("enrollment = true"));
    assert!(!edge_host.contains("[user_access.alice.enrollment]"));
}

#[test]
fn migrate_policy_rejects_canonical_sources_and_existing_outputs() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("policy");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["migrate", "policy", "--config-root"])
        .arg(example_config_root())
        .arg("--out-dir")
        .arg(&output)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already uses the canonical"));
    assert!(!output.exists());

    fs::create_dir(&output).unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["migrate", "policy", "--config-root"])
        .arg(legacy_config_root())
        .arg("--out-dir")
        .arg(&output)
        .assert()
        .failure()
        .stderr(predicate::str::contains("migration output already exists"));
}

#[test]
fn render_dry_run_lists_staged_files() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("render")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "hosts/ca-host/srv/example-ca/step/config/ca.json",
        ))
        .stdout(predicate::str::contains(
            "hosts/proxy-host/etc/apache2/conf-available/grafhome-ca-proxy.conf",
        ));
}

#[test]
fn render_rejects_clean_dry_run() {
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["render", "--dry-run", "--clean"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "the argument '--dry-run' cannot be used with '--clean'",
        ));
}

#[test]
fn render_writes_to_staging_directory() {
    let dir = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("render")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--out-dir")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("rendered "));

    let ca_json = fs::read_to_string(
        dir.path()
            .join("hosts/ca-host/srv/example-ca/step/config/ca.json"),
    )
    .unwrap();
    assert!(ca_json.contains("\"ca.example.test\""));
    assert!(ca_json.contains("\"ca-origin.example.test\""));
    assert!(ca_json.contains("\"address\": \"198.51.100.20:8443\""));
    assert!(ca_json.contains("\"allowWildcardNames\": false"));
    assert!(ca_json.contains("RUNTIME_SECRET_PLACEHOLDER"));
    assert!(
        dir.path()
            .join("hosts/ca-host/etc/ssh/grafhome/user_ca_keys.pem")
            .exists()
    );
    assert!(
        dir.path()
            .join("hosts/ca-host/etc/ssh/grafhome/revoked_user_certs")
            .exists()
    );
}

#[test]
fn render_clean_removes_stale_staging_files() {
    let dir = tempdir().unwrap();
    let stale = dir.path().join("hosts/old-host/stale.txt");
    fs::create_dir_all(stale.parent().unwrap()).unwrap();
    fs::write(&stale, "old").unwrap();
    let unrelated = dir.path().join("operator-notes.txt");
    fs::write(&unrelated, "keep").unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("render")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--out-dir")
        .arg(dir.path())
        .arg("--clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("rendered "));

    assert!(!stale.exists());
    assert_eq!(fs::read_to_string(&unrelated).unwrap(), "keep");
    assert!(
        dir.path()
            .join("hosts/ca-host/srv/example-ca/step/config/ca.json")
            .exists()
    );
}

#[test]
fn export_dry_run_lists_bundle_without_live_ca_state() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("export")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("root_fingerprint"))
        .stdout(predicate::str::contains("ssh_known_hosts"))
        .stdout(predicate::str::contains("manifest.json"));
}

#[cfg(unix)]
#[test]
fn export_writes_trust_bundle_and_manifest() {
    use std::os::unix::fs::PermissionsExt;

    let dir = trusted_tempdir();
    let config_root = dir.path().join("grafhome-ca");
    let ca_state = dir.path().join("state");
    let step_bin = dir.path().join("fake-step");
    let out_dir = dir.path().join("public");
    copy_dir(&example_config_root(), &config_root);
    fs::create_dir_all(ca_state.join("step/certs")).unwrap();
    fs::write(
        ca_state.join("step/certs/root_ca.crt"),
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(
        ca_state.join("step/certs/ssh_host_ca_key.pub"),
        "ssh-ed25519 AAAAhost grafhome-host-ca\n",
    )
    .unwrap();
    fs::write(
        ca_state.join("step/certs/ssh_user_ca_key.pub"),
        "ssh-ed25519 AAAAuser grafhome-user-ca\n",
    )
    .unwrap();
    fs::write(
        &step_bin,
        "#!/bin/sh\nprintf '%s\\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    )
    .unwrap();
    fs::set_permissions(&step_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let deployment = fs::read_to_string(config_root.join("config/deployment.env")).unwrap();
    let deployment = deployment
        .replace(
            "GRAFHOME_CA_STATE_DIR=/srv/example-ca",
            &format!("GRAFHOME_CA_STATE_DIR={}", ca_state.display()),
        )
        .replace(
            "GRAFHOME_CA_ROOT_STEP_BIN=/root/.local/bin/step",
            &format!("GRAFHOME_CA_ROOT_STEP_BIN={}", step_bin.display()),
        )
        .replace(
            "GRAFHOME_CA_PASSWORD_FILE=/srv/example-ca/secrets/intermediate_ca_password",
            &format!(
                "GRAFHOME_CA_PASSWORD_FILE={}",
                ca_state.join("secrets/intermediate_ca_password").display()
            ),
        );
    fs::write(config_root.join("config/deployment.env"), deployment).unwrap();

    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    cmd.arg("export")
        .arg("--config-root")
        .arg(&config_root)
        .arg("--out-dir")
        .arg(&out_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("exported 7 public files"));

    assert!(out_dir.join("root_ca.crt").exists());
    assert!(out_dir.join("user_ca_keys.pem").exists());
    assert!(out_dir.join("ssh_known_hosts").exists());
    let known_hosts = fs::read_to_string(out_dir.join("ssh_known_hosts")).unwrap();
    assert!(known_hosts.contains("@cert-authority"));
    assert!(known_hosts.contains("ca-origin.example.test"));
    assert!(known_hosts.contains("ssh-ed25519 AAAAhost"));

    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas/public/export-manifest.schema.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out_dir.join("manifest.json")).unwrap()).unwrap();
    grafhome_ca::schema::validate(manifest_path, &manifest).unwrap();
}

#[test]
fn materialize_test_ca_fixture_emits_parseable_placeholder_free_json() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    let output = cmd
        .arg("materialize-test-ca-fixture")
        .arg("--config-root")
        .arg(example_config_root())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let provisioners = value["authority"]["provisioners"].as_array().unwrap();

    assert!(!text.contains("RUNTIME_SECRET_PLACEHOLDER"));
    assert!(!text.contains("/srv/example-ca"));
    assert_eq!(value["address"], "127.0.0.1:0");
    assert_eq!(
        value["db"]["dataSource"],
        "/dev/null/grafhome-ca-test-fixture/step/db"
    );
    assert!(provisioners.iter().any(|item| {
        item["name"] == "grafhome-user-enrollment"
            && item["type"] == "JWK"
            && item["key"]["kty"] == "EC"
            && item.get("encryptedKey").is_none()
            && item["key"].get("d").is_none()
    }));
    for provisioner in provisioners {
        assert!(provisioner.get("encryptedKey").is_none());
    }
}

#[test]
fn materialize_writes_placeholder_free_ca_json() {
    let (dir, fixture) = exec_fixture();
    let staging = dir.path().join("staging");
    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .arg("render")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--out-dir")
        .arg(&staging)
        .assert()
        .success();
    let origin_host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    let staged_ca_json = staging.join(format!(
        "hosts/{origin_host}{}/step/config/ca.json",
        dir.path().join("state").display()
    ));
    let live_ca_json = dir.path().join("live-ca.json");
    fs::write(
        &live_ca_json,
        r#"{
          "authority": {
            "provisioners": [
              {
                "type": "JWK",
                "name": "grafhome-host-bootstrap",
                "key": {"kid": "bootstrap-kid", "kty": "EC", "crv": "P-256", "x": "bootstrap-x", "y": "bootstrap-y"},
                "encryptedKey": "encrypted-bootstrap",
                "claims": {"enableSSHCA": true}
              }
            ]
          }
        }"#,
    )
    .unwrap();
    let jwk_dir = dir.path().join("state/secrets/provisioners");
    let out_file = dir.path().join("materialized-ca.json");

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .arg("materialize")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--live-ca-json")
        .arg(&live_ca_json)
        .arg("--staged-ca-json")
        .arg(&staged_ca_json)
        .arg("--jwk-dir")
        .arg(&jwk_dir)
        .arg("--out-file")
        .arg(&out_file)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let text = fs::read_to_string(out_file).unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(dir.path().join("materialized-ca.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let provisioners = value["authority"]["provisioners"].as_array().unwrap();

    assert!(!text.contains("RUNTIME_SECRET_PLACEHOLDER"));
    assert!(!text.contains("encryptedKey"));
    assert!(provisioners.iter().any(|item| {
        item["name"] == "grafhome-host-bootstrap"
            && item["claims"]["defaultHostSSHCertDuration"] == "168h"
            && item["options"]["ssh"]["template"]
                .as_str()
                .is_some_and(|template| template.contains("\"type\": \"host\""))
    }));
    assert!(provisioners.iter().any(|item| {
        item["name"] == "grafhome-user-enrollment"
            && item["key"]["kid"] == "enrollment-kid"
            && item["claims"]["defaultUserSSHCertDuration"] == "24h"
    }));
    assert!(!provisioners.iter().any(|item| item["type"] == "SSHPOP"));
}

#[cfg(unix)]
#[test]
fn migrate_enrollment_provisioner_keys_preserves_public_keys_and_is_idempotent() {
    let (_dir, fixture) = exec_fixture();
    let key_dir = fixture.config_root.join("../state/secrets/provisioners");
    fs::remove_dir_all(&key_dir).unwrap();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    let live = serde_json::json!({
        "authority": {
            "provisioners": [
                {
                    "type": "JWK",
                    "name": "grafhome-host-bootstrap",
                    "key": {"alg": "ES256", "kid": "bootstrap-kid", "kty": "EC", "use": "sig", "crv": "P-256", "x": "bootstrap-x", "y": "bootstrap-y"},
                    "encryptedKey": "encrypted-bootstrap"
                },
                {
                    "type": "JWK",
                    "name": "grafhome-user-enrollment",
                    "key": {"alg": "ES256", "kid": "enrollment-kid", "kty": "EC", "use": "sig", "crv": "P-256", "x": "enrollment-x", "y": "enrollment-y"},
                    "encryptedKey": "encrypted-enrollment"
                }
            ]
        }
    });
    fs::write(&ca_json, serde_json::to_vec_pretty(&live).unwrap()).unwrap();

    let command = || {
        let mut command = Command::cargo_bin("grafhome-ca").unwrap();
        command
            .args(["migrate", "enrollment-provisioner-keys"])
            .arg("--config-root")
            .arg(&fixture.config_root)
            .env("PATH", prepend_path(&fixture.fake_bin))
            .env("FAKE_LOG", &fixture.log);
        command
    };
    command()
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "migrated grafhome-host-bootstrap enrollment provisioner key",
        ))
        .stdout(predicate::str::contains(
            "migrated grafhome-user-enrollment enrollment provisioner key",
        ));

    for (name, kid) in [
        ("grafhome-host-bootstrap", "bootstrap-kid"),
        ("grafhome-user-enrollment", "enrollment-kid"),
    ] {
        let public: serde_json::Value =
            serde_json::from_slice(&fs::read(key_dir.join(format!("{name}.pub.json"))).unwrap())
                .unwrap();
        assert_eq!(public["kid"], kid);
        assert_ne!(
            fs::read(key_dir.join(format!("{name}.password"))).unwrap(),
            b"ca-password\n"
        );
        assert_eq!(
            fs::metadata(key_dir.join(format!("{name}.priv.json")))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&ca_json).unwrap()).unwrap(),
        live
    );

    let host_public = key_dir.join("grafhome-host-bootstrap.pub.json");
    let valid_host_public = fs::read(&host_public).unwrap();
    fs::write(
        &host_public,
        r#"{"kty":"EC","crv":"P-256","x":"wrong","y":"wrong"}"#,
    )
    .unwrap();
    command()
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not match live enrollment provisioner",
        ));
    fs::write(&host_public, valid_host_public).unwrap();

    command()
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "grafhome-user-enrollment enrollment provisioner key already migrated",
        ));
}

#[cfg(unix)]
#[test]
fn migrate_enrollment_provisioner_keys_resumes_after_a_partial_migration() {
    let (_dir, fixture) = exec_fixture();
    let key_dir = fixture.config_root.join("../state/secrets/provisioners");
    fs::remove_dir_all(&key_dir).unwrap();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec_pretty(&serde_json::json!({
            "authority": {
                "provisioners": [
                    {
                        "type": "JWK",
                        "name": "grafhome-host-bootstrap",
                        "key": {"kty": "EC", "crv": "P-256", "x": "bootstrap-x", "y": "bootstrap-y"},
                        "encryptedKey": "encrypted-bootstrap"
                    },
                    {
                        "type": "JWK",
                        "name": "grafhome-user-enrollment",
                        "key": {"kty": "EC", "crv": "P-256", "x": "enrollment-x", "y": "enrollment-y"}
                    }
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let command = || {
        let mut command = Command::cargo_bin("grafhome-ca").unwrap();
        command
            .args(["migrate", "enrollment-provisioner-keys"])
            .arg("--config-root")
            .arg(&fixture.config_root)
            .env("PATH", prepend_path(&fixture.fake_bin))
            .env("FAKE_LOG", &fixture.log);
        command
    };
    command()
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "restore it from backup before migration",
        ));

    assert!(key_dir.join("grafhome-host-bootstrap.password").is_file());
    assert!(!key_dir.join("grafhome-user-enrollment.password").exists());

    let mut live: serde_json::Value = serde_json::from_slice(&fs::read(&ca_json).unwrap()).unwrap();
    live["authority"]["provisioners"][1]["encryptedKey"] =
        serde_json::json!("encrypted-enrollment");
    fs::write(&ca_json, serde_json::to_vec_pretty(&live).unwrap()).unwrap();

    command()
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "grafhome-host-bootstrap enrollment provisioner key already migrated",
        ))
        .stdout(predicate::str::contains(
            "migrated grafhome-user-enrollment enrollment provisioner key",
        ));
    assert!(key_dir.join("grafhome-user-enrollment.password").is_file());
}

#[cfg(unix)]
#[test]
fn approve_host_prints_one_complete_grant() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-host-bootstrap","key":{"kid":"bootstrap-kid"},"encryptedKey":"preserve-bootstrap-secret","claims":{"defaultHostSSHCertDuration":"24h","maxHostSSHCertDuration":"168h","disableRenewal":true}}]}}"#,
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    let request = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-request",
        "host": "proxy-host",
        "ssh_public_key": VALID_SSH_KEY,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"}
    });

    cmd.args(["approve", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--yes")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("REQUEST:{request}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("GRANT:{\"version\":1"))
        .stdout(predicate::str::contains("\"host\":\"proxy-host\""))
        .stdout(predicate::str::contains(
            "\"root_fingerprint\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
        ))
        .stdout(predicate::str::contains(
            "\"token\":\"token-for-proxy-host\"",
        ));

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ca token proxy-host --ssh --host"));
    assert!(log.contains("--principal proxy-host"));
    assert!(log.contains("--principal ca.example.test"));
    assert!(log.contains("--not-after 15m"));
    assert!(log.contains("--cert-not-after 168h"));
    let key_blob = VALID_SSH_KEY.split_whitespace().nth(1).unwrap();
    assert!(log.contains(&format!("--set grafhomeSSHPublicKey={key_blob}")));
    let enrollment_keys = fixture
        .config_root
        .parent()
        .unwrap()
        .join("state/secrets/provisioners");
    assert!(log.contains(&format!(
        "--key {}",
        enrollment_keys
            .join("grafhome-host-bootstrap.priv.json")
            .display()
    )));
    assert!(log.contains(&format!(
        "--password-file {}",
        enrollment_keys
            .join("grafhome-host-bootstrap.password")
            .display()
    )));
    assert!(!log.contains("--provisioner-password-file"));
    let config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(ca_json).unwrap()).unwrap();
    let provisioners = config["authority"]["provisioners"].as_array().unwrap();
    let bootstrap = provisioners
        .iter()
        .find(|item| item["name"] == "grafhome-host-bootstrap")
        .unwrap();
    assert_eq!(bootstrap["key"]["kid"], "bootstrap-kid");
    assert_eq!(bootstrap["encryptedKey"], "preserve-bootstrap-secret");
    assert_eq!(bootstrap["claims"]["defaultHostSSHCertDuration"], "168h");
    assert_eq!(bootstrap["claims"]["maxHostSSHCertDuration"], "720h");
    assert_eq!(bootstrap["claims"]["disableRenewal"], true);
    assert!(
        bootstrap["options"]["ssh"]["template"]
            .as_str()
            .unwrap()
            .contains("grafhomeSSHPublicKey")
    );
    let renewal = provisioners
        .iter()
        .find(|item| item["name"] == "grafhome-host-70726f78792d686f7374")
        .unwrap();
    assert!(
        renewal["options"]["ssh"]["template"]
            .as_str()
            .unwrap()
            .contains(&format!("grafhome-ca-ssh-key:{key_blob}"))
    );
    assert!(
        provisioners
            .iter()
            .any(|item| item["name"] == "grafhome-host-70726f78792d686f7374")
    );
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert_eq!(registry["records"].as_array().unwrap().len(), 1);
    assert_eq!(registry["records"][0]["status"], "active");
}

#[cfg(unix)]
#[test]
fn approve_host_rejects_malformed_ttl_before_step_runs() {
    let (_dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    let request = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-request",
        "host": "proxy-host",
        "ssh_public_key": VALID_SSH_KEY,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"}
    });

    cmd.args(["approve", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--yes")
        .arg("--ttl")
        .arg(".")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("REQUEST:{request}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "duration must use Smallstep units",
        ));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approve_host_token_failure_leaves_ca_state_untouched() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-host-bootstrap","key":{"kid":"bootstrap-kid"},"encryptedKey":"encrypted-bootstrap","claims":{"defaultHostSSHCertDuration":"168h","maxHostSSHCertDuration":"720h","enableSSHCA":true}},{"name":"keep-me"}]}}"#;
    fs::write(&ca_json, original).unwrap();
    let request = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-request",
        "host": "proxy-host",
        "ssh_public_key": VALID_SSH_KEY,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"}
    });

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_FAIL", "ca-token")
        .write_stdin(format!("REQUEST:{request}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("simulated token failure"));

    assert_eq!(fs::read_to_string(ca_json).unwrap(), original);
    assert!(
        !fixture
            .config_root
            .join("../state/step/templates/ssh/grafhome-host-70726f78792d686f7374.tpl")
            .exists()
    );
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert_eq!(registry["records"].as_array().unwrap().len(), 1);
    assert_eq!(registry["records"][0]["status"], "pending");
}

#[cfg(unix)]
#[test]
fn approve_user_token_failure_leaves_ca_state_untouched() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    let original = r#"{"authority":{"provisioners":[{"type":"JWK","name":"grafhome-user-enrollment","key":{"kid":"enrollment-kid"},"encryptedKey":"encrypted-enrollment","claims":{"defaultUserSSHCertDuration":"24h","maxUserSSHCertDuration":"2562047h","enableSSHCA":true}},{"name":"keep-me"}]}}"#;
    fs::write(&ca_json, original).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "user", "--yes", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_FAIL", "ca-token")
        .write_stdin(user_enrollment_request())
        .assert()
        .failure()
        .stderr(predicate::str::contains("simulated token failure"));

    assert_eq!(fs::read_to_string(ca_json).unwrap(), original);
    assert!(
        !fixture
            .config_root
            .join("../state/step/templates/ssh/grafhome-user-616c696365-63612d686f7374.tpl")
            .exists()
    );
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert_eq!(registry["records"].as_array().unwrap().len(), 1);
    assert_eq!(registry["records"][0]["status"], "pending");
}

#[cfg(unix)]
#[test]
fn enroll_host_restart_rebuilds_request_without_replacing_keys() {
    let (_dir, fixture) = exec_fixture();
    let args = [
        "enroll",
        "host",
        "--host",
        "proxy-host",
        "--request-only",
        "--config-root",
    ];

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let material = fixture
        .config_root
        .join("../server-step/secrets/hosts/proxy-host");
    let pending = material.join("pending-enrollment.json");
    let original_request = fs::read_to_string(&pending).unwrap();
    let private_jwk = fs::read(material.join("provisioner.priv.json")).unwrap();
    let public_jwk = fs::read(material.join("provisioner.pub.json")).unwrap();
    let password = fs::read(material.join("renewal-password")).unwrap();
    let original_log = fs::read(&fixture.log).unwrap();
    fs::write(&pending, "corrupt pending request\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .arg("--restart")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Restarted a public host enrollment request for proxy-host",
        ))
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"));

    assert_eq!(fs::read_to_string(pending).unwrap(), original_request);
    assert_eq!(
        fs::read(material.join("provisioner.priv.json")).unwrap(),
        private_jwk
    );
    assert_eq!(
        fs::read(material.join("provisioner.pub.json")).unwrap(),
        public_jwk
    );
    assert_eq!(
        fs::read(material.join("renewal-password")).unwrap(),
        password
    );
    assert_eq!(fs::read(&fixture.log).unwrap(), original_log);
}

#[cfg(unix)]
#[test]
fn enroll_host_restart_requires_existing_enrollment_material() {
    let (_dir, fixture) = exec_fixture();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "host",
            "--host",
            "proxy-host",
            "--restart",
            "--request-only",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot restart because"))
        .stderr(predicate::str::contains(
            "run enroll host without --restart",
        ));
}

#[cfg(unix)]
#[test]
fn enroll_host_restart_rejects_a_removed_policy_host() {
    let (_dir, fixture) = exec_fixture();
    let args = [
        "enroll",
        "host",
        "--host",
        "edge-host",
        "--request-only",
        "--config-root",
    ];
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let pending = fixture
        .config_root
        .join("../server-step/secrets/hosts/edge-host/pending-enrollment.json");
    let original = fs::read(&pending).unwrap();
    fs::remove_file(fixture.config_root.join("policy/hosts/edge-host.toml")).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .arg("--restart")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown host"));

    assert_eq!(fs::read(pending).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn enroll_host_uses_trusted_path_step_when_configured_path_is_missing() {
    let (dir, fixture) = exec_fixture();
    let path = configure_step_path_fallback(&dir, &fixture);

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "host",
            "--host",
            "proxy-host",
            "--request-only",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", path)
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"));

    assert!(
        fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("crypto jwk create")
    );
}

#[cfg(unix)]
#[test]
fn renew_host_uses_trusted_path_step_when_configured_path_is_missing() {
    let (dir, fixture) = exec_fixture();
    let path = configure_step_path_fallback(&dir, &fixture);
    let provisioners = fixture.config_root.join("policy/ca.toml");
    let text = fs::read_to_string(&provisioners).unwrap().replacen(
        "default_ttl = \"168h\"",
        "default_ttl = \"168h\"\nrenewal_default_ttl = \"24h\"",
        1,
    );
    fs::write(&provisioners, text).unwrap();
    let material = fixture
        .config_root
        .join("../server-step/secrets/hosts/proxy-host");
    fs::create_dir_all(&material).unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();
    fs::write(material.join("renewal-password"), "password\n").unwrap();
    let registry = enrollment_registry_path(&fixture);
    fs::create_dir_all(registry.parent().unwrap()).unwrap();
    fs::write(&registry, "malformed registry must be ignored by renewal\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["renew", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", path)
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ssh needs-renewal"));
    assert!(log.contains("ca token proxy-host"));
    assert!(log.contains("--cert-not-after 24h"));
    assert!(log.contains("ssh certificate proxy-host"));
    assert_eq!(
        fs::metadata(format!("{}-cert.pub", fixture.host_key.display()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn enroll_host_waits_for_grant_and_completes_in_one_invocation() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install-root");
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-grant",
        "host": "proxy-host",
        "ssh_public_key": VALID_SSH_KEY,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "host-token"
    });

    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    cmd.args(["enroll", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_REQUIRE_PRIOR_HOST_CERT_MODE", "1")
        .env("GRAFHOME_CA_INSTALL_ROOT", &install_root)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Created a public host enrollment request for proxy-host",
        ))
        .stderr(predicate::str::contains("Waiting for the enrollment grant"))
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"))
        .stdout(predicate::str::contains("signed"))
        .stdout(predicate::str::contains(
            "Host enrollment complete: proxy-host",
        ));

    assert!(PathBuf::from(format!("{}-cert.pub", fixture.host_key.display())).exists());
    assert_eq!(
        fs::metadata(format!("{}-cert.pub", fixture.host_key.display()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(
        install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .exists()
    );
    assert_eq!(
        fs::read_to_string(install_root.join("etc/ssh/grafhome/user_ca_keys.pem")).unwrap(),
        "ssh-ed25519 AAAAuserca grafhome-user-ca\n"
    );
    assert!(
        !install_root
            .join("etc/systemd/system/step-ca.service")
            .exists()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ca bootstrap"));
    assert!(log.contains("ssh certificate proxy-host"));
    assert!(log.contains("--token host-token"));
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("systemctl args=reload sshd.service"));
}

#[cfg(target_os = "macos")]
#[test]
fn enroll_host_waits_for_grant_and_completes_in_one_invocation_macos() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install-root");
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-grant",
        "host": "proxy-host",
        "ssh_public_key": VALID_SSH_KEY,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "host-token"
    });

    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    cmd.args(["enroll", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_REQUIRE_PRIOR_HOST_CERT_MODE", "1")
        .env("GRAFHOME_CA_INSTALL_ROOT", &install_root)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Created a public host enrollment request for proxy-host",
        ))
        .stderr(predicate::str::contains("Waiting for the enrollment grant"))
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"))
        .stdout(predicate::str::contains("signed"))
        .stdout(predicate::str::contains(
            "Host enrollment complete: proxy-host",
        ));

    assert!(PathBuf::from(format!("{}-cert.pub", fixture.host_key.display())).exists());
    assert_eq!(
        fs::metadata(format!("{}-cert.pub", fixture.host_key.display()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(
        install_root
            .join("etc/ssh/sshd_config.d/grafhome-ca.conf")
            .exists()
    );
    assert_eq!(
        fs::read_to_string(install_root.join("etc/ssh/grafhome/user_ca_keys.pem")).unwrap(),
        "ssh-ed25519 AAAAuserca grafhome-user-ca\n"
    );
    assert!(
        !install_root
            .join("etc/systemd/system/step-ca.service")
            .exists()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ca bootstrap"));
    assert!(log.contains("ssh certificate proxy-host"));
    assert!(log.contains("--token host-token"));
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("launchctl args=kickstart -k system/com.openssh.sshd"));
}

#[cfg(unix)]
#[test]
fn enroll_host_rejects_grant_for_unconfigured_ca() {
    let (dir, fixture) = exec_fixture();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "host",
            "--host",
            "proxy-host",
            "--request-only",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let pending = fixture
        .config_root
        .join("../server-step/secrets/hosts/proxy-host/pending-enrollment.json");
    let request: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(pending).unwrap()).unwrap();
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-grant",
        "host": request["host"],
        "ssh_public_key": request["ssh_public_key"],
        "renewal_public_jwk": request["renewal_public_jwk"],
        "ca_url": "https://attacker.example",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "attacker-token"
    });

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enroll", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("GRAFHOME_CA_INSTALL_ROOT", dir.path().join("install-root"))
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not match configured CA URL https://ca.example.test",
        ));

    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("ca bootstrap")
    );
}

#[cfg(unix)]
#[test]
fn enroll_user_first_run_creates_public_request_and_pending_state() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--password-file")
        .arg(&password_file)
        .arg("--request-only")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Created a public enrollment request for alice@ca-host",
        ))
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"))
        .stdout(predicate::str::contains("\"ssh_public_key\":\"ssh-ed25519"));

    let key = home.join(".ssh/id_ed25519");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    assert!(key.exists());
    assert!(material.join("provisioner.pub.json").exists());
    assert!(material.join("provisioner.priv.json").exists());
    assert!(material.join("pending-enrollment.json").exists());
    assert!(fs::read_dir(&material).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("password")
    }));
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("crypto jwk create"));
    assert!(!log.contains("user-owned-password"));
}

#[cfg(unix)]
#[test]
fn enroll_user_accepts_termux_step_cli_name() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    fs::rename(
        fixture.fake_bin.join("step"),
        fixture.fake_bin.join("step-cli"),
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--password-file")
        .arg(&password_file)
        .arg("--request-only")
        .env("HOME", &home)
        .env("PATH", &fixture.fake_bin)
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"));

    assert!(
        fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("crypto jwk create")
    );
}

#[cfg(unix)]
#[test]
fn enroll_user_restart_rebuilds_request_without_replacing_keys() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    let args = [
        "enroll",
        "user",
        "--user",
        "alice",
        "--host",
        "ca-host",
        "--request-only",
        "--config-root",
    ];

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .arg("--password-file")
        .arg(&password_file)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    let pending = material.join("pending-enrollment.json");
    let original_request = fs::read_to_string(&pending).unwrap();
    let private_key = fs::read(home.join(".ssh/id_ed25519")).unwrap();
    let private_jwk = fs::read(material.join("provisioner.priv.json")).unwrap();
    let public_jwk = fs::read(material.join("provisioner.pub.json")).unwrap();
    let original_log = fs::read(&fixture.log).unwrap();
    fs::write(&pending, "corrupt pending request\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .arg("--restart")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Restarted a public enrollment request for alice@ca-host",
        ))
        .stdout(predicate::str::contains("REQUEST:{\"version\":1"));

    assert_eq!(fs::read_to_string(pending).unwrap(), original_request);
    assert_eq!(fs::read(home.join(".ssh/id_ed25519")).unwrap(), private_key);
    assert_eq!(
        fs::read(material.join("provisioner.priv.json")).unwrap(),
        private_jwk
    );
    assert_eq!(
        fs::read(material.join("provisioner.pub.json")).unwrap(),
        public_jwk
    );
    assert_eq!(fs::read(&fixture.log).unwrap(), original_log);
}

#[cfg(unix)]
#[test]
fn enroll_user_restart_requires_existing_enrollment_material() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--restart",
            "--request-only",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot restart because"))
        .stderr(predicate::str::contains(
            "run enroll user without --restart",
        ));
}

#[cfg(unix)]
#[test]
fn enroll_user_restart_rejects_a_disabled_policy_client() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    let args = [
        "enroll",
        "user",
        "--user",
        "alice",
        "--host",
        "ca-host",
        "--request-only",
        "--config-root",
    ];
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .arg("--password-file")
        .arg(&password_file)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let pending =
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json");
    let original = fs::read(&pending).unwrap();
    let host_policy = fixture.config_root.join("policy/hosts/ca-host.toml");
    let policy = fs::read_to_string(&host_policy).unwrap().replace(
        "[user_access.alice.enrollment]\nallow_effectively_infinite_cert = true",
        "[user_access.alice.enrollment]\nallow_effectively_infinite_cert = true\nstatus = \"disabled\"",
    );
    fs::write(host_policy, policy).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(args)
        .arg(&fixture.config_root)
        .arg("--restart")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "missing active user client for user and host",
        ));

    assert_eq!(fs::read(pending).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn enroll_user_waits_for_grant_and_completes_in_one_invocation() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let root = home.join(".config/grafhome/step/certs/root_ca.crt");
    assert!(!root.exists());
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": VALID_SSH_KEY_TWO,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "user-token"
    });

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("user-owned-password\nGRANT:{grant}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Waiting for the enrollment grant"))
        .stdout(predicate::str::contains("REQUEST:"))
        .stdout(predicate::str::contains(
            "User enrollment complete: alice@ca-host",
        ));

    assert_eq!(fs::read_to_string(root).unwrap(), "root\n");
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains(
        "ca bootstrap --ca-url https://ca.example.test --fingerprint aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --force"
    ));
    assert!(log.contains("ca health --ca-url https://ca.example.test"));
}

#[cfg(target_os = "linux")]
#[test]
fn enroll_user_falls_back_to_systemd_user_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--request-only")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin("user-owned-password\n")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Stored the renewal password as an encrypted systemd user credential",
        ));

    let credential =
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/renewal-password.cred");
    assert!(credential.exists());
    let pending =
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json");
    fs::remove_file(&pending).unwrap();
    fs::remove_file(home.join(".ssh/id_ed25519")).unwrap();
    fs::remove_file(home.join(".ssh/id_ed25519.pub")).unwrap();
    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--request-only")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using the stored renewal credential for alice@ca-host",
        ));
    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["renew", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("user-owned-password")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn unavailable_secret_service_does_not_block_systemd_credentials() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let secret_tool = fixture.fake_bin.join("secret-tool");
    fs::write(&secret_tool, "not executable\n").unwrap();
    fs::set_permissions(&secret_tool, fs::Permissions::from_mode(0o644)).unwrap();

    user_enroll_request_command(&fixture, &home)
        .write_stdin("user-owned-password\n")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Stored the renewal password as an encrypted systemd user credential",
        ));

    reset_user_enrollment_request(&home);

    user_enroll_request_command(&fixture, &home)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using the stored renewal credential for alice@ca-host",
        ));
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_credential_precedes_and_recovers_through_secret_service() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    write_executable(
        &fixture.fake_bin.join("secret-tool"),
        r#"#!/bin/sh
set -eu
case "$1" in
  store) cat > "$FAKE_LOG.keyring" ;;
  lookup) cat "$FAKE_LOG.keyring" ;;
  *) exit 1 ;;
esac
"#,
    );

    user_enroll_request_command(&fixture, &home)
        .write_stdin("user-owned-password\n")
        .assert()
        .success();
    reset_user_enrollment_request(&home);
    fs::write(
        format!("{}.keyring", fixture.log.display()),
        "stale-password",
    )
    .unwrap();

    user_enroll_request_command(&fixture, &home)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using the stored renewal credential for alice@ca-host",
        ));
    reset_user_enrollment_request(&home);
    fs::write(
        format!("{}.keyring", fixture.log.display()),
        "user-owned-password",
    )
    .unwrap();

    user_enroll_request_command(&fixture, &home)
        .env("FAKE_SYSTEMD_CREDS_REJECT_DECRYPT", "1")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using the stored renewal credential for alice@ca-host",
        ));
    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("user-owned-password")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn enroll_user_falls_back_to_tpm_credential_on_pre_256_systemd() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    user_enroll_request_command(&fixture, &home)
        .env("FAKE_SYSTEMD_CREDS_REJECT_USER", "1")
        .write_stdin("user-owned-password\n")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Stored the renewal password as an encrypted TPM-bound systemd credential",
        ));

    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    let credential = material.join("renewal-password.cred");
    assert!(credential.is_file());
    assert_eq!(
        fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
        0o600
    );
    reset_user_enrollment_request(&home);

    user_enroll_request_command(&fixture, &home)
        .env("FAKE_SYSTEMD_CREDS_REJECT_USER", "1")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using the stored renewal credential for alice@ca-host",
        ));

    user_renew_command(&fixture, &home)
        .env("FAKE_SYSTEMD_CREDS_REJECT_USER", "1")
        .assert()
        .success();

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("systemd-creds args=encrypt --user"));
    assert!(log.contains("--with-key=tpm2 --tpm2-pcrs="));
    assert!(log.contains("systemd-creds args=decrypt --user"));
    assert!(!log.contains("user-owned-password"));
}

#[cfg(target_os = "linux")]
#[test]
fn upgraded_systemd_reads_an_existing_tpm_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    user_enroll_request_command(&fixture, &home)
        .env("FAKE_SYSTEMD_CREDS_REJECT_USER", "1")
        .write_stdin("user-owned-password\n")
        .assert()
        .success();

    reset_user_enrollment_request(&home);
    fs::write(&fixture.log, "").unwrap();

    user_enroll_request_command(&fixture, &home)
        .env("FAKE_SYSTEMD_CREDS_USER_DECRYPT_FAIL", "1")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using the stored renewal credential for alice@ca-host",
        ));

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("systemd-creds args=decrypt --user"));
    assert!(log.contains("systemd-creds args=decrypt --quiet"));
    assert!(!log.contains("user-owned-password"));
}

#[cfg(target_os = "linux")]
#[test]
fn enroll_user_reports_modern_and_tpm_credential_failures() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    user_enroll_request_command(&fixture, &home)
        .env("FAKE_SYSTEMD_CREDS_REJECT_USER", "1")
        .env("FAKE_SYSTEMD_CREDS_REJECT_TPM", "1")
        .write_stdin("user-owned-password\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user-scoped credential: systemd-creds: unrecognized option '--user'",
        ))
        .stderr(predicate::str::contains(
            "legacy TPM credential: Failed to create TPM2 context: Permission denied",
        ))
        .stderr(predicate::str::contains(
            "commonly by adding it to the tss group",
        ))
        .stderr(predicate::str::contains("user-owned-password").not());

    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    assert!(!material.join("renewal-password.cred").exists());
    assert!(!material.join("pending-enrollment.json").exists());
    assert_eq!(
        fs::read_dir(&material)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".renewal-password.cred-")
            })
            .count(),
        0
    );
}

#[cfg(target_os = "linux")]
#[test]
fn enroll_user_stores_an_unattended_credential_when_secret_service_succeeds() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    write_executable(
        &fixture.fake_bin.join("secret-tool"),
        "#!/bin/sh\nif [ \"$1\" = store ]; then cat >/dev/null; exit 0; fi\nexit 1\n",
    );

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--request-only",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin("user-owned-password\n")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "system keyring and as an encrypted systemd user credential",
        ));

    assert!(
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/renewal-password.cred")
            .is_file()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn enroll_and_renew_user_with_macos_keychain_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": VALID_SSH_KEY_TWO,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "user-token"
    });

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("user-owned-password\nGRANT:{grant}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Stored the renewal password in macOS Keychain",
        ));

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["renew", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["status", "--renewable"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env(
            "FAKE_PROVISIONER_LIST",
            r#"[{"name":"grafhome-user-616c696365-63612d686f7374"}]"#,
        )
        .assert()
        .success();

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("security interactive store"));
    assert!(log.contains(
        "security find args=find-generic-password -a alice@ca-host -s net.grafhome.ca.renewal -w"
    ));
    assert!(!log.contains("user-owned-password"));
    assert!(!log.contains("757365722d6f776e65642d70617373776f7264"));
}

#[cfg(target_os = "macos")]
#[test]
fn renew_user_reports_missing_macos_keychain_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["renew", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no usable renewal password found in macOS Keychain for alice@ca-host",
        ));
}

#[cfg(target_os = "linux")]
#[test]
fn renew_user_if_enrolled_reports_missing_systemd_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let root = home.join(".config/grafhome/step/certs/root_ca.crt");
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::write(root, "root\n").unwrap();
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();

    user_renew_command(&fixture, &home)
        .args(["--if-enrolled", "--quiet"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "no usable renewal password found for alice@ca-host",
        ));
}

#[cfg(target_os = "macos")]
#[test]
fn renew_user_if_enrolled_reports_missing_macos_keychain_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    prepare_macos_user_renewal(&home, &fixture, false);

    macos_user_renew_command(&fixture, &home)
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(
            "no usable renewal password found in macOS Keychain for alice@ca-host",
        ));
}

#[cfg(target_os = "macos")]
#[test]
fn renew_user_if_enrolled_reports_denied_macos_keychain_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    prepare_macos_user_renewal(&home, &fixture, true);

    macos_user_renew_command(&fixture, &home)
        .env("FAKE_KEYCHAIN_DENIED", "1")
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("User interaction is not allowed"));
}

#[cfg(target_os = "macos")]
#[test]
fn renew_user_if_enrolled_uses_valid_macos_keychain_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    prepare_macos_user_renewal(&home, &fixture, true);

    macos_user_renew_command(&fixture, &home)
        .env(
            "FAKE_PROVISIONER_LIST",
            r#"[{"name":"grafhome-user-616c696365-63612d686f7374"}]"#,
        )
        .assert()
        .success()
        .stdout("")
        .stderr("");

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        log.matches("security find args=find-generic-password")
            .count(),
        1,
        "the validated Keychain password should be reused"
    );
    assert!(log.contains("ssh certificate alice"));
}

#[cfg(target_os = "macos")]
#[test]
fn renew_user_if_enrolled_silently_skips_genuinely_unenrolled_user() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");

    macos_user_renew_command(&fixture, &home)
        .assert()
        .success()
        .stdout("")
        .stderr("");

    let log = fs::read_to_string(&fixture.log).unwrap_or_default();
    assert!(!log.contains("security find args="));
    assert!(!log.contains("ssh needs-renewal"));
}

#[cfg(unix)]
#[test]
fn enroll_user_second_run_completes_and_verifies_renewal() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--password-file")
        .arg(&password_file)
        .arg("--request-only")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let public_key = fs::read_to_string(home.join(".ssh/id_ed25519.pub")).unwrap();
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": public_key.trim(),
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "user-token"
    });
    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--password-file")
        .arg(&password_file)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "User enrollment complete: alice@ca-host",
        ));

    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    assert!(!material.join("pending-enrollment.json").exists());
    assert!(home.join(".ssh/id_ed25519").is_file());
    assert!(home.join(".ssh/id_ed25519.pub").is_file());
    assert!(home.join(".ssh/id_ed25519-cert.pub").is_file());
    assert!(!home.join(".ssh/alice.key").exists());
    assert!(!home.join(".ssh/alice.key-cert.pub").exists());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("--token user-token"));
    assert!(log.contains("--issuer grafhome-user-616c696365-63612d686f7374"));
}

#[cfg(unix)]
#[test]
fn enroll_user_verifies_renewal_without_replacing_effectively_infinite_cert() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enroll", "user", "--user", "alice", "--host", "ca-host"])
        .arg("--password-file")
        .arg(&password_file)
        .arg("--request-only")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let public_key = fs::read_to_string(home.join(".ssh/id_ed25519.pub")).unwrap();
    let grant = serde_json::json!({
        "version": 2,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": public_key.trim(),
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "effectively-infinite-token"
    });
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enroll", "user", "--user", "alice", "--host", "ca-host"])
        .arg("--password-file")
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(home.join(".ssh/id_ed25519-cert.pub")).unwrap(),
        "cert token=effectively-infinite-token\n"
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("--issuer grafhome-user-616c696365-63612d686f7374"));
    assert!(log.contains(".grafhome-ca-renewal-check-"));
}

#[cfg(unix)]
#[test]
fn failed_effectively_infinite_renewal_check_preserves_certificate_and_pending_grant() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enroll", "user", "--user", "alice", "--host", "ca-host"])
        .arg("--password-file")
        .arg(&password_file)
        .arg("--request-only")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let public_key = fs::read_to_string(home.join(".ssh/id_ed25519.pub")).unwrap();
    let grant = serde_json::json!({
        "version": 2,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": public_key.trim(),
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "effectively-infinite-token"
    });
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enroll", "user", "--user", "alice", "--host", "ca-host"])
        .arg("--password-file")
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_FAIL_TOKEN", "token-for-alice")
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .failure();

    assert_eq!(
        fs::read_to_string(home.join(".ssh/id_ed25519-cert.pub")).unwrap(),
        "cert token=effectively-infinite-token\n"
    );
    assert!(
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json")
            .is_file()
    );

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enroll", "user", "--user", "alice", "--host", "ca-host"])
        .arg("--password-file")
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(home.join(".ssh/id_ed25519-cert.pub")).unwrap(),
        "cert token=effectively-infinite-token\n"
    );
    assert!(
        !home
            .join(".config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn enroll_user_rejects_grant_for_a_different_ssh_key() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--password-file")
        .arg(&password_file)
        .arg("--request-only")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": VALID_SSH_KEY,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "user-token"
    });

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["enroll", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--password-file")
        .arg(&password_file)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "grant does not match this client host's pending request",
        ));
}

#[cfg(unix)]
#[test]
fn enroll_user_rejects_grant_for_unconfigured_ca() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--request-only")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let pending =
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json");
    let request: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(pending).unwrap()).unwrap();
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-user-enrollment-grant",
        "user": request["user"],
        "host": request["host"],
        "ssh_public_key": request["ssh_public_key"],
        "renewal_public_jwk": request["renewal_public_jwk"],
        "ca_url": "https://attacker.example",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "attacker-token"
    });

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not match configured CA URL https://ca.example.test",
        ));

    assert!(
        !fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("ca bootstrap")
    );
}

#[cfg(unix)]
#[test]
fn enroll_user_rejects_grant_for_a_substituted_renewal_jwk() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    fs::create_dir_all(&home).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--request-only")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let pending = fs::read_to_string(
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json"),
    )
    .unwrap();
    let request: serde_json::Value = serde_json::from_str(&pending).unwrap();
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": request["ssh_public_key"],
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"attacker"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "user-token"
    });

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "grant does not match this client host's pending request",
        ));
}

#[cfg(unix)]
#[test]
fn enroll_host_redacts_token_from_failed_step_error() {
    let (dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["enroll", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .arg("--request-only")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-grant",
        "host": "proxy-host",
        "ssh_public_key": VALID_SSH_KEY,
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "token": "sensitive-host-token"
    });
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    cmd.args(["enroll", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .env("GRAFHOME_CA_INSTALL_ROOT", dir.path().join("install-root"))
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_FAIL", "ssh-certificate")
        .write_stdin(format!("GRANT:{grant}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("[REDACTED]"))
        .stderr(predicate::str::contains("sensitive-host-token").not());
}

#[cfg(unix)]
#[test]
fn approve_user_authorizes_effectively_infinite_enrollment_and_finite_renewal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        serde_json::to_vec_pretty(&serde_json::json!({
            "authority": {
                "provisioners": [
                    {
                        "type": "JWK",
                        "name": "grafhome-user-enrollment",
                        "key": {"kid": "enrollment-kid", "kty": "EC"},
                        "encryptedKey": "preserve-enrollment-secret",
                        "claims": {
                            "defaultUserSSHCertDuration": "12h",
                            "maxUserSSHCertDuration": "168h",
                            "disableRenewal": true
                        }
                    },
                    {
                        "type": "JWK",
                        "name": "grafhome-user-616c696365-63612d686f7374",
                        "key": {
                            "kid": "client-kid",
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "client-x",
                            "y": "client-y"
                        },
                        "claims": {
                            "defaultUserSSHCertDuration": "12h",
                            "maxUserSSHCertDuration": "168h",
                            "enableSSHCA": true,
                            "disableRenewal": true
                        },
                        "options": {
                            "x509": {"template": "stale-x509"},
                            "ssh": {"template": "stale-ssh"}
                        }
                    }
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    seed_user_registry_record(
        &fixture,
        "alice",
        "ca-host",
        VALID_SSH_KEY_TWO,
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "client-x", "y": "client-y"
        }),
    );
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["approve", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--effectively-infinite")
        .arg("--yes")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(user_enrollment_request())
        .assert()
        .success()
        .stderr(predicate::str::contains("Approved alice@ca-host"))
        .stdout(predicate::str::contains("GRANT:{\"version\":2"))
        .stdout(predicate::str::contains("\"token\":\"token-for-alice\""));

    let ca_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    let provisioners = ca_config["authority"]["provisioners"].as_array().unwrap();
    let enrollment = provisioners
        .iter()
        .find(|item| item["name"] == "grafhome-user-enrollment")
        .unwrap();
    assert_eq!(enrollment["key"]["kid"], "enrollment-kid");
    assert_eq!(enrollment["encryptedKey"], "preserve-enrollment-secret");
    assert_eq!(enrollment["claims"]["defaultUserSSHCertDuration"], "24h");
    assert_eq!(enrollment["claims"]["maxUserSSHCertDuration"], "2562047h");
    assert_eq!(enrollment["claims"]["disableRenewal"], true);
    let provisioner = provisioners
        .iter()
        .find(|item| item["name"] == "grafhome-user-616c696365-63612d686f7374")
        .unwrap();
    assert_eq!(
        provisioner["name"],
        "grafhome-user-616c696365-63612d686f7374"
    );
    assert_eq!(provisioner["claims"]["defaultUserSSHCertDuration"], "24h");
    assert_eq!(provisioner["claims"]["maxUserSSHCertDuration"], "48h");
    assert!(
        provisioner["claims"]
            .as_object()
            .unwrap()
            .get("disableRenewal")
            .is_none()
    );
    assert!(
        provisioner["options"]["ssh"]["template"]
            .as_str()
            .unwrap()
            .contains(r#""principals": ["alice"]"#)
    );
    let key_blob = VALID_SSH_KEY_TWO.split_whitespace().nth(1).unwrap();
    assert!(
        provisioner["options"]["ssh"]["template"]
            .as_str()
            .unwrap()
            .contains(&format!("grafhome-ca-ssh-key:{key_blob}"))
    );
    assert!(
        enrollment["options"]["ssh"]["template"]
            .as_str()
            .unwrap()
            .contains("grafhomeSSHPublicKey")
    );
    assert!(
        ca_json
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("templates/ssh/grafhome-user-616c696365-63612d686f7374.tpl")
            .exists()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("chown args=step-ca:step-ca"));
    assert!(log.contains("chmod args=0640"));
    assert!(log.contains("systemctl args=restart step-ca.service"));
    assert!(log.contains("systemctl args=is-active step-ca.service"));
    assert!(log.contains("ca health"));
    assert!(log.contains("--cert-not-after 2562047h"));
    assert!(log.contains(&format!("--set grafhomeSSHPublicKey={key_blob}")));
    let enrollment_keys = fixture
        .config_root
        .parent()
        .unwrap()
        .join("state/secrets/provisioners");
    assert!(log.contains(&format!(
        "--key {}",
        enrollment_keys
            .join("grafhome-user-enrollment.priv.json")
            .display()
    )));
    assert!(log.contains(&format!(
        "--password-file {}",
        enrollment_keys
            .join("grafhome-user-enrollment.password")
            .display()
    )));
    assert!(!log.contains("--provisioner-password-file"));
}

#[cfg(unix)]
#[test]
fn approve_user_rejects_effectively_infinite_cert_for_unallowlisted_client() {
    let (_dir, fixture) = exec_fixture();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "user", "--effectively-infinite", "--yes"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(user_enrollment_request_for("proxy-host"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "effectively-infinite certificate approval is not allowed",
        ));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approve_user_rejects_finite_cert_above_renewal_maximum() {
    let (_dir, fixture) = exec_fixture();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "user", "--cert-ttl", "49h", "--yes"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(user_enrollment_request())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "must not exceed renewal_max_ttl (48h) without --effectively-infinite",
        ));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn approve_user_rejects_existing_provisioner_with_different_key_before_restart() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    let original = serde_json::to_vec_pretty(&serde_json::json!({
        "authority": {
            "provisioners": [
                {
                    "type": "JWK",
                    "name": "grafhome-user-enrollment",
                    "key": {"kid": "enrollment-kid", "kty": "EC"},
                    "encryptedKey": "encrypted-enrollment",
                    "claims": {
                        "defaultUserSSHCertDuration": "24h",
                        "maxUserSSHCertDuration": "2562047h",
                        "enableSSHCA": true
                    }
                },
                {
                    "type": "JWK",
                    "name": "grafhome-user-616c696365-63612d686f7374",
                    "key": {
                        "kid": "different-client",
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "different-x",
                        "y": "different-y"
                    }
                }
            ]
        }
    }))
    .unwrap();
    fs::write(&ca_json, &original).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["approve", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--yes")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(user_enrollment_request())
        .assert()
        .failure()
        .stderr(predicate::str::contains("different public key"));

    assert_eq!(fs::read(&ca_json).unwrap(), original);
    let log = fs::read_to_string(&fixture.log).unwrap_or_default();
    assert!(!log.contains("systemctl args=restart step-ca.service"));
    assert!(!log.contains("ca health"));
    assert!(!log.contains("ca token"));
}

#[cfg(unix)]
#[test]
fn approve_user_retries_transient_health_failure_after_restart() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, USER_ENROLLMENT_CA_JSON).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["approve", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--yes")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_HEALTH_FAIL_ONCE", "1")
        .write_stdin(user_enrollment_request())
        .assert()
        .success()
        .stdout(predicate::str::contains("GRANT:{\"version\":1"))
        .stderr(predicate::str::contains("failed decoding CA error response").not());

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(log.matches("ca health").count(), 3);
    let ca_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    assert!(
        ca_config["authority"]["provisioners"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == "grafhome-user-616c696365-63612d686f7374")
    );
}

#[cfg(unix)]
#[test]
fn concurrent_approvals_preserve_both_renewal_provisioners() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, USER_ENROLLMENT_CA_JSON).unwrap();
    let path = prepend_path(&fixture.fake_bin);
    let requests = ["ca-host", "proxy-host"]
        .into_iter()
        .zip([VALID_SSH_KEY, VALID_SSH_KEY_TWO])
        .map(|(host, ssh_public_key)| {
            format!(
                "REQUEST:{}\n",
                serde_json::json!({
                    "version": 1,
                    "kind": "grafhome-user-enrollment-request",
                    "user": "alice",
                    "host": host,
                    "ssh_public_key": ssh_public_key,
                    "renewal_public_jwk": {
                        "kid": format!("{host}-kid"),
                        "kty": "EC",
                        "crv": "P-256",
                        "x": format!("{host}-x"),
                        "y": format!("{host}-y")
                    }
                })
            )
        });
    let handles = requests.map(|request| {
        let config_root = fixture.config_root.clone();
        let log = fixture.log.clone();
        let path = path.clone();
        std::thread::spawn(move || {
            Command::cargo_bin("grafhome-ca")
                .unwrap()
                .args(["approve", "user", "--yes", "--config-root"])
                .arg(config_root)
                .env("PATH", path)
                .env("FAKE_LOG", log)
                .env("FAKE_SYSTEMCTL_RESTART_DELAY", "1")
                .write_stdin(request)
                .output()
                .unwrap()
        })
    });
    for handle in handles {
        let output = handle.join().unwrap();
        assert!(
            output.status.success(),
            "approval failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let text = fs::read_to_string(ca_json).unwrap();
    assert!(text.contains("grafhome-user-616c696365-63612d686f7374"));
    assert!(text.contains("grafhome-user-616c696365-70726f78792d686f7374"));
}

#[cfg(unix)]
#[test]
fn approve_user_rolls_back_ca_json_if_restart_fails() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    let original = USER_ENROLLMENT_CA_JSON;
    fs::write(&ca_json, original).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["approve", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--yes")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_SYSTEMCTL_RESTART_FAIL_ONCE", "1")
        .write_stdin(user_enrollment_request())
        .assert()
        .failure()
        .stderr(predicate::str::contains("restored previous ca.json"));

    assert_eq!(fs::read_to_string(&ca_json).unwrap(), original);
    assert!(
        !fixture
            .config_root
            .join("../state/step/templates/ssh/grafhome-user-616c696365-63612d686f7374.tpl")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn renew_user_reads_password_from_stdin_and_refreshes_cert() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/id_ed25519.pub"), "public\n").unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();
    let password_file = dir.path().join("password");
    fs::write(&password_file, "user-owned-password\n").unwrap();
    let registry = enrollment_registry_path(&fixture);
    fs::create_dir_all(registry.parent().unwrap()).unwrap();
    fs::write(&registry, "malformed registry must be ignored by renewal\n").unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["renew", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .arg("--password-file")
        .arg(&password_file)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed"))
        .stdout(predicate::str::contains("inspect"));

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("--issuer grafhome-user-616c696365-63612d686f7374"));
    assert!(log.contains("ssh certificate alice"));
    assert!(!log.contains("user-owned-password"));
}

#[cfg(unix)]
#[test]
fn quiet_renew_user_suppresses_successful_renewal_output() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/id_ed25519.pub"), "public\n").unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();
    let password_file = dir.path().join("password");
    fs::write(&password_file, "user-owned-password\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--quiet",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout("")
        .stderr("");

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ssh certificate alice"));
    assert!(log.contains("ssh-keygen args=-L"));
}

#[cfg(unix)]
#[test]
fn renew_user_if_reachable_silently_skips_offline_ca() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    configure_unreachable_ca(&fixture);

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--if-reachable",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout("")
        .stderr("");

    let log = fs::read_to_string(&fixture.log).unwrap_or_default();
    assert!(!log.contains("needs-renewal"));
    assert!(!log.contains("ca token"));
}

#[cfg(unix)]
#[test]
fn quiet_renew_user_reports_redacted_renewal_failures() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/id_ed25519.pub"), "public\n").unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();
    let password_file = dir.path().join("password");
    fs::write(&password_file, "user-owned-password\n").unwrap();

    let output = Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--quiet",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_FAIL", "ssh-certificate")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("simulated failure"));
    assert!(!stderr.contains("token-for-alice"));
}

#[cfg(unix)]
#[test]
fn renew_user_skips_fresh_certificate_without_loading_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/id_ed25519-cert.pub"), "cert\n").unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_CERT_FRESH", "1")
        .assert()
        .success();

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ssh needs-renewal"));
    assert!(!log.contains("ca token"));
}

#[cfg(unix)]
#[test]
fn revoke_host_removes_only_the_renewal_provisioner() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-host-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"proxy-host-host-x","y":"host-y"}},{"name":"grafhome-user-616c696365-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"proxy-host-user-x","y":"user-y"}},{"name":"grafhome-user-616c696365-63612d686f7374"},{"type":"SSHPOP","name":"grafhome-host-renew"},{"name":"keep-me"}]}}"#,
    )
    .unwrap();
    seed_host_and_user_registry(&fixture, "proxy-host", "alice");

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["revoke", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "future issuance and renewal are disabled",
        ))
        .stdout(predicate::str::contains(
            "recorded 2 SSH keys for active revocation",
        ));

    let text = fs::read_to_string(ca_json).unwrap();
    assert!(!text.contains("grafhome-host-70726f78792d686f7374"));
    assert!(!text.contains("grafhome-user-616c696365-70726f78792d686f7374"));
    assert!(text.contains("grafhome-user-616c696365-63612d686f7374"));
    assert!(!text.contains("SSHPOP"));
    assert!(text.contains("keep-me"));
}

#[cfg(unix)]
#[test]
fn status_reports_host_and_user_clients_from_live_ca_state() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let root = home.join(".config/grafhome/step/certs/root_ca.crt");
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::write(root, "root\n").unwrap();
    let provisioners = r#"[{"name":"grafhome-host-70726f78792d686f7374","type":"JWK"},{"name":"grafhome-user-616c696365-70726f78792d686f7374","future":{"enabled":true}}]"#;

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["status", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("USER", "root")
        .env("PATH", "/usr/bin:/bin")
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("host proxy-host: enrolled; users: alice\n");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["status", "--user", "alice", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("user alice: enrolled on proxy-host\n");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["status", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("USER", "alice")
        .env("HOSTNAME", "proxy-host.example.test")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("user alice on proxy-host: enrolled\n");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["status", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("USER", "root")
        .env("HOSTNAME", "proxy-host.example.test")
        .env("PATH", "/usr/bin:/bin")
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("host proxy-host: enrolled; users: alice\n");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("user alice on ca-host: not enrolled\n");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "proxy-host",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("");
    let renewal_dir = home.join(".config/grafhome-ca/users/alice/hosts/proxy-host");
    fs::create_dir_all(&renewal_dir).unwrap();
    fs::write(renewal_dir.join("provisioner.priv.json"), "private\n").unwrap();
    #[cfg(target_os = "linux")]
    fs::write(renewal_dir.join("renewal-password.cred"), "credential\n").unwrap();
    #[cfg(target_os = "macos")]
    fs::write(
        format!("{}.keychain", fixture.log.display()),
        "credential\n",
    )
    .unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "proxy-host",
            "--quiet",
            "--renewable",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .failure()
        .stdout("")
        .stderr("");
}

#[cfg(unix)]
#[test]
fn renew_user_if_enrolled_rejects_malformed_provisioner_entries() {
    for (description, response, diagnostic) in [
        ("non-array response", r#"{}"#, "invalid type: map"),
        ("non-object entry", r#"[null]"#, "invalid type: null"),
        ("missing name", r#"[{}]"#, "missing field `name`"),
        (
            "non-string name",
            r#"[{"name":7}]"#,
            "invalid type: integer",
        ),
        (
            "empty name",
            r#"[{"name":""}]"#,
            "provisioner entry 0 has an empty name",
        ),
        (
            "blank name",
            r#"[{"name":" "}]"#,
            "provisioner entry 0 has an empty name",
        ),
    ] {
        let (dir, fixture) = exec_fixture();
        let home = dir.path().join("home");
        let root = home.join(".config/grafhome/step/certs/root_ca.crt");
        fs::create_dir_all(root.parent().unwrap()).unwrap();
        fs::write(root, "root\n").unwrap();
        let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
        fs::create_dir_all(&material).unwrap();
        fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();
        let password_file = dir.path().join("password");
        fs::write(&password_file, "renewal-password\n").unwrap();

        let output = Command::cargo_bin("grafhome-ca")
            .expect("binary exists")
            .args([
                "renew",
                "user",
                "--user",
                "alice",
                "--host",
                "ca-host",
                "--if-enrolled",
                "--quiet",
                "--password-file",
            ])
            .arg(&password_file)
            .arg("--config-root")
            .arg(&fixture.config_root)
            .env("HOME", &home)
            .env("PATH", prepend_path(&fixture.fake_bin))
            .env("FAKE_LOG", &fixture.log)
            .env("FAKE_PROVISIONER_LIST", response)
            .output()
            .unwrap();

        assert!(
            !output.status.success(),
            "{description} must not be treated as an empty provisioner list"
        );
        assert!(output.stdout.is_empty(), "{description} must stay quiet");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("step ca provisioner list") && stderr.contains(diagnostic),
            "{description} should identify the malformed response: {}",
            stderr
        );
        let log = fs::read_to_string(&fixture.log).unwrap();
        assert!(log.contains("ca provisioner list"));
        assert!(!log.contains("ssh needs-renewal"));
    }
}

#[cfg(unix)]
#[test]
fn policy_identity_environment_overrides_os_inference_but_not_cli_flags() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let root = home.join(".config/grafhome/step/certs/root_ca.crt");
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::write(root, "root\n").unwrap();
    let provisioners = r#"[{"name":"grafhome-host-70726f78792d686f7374"},{"name":"grafhome-user-616c696365-70726f78792d686f7374"}]"#;

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["status", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("USER", "u0_a123")
        .env("HOSTNAME", "localhost")
        .env("GRAFHOME_CA_LOCAL_USER", "alice")
        .env("GRAFHOME_CA_LOCAL_HOST", "proxy-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("user alice on proxy-host: enrolled\n");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "proxy-host",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("USER", "u0_a123")
        .env("HOSTNAME", "localhost")
        .env("GRAFHOME_CA_LOCAL_USER", "wrong-user")
        .env("GRAFHOME_CA_LOCAL_HOST", "wrong-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", provisioners)
        .assert()
        .success()
        .stdout("user alice on proxy-host: enrolled\n");
}

#[cfg(unix)]
#[test]
fn quiet_status_treats_a_missing_local_trust_root_as_not_enrolled() {
    let (dir, fixture) = exec_fixture();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--quiet",
            "--renewable",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", dir.path().join("never-enrolled-home"))
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stdout("")
        .stderr("");
    assert!(
        !fixture.log.exists()
            || !fs::read_to_string(&fixture.log)
                .unwrap()
                .contains("ca provisioner list")
    );
}

#[cfg(unix)]
#[test]
fn host_status_uses_user_step_with_a_user_owned_trust_root() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let user_root = home.join(".config/grafhome/step/certs/root_ca.crt");
    fs::create_dir_all(user_root.parent().unwrap()).unwrap();
    fs::write(user_root, "root\n").unwrap();
    let deployment_path = fixture.config_root.join("config/deployment.env");
    let deployment = fs::read_to_string(&deployment_path).unwrap().replace(
        &format!(
            "GRAFHOME_CA_ROOT_STEP_BIN={}",
            fixture.fake_bin.join("step").display()
        ),
        "GRAFHOME_CA_ROOT_STEP_BIN=/root/inaccessible-step",
    );
    fs::write(deployment_path, deployment).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["status", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("USER", "alice")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env(
            "FAKE_PROVISIONER_LIST",
            r#"[{"name":"grafhome-host-70726f78792d686f7374"}]"#,
        )
        .assert()
        .success()
        .stdout("host proxy-host: enrolled; users: none\n");
}

#[cfg(unix)]
#[test]
fn revoke_host_discovers_live_enrollment_after_policy_removal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-host-6465706172746564","key":{"kty":"EC","crv":"P-256","x":"departed-host-x","y":"host-y"}},{"name":"grafhome-user-616c696365-6465706172746564","key":{"kty":"EC","crv":"P-256","x":"departed-user-x","y":"user-y"}},{"name":"keep-me"}]}}"#,
    )
    .unwrap();
    seed_host_and_user_registry(&fixture, "departed", "alice");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "departed", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let text = fs::read_to_string(ca_json).unwrap();
    assert!(!text.contains("grafhome-host-6465706172746564"));
    assert!(!text.contains("grafhome-user-616c696365-6465706172746564"));
    assert!(text.contains("keep-me"));

    let stale_template = fixture
        .config_root
        .join("../state/step/templates/ssh/grafhome-host-6465706172746564.tpl");
    fs::create_dir_all(stale_template.parent().unwrap()).unwrap();
    fs::write(&stale_template, "stale\n").unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "departed", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    assert!(!stale_template.exists());
}

#[cfg(unix)]
#[test]
fn revoke_user_discovers_every_live_client_after_policy_removal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-user-6465706172746564-63612d686f7374","key":{"kty":"EC","crv":"P-256","x":"first-user-x","y":"user-y"}},{"name":"grafhome-user-6465706172746564-70726f78792d686f7374","key":{"kty":"EC","crv":"P-256","x":"second-user-x","y":"user-y"}},{"name":"keep-me"}]}}"#,
    )
    .unwrap();
    seed_two_user_clients_registry(&fixture, "departed", "ca-host", "proxy-host");

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .args(["revoke", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("departed")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();

    let text = fs::read_to_string(ca_json).unwrap();
    assert!(!text.contains("grafhome-user-6465706172746564-63612d686f7374"));
    assert!(!text.contains("grafhome-user-6465706172746564-70726f78792d686f7374"));
    assert!(text.contains("keep-me"));
}

#[cfg(unix)]
#[test]
fn fresh_user_enrollment_then_revocation_disables_device_bound_renewal() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    fs::write(&ca_json, USER_ENROLLMENT_CA_JSON).unwrap();
    assert!(!home.join(".config/grafhome-ca").exists());
    assert!(
        !fixture
            .config_root
            .join("../state/step/templates/ssh/grafhome-user-616c696365-63612d686f7374.tpl")
            .exists()
    );

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--request-only",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let pending =
        home.join(".config/grafhome-ca/users/alice/hosts/ca-host/pending-enrollment.json");
    let request = fs::read_to_string(&pending).unwrap();
    let approval = Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "user", "--yes", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_REQUIRE_RESTART_BEFORE_TOKEN", "1")
        .write_stdin(request)
        .output()
        .unwrap();
    assert!(approval.status.success());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(
        log.find("systemctl args=restart step-ca.service").unwrap()
            < log.find("args=ca token").unwrap()
    );
    let grant = prefixed_document(&approval.stdout, "GRANT:");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_ENFORCE_ISSUER", "1")
        .env("FAKE_CA_JSON", &ca_json)
        .write_stdin(grant)
        .assert()
        .success();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env(
            "FAKE_PROVISIONER_LIST",
            r#"[{"name":"grafhome-user-616c696365-63612d686f7374"}]"#,
        )
        .assert()
        .success()
        .stdout("");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--if-enrolled",
            "--quiet",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_ENFORCE_ISSUER", "1")
        .env("FAKE_CA_JSON", &ca_json)
        .env(
            "FAKE_PROVISIONER_LIST",
            r#"[{"name":"grafhome-user-616c696365-63612d686f7374"}]"#,
        )
        .assert()
        .success()
        .stdout("")
        .stderr("");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "revoke",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", "[]")
        .assert()
        .failure()
        .stdout("")
        .stderr("");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--if-enrolled",
            "--quiet",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", "[]")
        .assert()
        .success()
        .stdout("")
        .stderr("");
    assert!(
        !fixture
            .config_root
            .join("../state/step/templates/ssh/grafhome-user-616c696365-63612d686f7374.tpl")
            .exists()
    );
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "user",
            "--user",
            "alice",
            "--host",
            "ca-host",
            "--password-file",
        ])
        .arg(&password_file)
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_ENFORCE_ISSUER", "1")
        .env("FAKE_CA_JSON", &ca_json)
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown issuer"));
}

#[cfg(unix)]
#[test]
fn fresh_host_enrollment_then_revocation_disables_device_bound_renewal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, HOST_BOOTSTRAP_CA_JSON).unwrap();
    assert!(
        !fixture
            .config_root
            .join("../server-step/secrets/hosts/proxy-host")
            .exists()
    );
    assert!(
        !fixture
            .config_root
            .join("../state/step/templates/ssh/grafhome-host-70726f78792d686f7374.tpl")
            .exists()
    );

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enroll",
            "host",
            "--host",
            "proxy-host",
            "--request-only",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    let pending = fixture
        .config_root
        .join("../server-step/secrets/hosts/proxy-host/pending-enrollment.json");
    let request = fs::read_to_string(pending).unwrap();
    let approval = Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["approve", "host", "--yes", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_REQUIRE_RESTART_BEFORE_TOKEN", "1")
        .write_stdin(request)
        .output()
        .unwrap();
    assert!(approval.status.success());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(
        log.find("systemctl args=restart step-ca.service").unwrap()
            < log.find("args=ca token").unwrap()
    );
    let grant = prefixed_document(&approval.stdout, "GRANT:");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enroll", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_ENFORCE_ISSUER", "1")
        .env("FAKE_CA_JSON", &ca_json)
        .env(
            "GRAFHOME_CA_INSTALL_ROOT",
            fixture.config_root.join("../install"),
        )
        .write_stdin(grant)
        .assert()
        .success();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--host",
            "proxy-host",
            "--quiet",
            "--renewable",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env(
            "FAKE_PROVISIONER_LIST",
            r#"[{"name":"grafhome-host-70726f78792d686f7374"}]"#,
        )
        .assert()
        .success()
        .stdout("");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "host",
            "--host",
            "proxy-host",
            "--if-enrolled",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_ENFORCE_ISSUER", "1")
        .env("FAKE_CA_JSON", &ca_json)
        .env(
            "FAKE_PROVISIONER_LIST",
            r#"[{"name":"grafhome-host-70726f78792d686f7374"}]"#,
        )
        .assert()
        .success()
        .stdout("")
        .stderr("");

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "status",
            "--host",
            "proxy-host",
            "--quiet",
            "--renewable",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", "[]")
        .assert()
        .failure()
        .stdout("")
        .stderr("");
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "renew",
            "host",
            "--host",
            "proxy-host",
            "--if-enrolled",
            "--quiet",
            "--config-root",
        ])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_PROVISIONER_LIST", "[]")
        .assert()
        .success()
        .stdout("")
        .stderr("");
    assert!(
        !fixture
            .config_root
            .join("../state/step/templates/ssh/grafhome-host-70726f78792d686f7374.tpl")
            .exists()
    );
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["renew", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_ENFORCE_ISSUER", "1")
        .env("FAKE_CA_JSON", &ca_json)
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown issuer"));
}

#[cfg(unix)]
#[test]
fn reused_host_name_can_complete_two_distinct_enrollment_generations() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, HOST_BOOTSTRAP_CA_JSON).unwrap();

    for (ssh_key, generation) in [(VALID_SSH_KEY, "first"), (VALID_SSH_KEY_TWO, "second")] {
        let request = serde_json::json!({
            "version": 1,
            "kind": "grafhome-host-enrollment-request",
            "host": "proxy-host",
            "ssh_public_key": ssh_key,
            "renewal_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": format!("{generation}-x"),
                "y": format!("{generation}-y")
            }
        });
        Command::cargo_bin("grafhome-ca")
            .unwrap()
            .args(["approve", "host", "--yes", "--config-root"])
            .arg(&fixture.config_root)
            .env("PATH", prepend_path(&fixture.fake_bin))
            .env("FAKE_LOG", &fixture.log)
            .write_stdin(format!("REQUEST:{request}\n"))
            .assert()
            .success();
        Command::cargo_bin("grafhome-ca")
            .unwrap()
            .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
            .arg(&fixture.config_root)
            .env("PATH", prepend_path(&fixture.fake_bin))
            .env("FAKE_LOG", &fixture.log)
            .assert()
            .success();
    }

    let policy = fs::read_to_string(fixture.config_root.join("policy/revocations.toml")).unwrap();
    assert_eq!(policy.matches("[[ssh_keys]]").count(), 2);
    assert_eq!(policy.matches("renewal_fingerprint = ").count(), 2);
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(enrollment_registry_path(&fixture)).unwrap()).unwrap();
    assert_eq!(registry["records"].as_array().unwrap().len(), 2);
    assert!(
        registry["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["status"] == "revoked")
    );
}

#[cfg(unix)]
fn prefixed_document(output: &[u8], prefix: &str) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing {prefix} document"))
        .to_owned()
}

#[cfg(unix)]
fn user_enrollment_request() -> String {
    user_enrollment_request_for("ca-host")
}

#[cfg(unix)]
fn user_enrollment_request_for(host: &str) -> String {
    format!(
        "REQUEST:{}\n",
        serde_json::json!({
            "version": 1,
            "kind": "grafhome-user-enrollment-request",
            "user": "alice",
            "host": host,
            "ssh_public_key": format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/YQ6c6N8hXDSaeqEQ1UvUgrymxo5vYQNy/1KO4HPpw alice@{host}"),
            "renewal_public_jwk": {
                "kid": "client-kid",
                "kty": "EC",
                "crv": "P-256",
                "x": "client-x",
                "y": "client-y"
            }
        })
    )
}
