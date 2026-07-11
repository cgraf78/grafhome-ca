use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn example_config_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/site-config")
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
struct ExecFixture {
    config_root: PathBuf,
    fake_bin: PathBuf,
    log: PathBuf,
    host_key: PathBuf,
}

#[cfg(unix)]
fn exec_fixture() -> (tempfile::TempDir, ExecFixture) {
    let dir = tempdir().unwrap();
    let config_root = dir.path().join("grafhome-ca");
    let fake_bin = dir.path().join("bin");
    let state = dir.path().join("state");
    let server_step = dir.path().join("server-step");
    let host_key = dir.path().join("ssh_host_ed25519_key");
    let password = state.join("secrets/intermediate_ca_password");
    let log = dir.path().join("calls.log");

    copy_dir(&example_config_root(), &config_root);
    fs::create_dir_all(&fake_bin).unwrap();
    fs::create_dir_all(state.join("step/certs")).unwrap();
    fs::create_dir_all(password.parent().unwrap()).unwrap();
    fs::write(state.join("step/certs/root_ca.crt"), "root\n").unwrap();
    fs::write(&password, "ca-password\n").unwrap();
    fs::write(&host_key, "host-private\n").unwrap();
    fs::write(
        format!("{}.pub", host_key.display()),
        "ssh-ed25519 AAAAhostpublic fixture\n",
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
    printf 'fingerprint-from-fake-step\n'
    ;;
  "ca token")
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
      printf 'simulated health failure\n' >&2
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
    if [ "${FAKE_STEP_FAIL:-}" = "ssh-certificate" ]; then
      printf 'simulated failure token=%s\n' "$8" >&2
      exit 42
    fi
    pub="$4"
    cert="${pub%.pub}-cert.pub"
    printf 'cert\n' > "$cert"
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
  "crypto jwe")
    cat >/dev/null
    printf '{"kty":"OKP","d":"private"}\n'
    ;;
esac
"#,
    );
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
  printf 'ssh-ed25519 AAAApublic test@fixture\n' > "$out.pub"
elif [ "$1" = "-L" ]; then
  test -s "$3"
  printf 'inspect %s\n' "$3"
fi
"#,
    );
    write_executable(
        &fake_bin.join("sshd"),
        r#"#!/bin/sh
set -eu
printf 'sshd args=%s\n' "$*" >> "$FAKE_LOG"
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
if [ "$1" = "is-active" ]; then printf 'active\n'; fi
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
case "$1" in
  encrypt)
    for output in "$@"; do :; done
    cat > "$output"
    ;;
  decrypt)
    for input in "$@"; do
      if [ -f "$input" ]; then cat "$input"; exit 0; fi
    done
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
fn help_exposes_only_supported_enrollment_operations() {
    let output = Command::cargo_bin("grafhome-ca")
        .unwrap()
        .arg("help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();

    for command in ["approve", "enroll", "renew", "revoke", "enrollment-status"] {
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
}

#[test]
fn check_rejects_legacy_sshpop_policy() {
    let dir = tempdir().unwrap();
    let config_root = dir.path().join("grafhome-ca");
    copy_dir(&example_config_root(), &config_root);
    let provisioners = config_root.join("policy/provisioners.tsv");
    let mut text = fs::read_to_string(&provisioners).unwrap();
    text.push_str(
        "host_renew\tgrafhome-host-renew\tSSHPOP\t168h\t720h\t8h-jitter\tactive\tlegacy\n",
    );
    fs::write(provisioners, text).unwrap();

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .arg("check")
        .arg("--config-root")
        .arg(config_root)
        .assert()
        .failure()
        .stderr(predicate::str::contains("host_renew"));
}

#[test]
fn render_dry_run_lists_staged_files() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("render")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--out-dir")
        .arg("/tmp/not-used-by-dry-run")
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
fn export_public_dry_run_lists_bundle_without_live_ca_state() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("export-public")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--out-dir")
        .arg("/tmp/not-used-by-dry-run")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("root_fingerprint"))
        .stdout(predicate::str::contains("ssh_known_hosts"))
        .stdout(predicate::str::contains("manifest.json"));
}

#[cfg(unix)]
#[test]
fn export_public_writes_trust_bundle_and_manifest() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
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
    cmd.arg("export-public")
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
fn materialize_runtime_provisioners_writes_placeholder_free_ca_json() {
    let dir = tempdir().unwrap();
    let staging = dir.path().join("staging");
    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .arg("render")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--out-dir")
        .arg(&staging)
        .assert()
        .success();
    let staged_ca_json = staging.join("hosts/ca-host/srv/example-ca/step/config/ca.json");
    let live_ca_json = dir.path().join("live-ca.json");
    fs::write(
        &live_ca_json,
        r#"{
          "authority": {
            "provisioners": [
              {
                "type": "JWK",
                "name": "grafhome-host-bootstrap",
                "key": {"kid": "bootstrap-kid"},
                "encryptedKey": "encrypted-bootstrap",
                "claims": {"enableSSHCA": true}
              }
            ]
          }
        }"#,
    )
    .unwrap();
    let jwk_dir = dir.path().join("provisioners");
    fs::create_dir(&jwk_dir).unwrap();
    fs::write(
        jwk_dir.join("grafhome-user-enrollment.pub.json"),
        r#"{"kid":"user-enrollment-kid","kty":"EC"}"#,
    )
    .unwrap();
    fs::write(
        jwk_dir.join("grafhome-user-enrollment.priv.json"),
        "{\n  \"protected\": \"encrypted-user-enrollment\"\n}\n",
    )
    .unwrap();
    let out_file = dir.path().join("materialized-ca.json");

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .arg("materialize-runtime-provisioners")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--live-ca-json")
        .arg(&live_ca_json)
        .arg("--staged-ca-json")
        .arg(&staged_ca_json)
        .arg("--jwk-dir")
        .arg(&jwk_dir)
        .arg("--out-file")
        .arg(&out_file)
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
    assert!(provisioners.iter().any(|item| {
        item["name"] == "grafhome-host-bootstrap"
            && item["encryptedKey"] == "encrypted-bootstrap"
            && item["claims"]["defaultHostSSHCertDuration"] == "168h"
    }));
    assert!(provisioners.iter().any(|item| {
        item["name"] == "grafhome-user-enrollment"
            && item["key"]["kid"] == "user-enrollment-kid"
            && item["claims"]["defaultUserSSHCertDuration"] == "24h"
    }));
    assert!(!provisioners.iter().any(|item| item["type"] == "SSHPOP"));
}

#[test]
fn every_plan_json_command_matches_plan_schema() {
    let cases: &[&[&str]] = &[
        &["init-ca"],
        &["backup-ca"],
        &["verify-live", "--host", "ca-host"],
        &["proxy-cert"],
        &["add-host", "--host", "new-host"],
        &["add-user", "--user", "new-user"],
    ];
    let schema =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/lifecycle/plan.schema.json");

    for args in cases {
        let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
        let output = cmd
            .arg("plan")
            .arg("--config-root")
            .arg(example_config_root())
            .arg("--json")
            .args(*args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();

        grafhome_ca::schema::validate(&schema, &value).expect("CLI plan output matches schema");
    }
}

#[test]
fn plan_help_exposes_only_supported_operations() {
    let output = Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["plan", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for supported in [
        "init-ca",
        "backup-ca",
        "verify-live",
        "proxy-cert",
        "add-host",
        "add-user",
    ] {
        assert!(
            text.contains(supported),
            "missing supported plan {supported}"
        );
    }
    for obsolete in [
        "host-bootstrap",
        "host-renew",
        "host-renew-all",
        "renew",
        "user",
    ] {
        let listed = text
            .lines()
            .map(str::trim_start)
            .any(|line| line == obsolete || line.starts_with(&format!("{obsolete} ")));
        assert!(!listed, "found obsolete plan {obsolete}");
    }
}

#[test]
fn plan_rollout_hardening_commands_are_visible() {
    let mut backup = Command::cargo_bin("grafhome-ca").expect("binary exists");
    backup
        .arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("backup-ca")
        .assert()
        .success()
        .stdout(predicate::str::contains("restore-test"))
        .stdout(predicate::str::contains("intermediate_ca_key"))
        .stdout(predicate::str::contains("backup_file='<backup-file>'"))
        .stdout(predicate::str::contains("dirname \"$backup_file\""));

    let mut verify = Command::cargo_bin("grafhome-ca").expect("binary exists");
    verify
        .arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("verify-live")
        .arg("--host")
        .arg("proxy-host")
        .assert()
        .success()
        .stdout(predicate::str::contains("step ca health"))
        .stdout(predicate::str::contains("sshd -T"))
        .stdout(predicate::str::contains(
            "test -s /etc/ssl/example-ca/root_ca.crt",
        ))
        .stdout(predicate::str::contains(
            "cmp -s /etc/ssl/example-ca/root_ca.crt '<public-material-dir>/root_ca.crt'",
        ))
        .stdout(predicate::str::contains("openssl s_client"))
        .stdout(predicate::str::contains(
            "-CAfile '<public-material-dir>/root_ca.crt'",
        ))
        .stdout(predicate::str::contains("-verify_hostname ca.example.test"));

    let mut proxy = Command::cargo_bin("grafhome-ca").expect("binary exists");
    proxy
        .arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("proxy-cert")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "install -D -m 0644 '<public-material-dir>/root_ca.crt' /etc/ssl/example-ca/root_ca.crt",
        ))
        .stdout(predicate::str::contains(
            "install -d -m 0755 /var/www/html/.well-known/acme-challenge",
        ))
        .stdout(predicate::str::contains("step ca certificate"))
        .stdout(predicate::str::contains("--webroot /var/www/html"))
        .stdout(predicate::str::contains(
            "-CAfile '<public-material-dir>/root_ca.crt'",
        ))
        .stdout(predicate::str::contains("-verify_hostname ca.example.test"));
}

#[cfg(unix)]
#[test]
fn ca_fingerprint_executes_step_and_prints_fingerprint() {
    let (_dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("ca-fingerprint")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout("fingerprint-from-fake-step\n");

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("certificate fingerprint"));
}

#[cfg(unix)]
#[test]
fn approve_host_prints_one_complete_grant() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    let request = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-request",
        "host": "proxy-host",
        "ssh_public_key": "ssh-ed25519 AAAAhostpublic fixture",
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
            "\"root_fingerprint\":\"fingerprint-from-fake-step\"",
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
    let config = fs::read_to_string(ca_json).unwrap();
    assert!(config.contains("grafhome-host-70726f78792d686f7374"));
    assert!(config.contains("defaultHostSSHCertDuration"));
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
        "ssh_public_key": "ssh-ed25519 AAAAhostpublic fixture",
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"}
    });

    cmd.args(["approve", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--yes")
        .arg("--ttl")
        .arg(".")
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
    let original = r#"{"authority":{"provisioners":[{"name":"keep-me"}]}}"#;
    fs::write(&ca_json, original).unwrap();
    let request = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-request",
        "host": "proxy-host",
        "ssh_public_key": "ssh-ed25519 AAAAhostpublic fixture",
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
}

#[cfg(unix)]
#[test]
fn approve_user_token_failure_leaves_ca_state_untouched() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    let original = r#"{"authority":{"provisioners":[{"name":"keep-me"}]}}"#;
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
}

#[cfg(unix)]
#[test]
fn enroll_host_waits_for_grant_and_completes_in_one_invocation() {
    let (dir, fixture) = exec_fixture();
    let install_root = dir.path().join("install-root");
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-host-enrollment-grant",
        "host": "proxy-host",
        "ssh_public_key": "ssh-ed25519 AAAAhostpublic fixture",
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "trusted-fingerprint",
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
    assert!(log.contains("systemctl args=reload ssh"));
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

    let key = home.join(".ssh/alice_ca_host_ed25519");
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
        "ssh_public_key": "ssh-ed25519 AAAApublic test@fixture",
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "trusted-fingerprint",
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
            "Enrollment complete. Try: ssh nas",
        ));

    assert_eq!(fs::read_to_string(root).unwrap(), "root\n");
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains(
        "ca bootstrap --ca-url https://ca.example.test --fingerprint trusted-fingerprint --force"
    ));
    assert!(log.contains("ca health --ca-url https://ca.example.test"));
}

#[cfg(unix)]
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

#[cfg(unix)]
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

    let public_key = fs::read_to_string(home.join(".ssh/alice_ca_host_ed25519.pub")).unwrap();
    let grant = serde_json::json!({
        "version": 1,
        "kind": "grafhome-user-enrollment-grant",
        "user": "alice",
        "host": "ca-host",
        "ssh_public_key": public_key.trim(),
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "trusted-fingerprint",
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
            "Enrollment complete. Try: ssh nas",
        ));

    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    assert!(!material.join("pending-enrollment.json").exists());
    assert_eq!(
        fs::read_link(home.join(".ssh/alice.key")).unwrap(),
        PathBuf::from("alice_ca_host_ed25519")
    );
    assert_eq!(
        fs::read_link(home.join(".ssh/alice.key-cert.pub")).unwrap(),
        PathBuf::from("alice_ca_host_ed25519-cert.pub")
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("--token user-token"));
    assert!(log.contains("--issuer grafhome-user-616c696365-63612d686f7374"));
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
        "ssh_public_key": "ssh-ed25519 AAAAdifferent attacker",
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "trusted-fingerprint",
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
            "grant does not match this device's pending request",
        ));
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
        "root_fingerprint": "trusted-fingerprint",
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
            "grant does not match this device's pending request",
        ));
}

#[cfg(unix)]
#[test]
fn enroll_host_redacts_token_from_failed_step_error() {
    let (_dir, fixture) = exec_fixture();
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
        "ssh_public_key": "ssh-ed25519 AAAAhostpublic fixture",
        "renewal_public_jwk": {"kty":"OKP","crv":"Ed25519","x":"public"},
        "ca_url": "https://ca.example.test",
        "root_fingerprint": "trusted-fingerprint",
        "token": "sensitive-host-token"
    });
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    cmd.args(["enroll", "host"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
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
fn approve_user_authorizes_renewal_and_prints_complete_grant() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.args(["approve", "user"])
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--yes")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin(user_enrollment_request())
        .assert()
        .success()
        .stderr(predicate::str::contains("Approved alice@ca-host"))
        .stdout(predicate::str::contains("GRANT:{\"version\":1"))
        .stdout(predicate::str::contains("\"token\":\"token-for-alice\""));

    let ca_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    let provisioner = &ca_config["authority"]["provisioners"][0];
    assert_eq!(
        provisioner["name"],
        "grafhome-user-616c696365-63612d686f7374"
    );
    assert_eq!(provisioner["claims"]["defaultUserSSHCertDuration"], "24h");
    assert!(
        provisioner["options"]["ssh"]["template"]
            .as_str()
            .unwrap()
            .contains(r#""principals": ["alice"]"#)
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
}

#[cfg(unix)]
#[test]
fn approve_user_retries_transient_health_failure_after_restart() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
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
        .stdout(predicate::str::contains("GRANT:"));

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(log.matches("ca health").count(), 3);
    let ca_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    assert_eq!(
        ca_config["authority"]["provisioners"][0]["name"],
        "grafhome-user-616c696365-63612d686f7374"
    );
}

#[cfg(unix)]
#[test]
fn concurrent_approvals_preserve_both_scoped_provisioners() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
    let path = prepend_path(&fixture.fake_bin);
    let requests = ["ca-host", "proxy-host"].map(|host| {
        format!(
            "REQUEST:{}\n",
            serde_json::json!({
                "version": 1,
                "kind": "grafhome-user-enrollment-request",
                "user": "alice",
                "host": host,
                "ssh_public_key": format!("ssh-ed25519 AAAApublic alice@{host}"),
                "renewal_public_jwk": {"kid": format!("{host}-kid"), "kty": "EC"}
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
    let original = r#"{"authority":{"provisioners":[]}}"#;
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
}

#[cfg(unix)]
#[test]
fn ssh_ensure_reads_password_from_stdin_and_refreshes_cert() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/alice_ca_host_ed25519.pub"), "public\n").unwrap();
    fs::write(material.join("provisioner.priv.json"), "private\n").unwrap();
    let password_file = dir.path().join("password");
    fs::write(&password_file, "user-owned-password\n").unwrap();
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
fn quiet_ssh_ensure_suppresses_successful_renewal_output() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/alice_ca_host_ed25519.pub"), "public\n").unwrap();
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
fn quiet_ssh_ensure_reports_redacted_renewal_failures() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    fs::create_dir_all(&material).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/alice_ca_host_ed25519.pub"), "public\n").unwrap();
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
fn ssh_ensure_skips_fresh_certificate_without_loading_credential() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/alice_ca_host_ed25519-cert.pub"), "cert\n").unwrap();

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
fn revoke_host_removes_only_the_scoped_provisioner() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-host-70726f78792d686f7374"},{"name":"grafhome-user-616c696365-70726f78792d686f7374"},{"name":"grafhome-user-616c696365-63612d686f7374"},{"type":"SSHPOP","name":"grafhome-host-renew"},{"name":"keep-me"}]}}"#,
    )
    .unwrap();

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
            "remain valid until their current expiry",
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
fn enrollment_status_reports_host_and_user_devices_from_live_ca_state() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let root = home.join(".config/grafhome/step/certs/root_ca.crt");
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::write(root, "root\n").unwrap();
    let provisioners = r#"[{"name":"grafhome-host-70726f78792d686f7374"},{"name":"grafhome-user-616c696365-70726f78792d686f7374"}]"#;

    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args(["enrollment-status", "--host", "proxy-host", "--config-root"])
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
        .args(["enrollment-status", "--user", "alice", "--config-root"])
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
        .args([
            "enrollment-status",
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
            "enrollment-status",
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
    fs::write(renewal_dir.join("renewal-password.cred"), "credential\n").unwrap();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enrollment-status",
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
            "enrollment-status",
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
fn quiet_enrollment_status_treats_a_missing_local_trust_root_as_not_enrolled() {
    let (dir, fixture) = exec_fixture();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enrollment-status",
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
        .args(["enrollment-status", "--host", "proxy-host", "--config-root"])
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
        r#"{"authority":{"provisioners":[{"name":"grafhome-host-6465706172746564"},{"name":"grafhome-user-616c696365-6465706172746564"},{"name":"keep-me"}]}}"#,
    )
    .unwrap();

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
fn revoke_user_discovers_every_live_device_after_policy_removal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(
        &ca_json,
        r#"{"authority":{"provisioners":[{"name":"grafhome-user-6465706172746564-63612d686f7374"},{"name":"grafhome-user-6465706172746564-70726f78792d686f7374"},{"name":"keep-me"}]}}"#,
    )
    .unwrap();

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
fn user_enrollment_then_revocation_disables_scoped_renewal() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    let password_file = dir.path().join("password");
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&password_file, "user-owned-password\n").unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();

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
        .write_stdin(request)
        .output()
        .unwrap();
    assert!(approval.status.success());
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
            "enrollment-status",
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
            "enrollment-status",
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
fn host_enrollment_then_revocation_disables_scoped_renewal() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();

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
        .write_stdin(request)
        .output()
        .unwrap();
    assert!(approval.status.success());
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
            "enrollment-status",
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
        .args(["revoke", "host", "--host", "proxy-host", "--config-root"])
        .arg(&fixture.config_root)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success();
    Command::cargo_bin("grafhome-ca")
        .unwrap()
        .args([
            "enrollment-status",
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
fn prefixed_document(output: &[u8], prefix: &str) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing {prefix} document"))
        .to_owned()
}

#[cfg(unix)]
fn user_enrollment_request() -> String {
    format!(
        "REQUEST:{}\n",
        serde_json::json!({
            "version": 1,
            "kind": "grafhome-user-enrollment-request",
            "user": "alice",
            "host": "ca-host",
            "ssh_public_key": "ssh-ed25519 AAAApublic alice@ca-host",
            "renewal_public_jwk": {"kid": "device-kid", "kty": "EC"}
        })
    )
}
