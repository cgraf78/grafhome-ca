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
    fs::write(format!("{}.pub", host_key.display()), "host-public\n").unwrap();

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
  "crypto jwk")
    pub="$4"
    priv="$5"
    printf '{"kty":"OKP","crv":"Ed25519","x":"public"}\n' > "$pub"
    printf '{"kty":"OKP","crv":"Ed25519","x":"public","d":"private"}\n' > "$priv"
    printf 'jwk\n'
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
  printf 'public\n' > "$out.pub"
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
fn live_init_is_gated() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("init-ca")
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing live CA initialization"));
}

#[test]
fn init_dry_run_prints_plan() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("init-ca")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("init-ca: initialize step-ca"))
        .stdout(predicate::str::contains(
            "systemctl enable --now step-ca.service",
        ));
}

#[test]
fn init_dry_run_matches_init_plan_output() {
    let dry_run = Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .arg("init-ca")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--dry-run")
        .output()
        .expect("dry-run command exits");
    assert!(dry_run.status.success());

    let plan = Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("init-ca")
        .output()
        .expect("plan command exits");
    assert!(plan.status.success());
    assert_eq!(dry_run.stdout, plan.stdout);
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
    assert!(
        provisioners
            .iter()
            .any(|item| item["name"] == "grafhome-host-renew")
    );
}

#[test]
fn add_user_device_provisioner_writes_constrained_jwk_provisioner() {
    let dir = tempdir().unwrap();
    let ca_json = dir.path().join("ca.json");
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
    let public_key = dir.path().join("provisioner.pub.json");
    fs::write(&public_key, r#"{"kid":"device-kid","kty":"EC"}"#).unwrap();
    let template = dir.path().join("user.tpl");
    fs::write(&template, r#"{"type":"user","principals":["alice"]}"#).unwrap();
    let out_file = dir.path().join("out-ca.json");

    Command::cargo_bin("grafhome-ca")
        .expect("binary exists")
        .arg("add-user-device-provisioner")
        .arg("--ca-json")
        .arg(&ca_json)
        .arg("--public-key")
        .arg(&public_key)
        .arg("--name")
        .arg("grafhome-user-alice-ca-host")
        .arg("--ssh-template")
        .arg(&template)
        .arg("--default-ttl")
        .arg("24h")
        .arg("--max-ttl")
        .arg("168h")
        .arg("--out-file")
        .arg(&out_file)
        .assert()
        .success();

    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&out_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out_file).unwrap()).unwrap();
    let provisioner = &value["authority"]["provisioners"][0];
    assert_eq!(provisioner["name"], "grafhome-user-alice-ca-host");
    assert_eq!(provisioner["claims"]["defaultUserSSHCertDuration"], "24h");
    assert!(provisioner["claims"]["defaultHostSSHCertDuration"].is_null());
    assert!(
        provisioner["options"]["x509"]["template"]
            .as_str()
            .unwrap()
            .contains("x509 issuance disabled")
    );
    assert_eq!(
        provisioner["options"]["ssh"]["template"],
        r#"{"type":"user","principals":["alice"]}"#
    );
}

#[test]
fn plan_user_enrollment_commands_can_emit_json() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--json")
        .arg("enroll-user")
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"operation\": \"enroll-user\""))
        .stdout(predicate::str::contains("step ssh certificate"))
        .stdout(predicate::str::contains("--sign"))
        .stdout(predicate::str::contains("crypto jwk create"))
        .stdout(predicate::str::contains(
            "authorize-user --user alice --host ca-host",
        ))
        .stdout(predicate::str::contains("alice_ca_host_ed25519.pub"));
}

#[test]
fn plan_ssh_ensure_requires_host_for_multi_host_user() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("ssh-ensure")
        .arg("--user")
        .arg("alice")
        .assert()
        .failure()
        .stderr(predicate::str::contains("multiple active client hosts"));
}

#[test]
fn plan_host_renew_all_emits_structured_host_targets() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");
    let output = cmd
        .arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--json")
        .arg("host-renew-all")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let steps = value["steps"].as_array().unwrap();

    assert_eq!(value["operation"], "host-renew-all");
    assert_eq!(steps.len(), 4);
    assert_eq!(steps[0]["hosts"][0], "ca-host");
    assert!(steps.iter().all(|step| step["manual"] == false));
    assert!(steps.iter().all(|step| {
        step["commands"][0]
            .as_str()
            .unwrap()
            .contains("step ssh renew")
    }));
}

#[test]
fn every_plan_json_command_matches_plan_schema() {
    let cases: &[&[&str]] = &[
        &["init-ca"],
        &["host-bootstrap", "--host", "ca-host"],
        &["host-renew", "--host", "ca-host"],
        &["host-renew-all"],
        &["backup-ca"],
        &["verify-live", "--host", "ca-host"],
        &["proxy-cert"],
        &["create-host-token", "--host", "ca-host"],
        &["enroll-host", "--host", "ca-host"],
        &["create-user-token", "--user", "alice", "--host", "ca-host"],
        &["enroll-user", "--user", "alice", "--host", "ca-host"],
        &["ssh-ensure", "--user", "alice", "--host", "ca-host"],
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

#[test]
fn plan_host_bootstrap_prints_structured_target_host() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("host-bootstrap")
        .arg("--host")
        .arg("ca-host")
        .assert()
        .success()
        .stdout(predicate::str::contains("hosts: ca-host"))
        .stdout(predicate::str::contains("ca bootstrap"));
}

#[test]
fn plan_unknown_host_fails_before_any_execution() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("host-bootstrap")
        .arg("--host")
        .arg("missing")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown host"));
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
fn bootstrap_client_reads_fingerprint_from_stdin() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("bootstrap-client")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin("trusted-fingerprint\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("trusted root fingerprint: "))
        .stdout(predicate::str::contains("bootstrapped"))
        .stdout(predicate::str::contains("ok"));

    assert!(
        home.join(".config/grafhome/step/certs/root_ca.crt")
            .exists()
    );
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ca bootstrap"));
    assert!(log.contains("--fingerprint trusted-fingerprint"));
    assert!(log.contains("ca health"));
}

#[cfg(unix)]
#[test]
fn create_host_token_executes_step_and_prints_token() {
    let (_dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("create-host-token")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout("token-for-proxy-host\n");

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ca token proxy-host --ssh --host"));
    assert!(log.contains("--principal proxy-host"));
    assert!(log.contains("--principal ca.example.test"));
    assert!(log.contains("--not-after 15m"));
    assert!(log.contains("--cert-not-after 168h"));
}

#[cfg(unix)]
#[test]
fn create_host_token_rejects_malformed_ttl_before_step_runs() {
    let (_dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("create-host-token")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .arg("--ttl")
        .arg(".")
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "duration must use Smallstep units",
        ));

    assert!(!fixture.log.exists());
}

#[cfg(unix)]
#[test]
fn enroll_host_reads_token_from_stdin_and_reloads_ssh() {
    let (_dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("enroll-host")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin("host-token\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("host enrollment token: "))
        .stdout(predicate::str::contains("signed"))
        .stdout(predicate::str::contains("inspect"));

    assert!(PathBuf::from(format!("{}-cert.pub", fixture.host_key.display())).exists());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ssh certificate proxy-host"));
    assert!(log.contains("--token host-token"));
    assert!(log.contains("sshd args=-t"));
    assert!(log.contains("systemctl args=reload ssh"));
}

#[cfg(unix)]
#[test]
fn create_user_token_executes_step_and_prints_token() {
    let (_dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("create-user-token")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("FAKE_LOG", &fixture.log)
        .assert()
        .success()
        .stdout("token-for-alice\n");

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("ca token alice --ssh --principal alice"));
    assert!(log.contains("--provisioner grafhome-user-enrollment"));
    assert!(log.contains("--cert-not-after 24h"));
}

#[cfg(unix)]
#[test]
fn enroll_user_reads_token_and_password_from_stdin_without_persisting_password() {
    let (dir, fixture) = exec_fixture();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("enroll-user")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin("user-token\nuser-owned-password\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("user enrollment token: "))
        .stderr(predicate::str::contains("user provisioner password: "))
        .stdout(predicate::str::contains("user cert:"))
        .stdout(predicate::str::contains(
            "authorize renewal on the CA with:",
        ))
        .stdout(predicate::str::contains(
            "grafhome-ca authorize-user --user alice --host ca-host <<'GRAFHOME_CA_USER_RENEWAL_PUBLIC_KEY'",
        ))
        .stdout(predicate::str::contains(
            "GRAFHOME_CA_USER_RENEWAL_PUBLIC_KEY",
        ));

    let key = home.join(".ssh/alice_ca_host_ed25519");
    let cert = home.join(".ssh/alice_ca_host_ed25519-cert.pub");
    let material = home.join(".config/grafhome-ca/users/alice/hosts/ca-host");
    assert!(key.exists());
    assert!(cert.exists());
    assert!(material.join("provisioner.pub.json").exists());
    assert!(material.join("provisioner.priv.json").exists());
    assert!(fs::read_dir(&material).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("password")
    }));
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("--token user-token"));
    assert!(log.contains("crypto jwk create"));
    assert!(!log.contains("user-owned-password"));
}

#[cfg(unix)]
#[test]
fn enroll_host_redacts_token_from_failed_step_error() {
    let (_dir, fixture) = exec_fixture();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("enroll-host")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--host")
        .arg("proxy-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_FAIL", "ssh-certificate")
        .write_stdin("sensitive-host-token\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("[REDACTED]"))
        .stderr(predicate::str::contains("sensitive-host-token").not());
}

#[cfg(unix)]
#[test]
fn authorize_user_reads_public_key_from_stdin_and_restarts_step_ca() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("authorize-user")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin("{\n  \"kid\": \"device-kid\",\n  \"kty\": \"EC\"\n}\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("public JWK: "))
        .stdout(predicate::str::contains("backup ca.json:"))
        .stdout(predicate::str::contains(
            "authorized provisioner: grafhome-user-alice-ca-host",
        ));

    let ca_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    let provisioner = &ca_config["authority"]["provisioners"][0];
    assert_eq!(provisioner["name"], "grafhome-user-alice-ca-host");
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
            .join("templates/ssh/grafhome-user-alice-ca-host.tpl")
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
fn authorize_user_retries_transient_health_failure_after_restart() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    fs::write(&ca_json, r#"{"authority":{"provisioners":[]}}"#).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("authorize-user")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_STEP_HEALTH_FAIL_ONCE", "1")
        .write_stdin("{\n  \"kid\": \"device-kid\",\n  \"kty\": \"EC\"\n}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "authorized provisioner: grafhome-user-alice-ca-host",
        ));

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(log.matches("ca health").count(), 3);
    let ca_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&ca_json).unwrap()).unwrap();
    assert_eq!(
        ca_config["authority"]["provisioners"][0]["name"],
        "grafhome-user-alice-ca-host"
    );
}

#[cfg(unix)]
#[test]
fn authorize_user_rolls_back_ca_json_if_restart_fails() {
    let (_dir, fixture) = exec_fixture();
    let ca_json = fixture.config_root.join("../state/step/config/ca.json");
    fs::create_dir_all(ca_json.parent().unwrap()).unwrap();
    let original = r#"{"authority":{"provisioners":[]}}"#;
    fs::write(&ca_json, original).unwrap();
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("authorize-user")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .env("FAKE_SYSTEMCTL_RESTART_FAIL_ONCE", "1")
        .write_stdin("{\n  \"kid\": \"device-kid\",\n  \"kty\": \"EC\"\n}\n")
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
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("ssh-ensure")
        .arg("--config-root")
        .arg(&fixture.config_root)
        .arg("--user")
        .arg("alice")
        .arg("--host")
        .arg("ca-host")
        .env("HOME", &home)
        .env("PATH", prepend_path(&fixture.fake_bin))
        .env("FAKE_LOG", &fixture.log)
        .write_stdin("user-owned-password\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("user provisioner password: "))
        .stdout(predicate::str::contains("signed"))
        .stdout(predicate::str::contains("inspect"));

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("--issuer grafhome-user-alice-ca-host"));
    assert!(log.contains("ssh certificate alice"));
    assert!(!log.contains("user-owned-password"));
}
