use std::fs;

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
fn ssh_login_live_issuance_is_gated() {
    let mut cmd = Command::cargo_bin("grafhome-ssh-login").expect("binary exists");

    cmd.arg("--user")
        .arg("alice")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "live certificate issuance is not implemented",
        ));
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
        item["name"] == "grafhome-user-login"
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
fn plan_user_login_can_emit_json() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("--json")
        .arg("user-login")
        .arg("--user")
        .arg("alice")
        .arg("--device")
        .arg("ca-host")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"operation\": \"user-login\""))
        .stdout(predicate::str::contains("step ssh certificate"))
        .stdout(predicate::str::contains("--sign"))
        .stdout(predicate::str::contains("grafhome-user-login"))
        .stdout(predicate::str::contains("alice_ca_host_ed25519.pub"));
}

#[test]
fn plan_user_login_requires_device_for_multi_device_user() {
    let mut cmd = Command::cargo_bin("grafhome-ca").expect("binary exists");

    cmd.arg("plan")
        .arg("--config-root")
        .arg(example_config_root())
        .arg("user-login")
        .arg("--user")
        .arg("alice")
        .assert()
        .failure()
        .stderr(predicate::str::contains("multiple active client devices"));
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
        &["user-login", "--user", "alice", "--device", "ca-host"],
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
