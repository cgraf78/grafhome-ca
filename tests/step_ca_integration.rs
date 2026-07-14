use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

#[test]
fn rendered_config_can_start_throwaway_step_ca() {
    if std::env::var("GRAFHOME_CA_RUN_STEP_CA_INTEGRATION").as_deref() != Ok("1") {
        let message =
            "skipping step-ca integration test; set GRAFHOME_CA_RUN_STEP_CA_INTEGRATION=1";
        if std::env::var("GRAFHOME_CA_REQUIRE_STEP_CA_INTEGRATION").as_deref() == Ok("1") {
            panic!("{message}");
        }
        eprintln!("{message}");
        return;
    }
    assert_command_available("step");
    assert_command_available("step-ca");

    let temp = tempdir().unwrap();
    let password = temp.path().join("password");
    let passphrase = ["test", "only", "passphrase"].join("-");
    std::fs::write(&password, format!("{passphrase}\n")).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let steppath = temp.path().join("step");

    run(Command::new("step")
        .env("STEPPATH", &steppath)
        .arg("ca")
        .arg("init")
        .arg("--ssh")
        .arg("--deployment-type")
        .arg("standalone")
        .arg("--name")
        .arg("grafhome-ca-test")
        .arg("--dns")
        .arg("ca.example.test")
        .arg("--dns")
        .arg("ca-origin.example.test")
        .arg("--dns")
        .arg("127.0.0.1")
        .arg("--address")
        .arg("127.0.0.1:0")
        .arg("--provisioner")
        .arg("grafhome-host-bootstrap")
        .arg("--password-file")
        .arg(&password)
        .arg("--provisioner-password-file")
        .arg(&password));
    let config_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site-config");
    let mut model = grafhome_ca::model::SiteModel::load(config_root).unwrap();
    model.deployment.values.insert(
        "GRAFHOME_CA_STATE_DIR".to_owned(),
        temp.path().display().to_string(),
    );
    model
        .deployment
        .values
        .insert("GRAFHOME_CA_ROOT_STEP_BIN".to_owned(), "step".to_owned());
    let rendered = grafhome_ca::render::render(&model).unwrap();
    let ca_json = rendered
        .iter()
        .find(|file| file.path.ends_with("step/config/ca.json"))
        .unwrap();
    let mut config: serde_json::Value = serde_json::from_str(&ca_json.content).unwrap();
    rewrite_state_dir(
        &mut config,
        &model.deployment.values["GRAFHOME_CA_STATE_DIR"],
        temp.path().to_str().unwrap(),
    );
    config["address"] = serde_json::json!(format!("127.0.0.1:{}", free_port()));
    config["dnsNames"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("127.0.0.1"));
    let staged_ca_json = temp.path().join("staged-ca.json");
    std::fs::write(
        &staged_ca_json,
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    let mut live_config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(steppath.join("config/ca.json")).unwrap()).unwrap();
    let legacy = temp.path().join("legacy-user-enrollment");
    std::fs::create_dir(&legacy).unwrap();
    run(Command::new("step")
        .arg("crypto")
        .arg("jwk")
        .arg("create")
        .arg(legacy.join("public.json"))
        .arg(legacy.join("private.json"))
        .arg("--password-file")
        .arg(&password));
    let legacy_user_public: serde_json::Value =
        serde_json::from_slice(&std::fs::read(legacy.join("public.json")).unwrap()).unwrap();
    let legacy_user_private: serde_json::Value =
        serde_json::from_slice(&std::fs::read(legacy.join("private.json")).unwrap()).unwrap();
    live_config["authority"]["provisioners"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "JWK",
            "name": "grafhome-user-enrollment",
            "key": legacy_user_public,
            "encryptedKey": serde_json::to_string(&legacy_user_private).unwrap()
        }));
    std::fs::write(
        steppath.join("config/ca.json"),
        serde_json::to_vec_pretty(&live_config).unwrap(),
    )
    .unwrap();

    let integration_config = prepare_integration_config(temp.path(), &password);
    run(Command::new(env!("CARGO_BIN_EXE_grafhome-ca"))
        .args(["migrate", "enrollment-provisioner-keys", "--config-root"])
        .arg(&integration_config)
        .env("PATH", temp.path().join("bin")));
    run(Command::new(env!("CARGO_BIN_EXE_grafhome-ca"))
        .args(["migrate", "enrollment-provisioner-keys", "--config-root"])
        .arg(&integration_config)
        .env("PATH", temp.path().join("bin")));
    let jwk_dir = temp.path().join("secrets/provisioners");
    let host_enrollment_password = jwk_dir.join("grafhome-host-bootstrap.password");
    let user_enrollment_password = jwk_dir.join("grafhome-user-enrollment.password");
    assert_ne!(
        std::fs::read(&host_enrollment_password).unwrap(),
        std::fs::read(&password).unwrap()
    );
    assert_ne!(
        std::fs::read(&user_enrollment_password).unwrap(),
        std::fs::read(&password).unwrap()
    );
    assert_ne!(
        std::fs::read(&host_enrollment_password).unwrap(),
        std::fs::read(&user_enrollment_password).unwrap()
    );
    for name in ["grafhome-host-bootstrap", "grafhome-user-enrollment"] {
        assert_migrated_jwk_matches_public(&jwk_dir, name);
    }
    let valid_user_password = std::fs::read(&user_enrollment_password).unwrap();
    std::fs::write(&user_enrollment_password, "wrong-password\n").unwrap();
    let rejected_materialized = temp.path().join("rejected-materialized-ca.json");
    run_fails(
        Command::new(env!("CARGO_BIN_EXE_grafhome-ca"))
            .arg("materialize")
            .arg("--config-root")
            .arg(&integration_config)
            .arg("--live-ca-json")
            .arg(steppath.join("config/ca.json"))
            .arg("--staged-ca-json")
            .arg(&staged_ca_json)
            .arg("--jwk-dir")
            .arg(&jwk_dir)
            .arg("--out-file")
            .arg(&rejected_materialized)
            .env("PATH", temp.path().join("bin")),
    );
    assert!(!rejected_materialized.exists());
    run_fails(
        Command::new(env!("CARGO_BIN_EXE_grafhome-ca"))
            .args(["migrate", "enrollment-provisioner-keys", "--config-root"])
            .arg(&integration_config)
            .env("PATH", temp.path().join("bin")),
    );
    std::fs::write(&user_enrollment_password, valid_user_password).unwrap();
    run(Command::new(env!("CARGO_BIN_EXE_grafhome-ca"))
        .args(["migrate", "enrollment-provisioner-keys", "--config-root"])
        .arg(&integration_config)
        .env("PATH", temp.path().join("bin")));
    for name in ["preserved-user", "preserved-host"] {
        run(Command::new("step")
            .arg("crypto")
            .arg("jwk")
            .arg("create")
            .arg(jwk_dir.join(format!("{name}.pub.json")))
            .arg(jwk_dir.join(format!("{name}.priv.json")))
            .arg("--password-file")
            .arg(&password));
    }
    let preserved_user_key: serde_json::Value =
        serde_json::from_slice(&std::fs::read(jwk_dir.join("preserved-user.pub.json")).unwrap())
            .unwrap();
    let preserved_host_key: serde_json::Value =
        serde_json::from_slice(&std::fs::read(jwk_dir.join("preserved-host.pub.json")).unwrap())
            .unwrap();
    live_config["authority"]["provisioners"]
        .as_array_mut()
        .unwrap()
        .extend([
            serde_json::json!({
                "type": "JWK",
                "name": "grafhome-user-616c696365-70726f78792d686f7374",
                "key": preserved_user_key,
                "encryptedKey": "remove-accidental-secret",
                "claims": {
                    "defaultUserSSHCertDuration": "12h",
                    "maxUserSSHCertDuration": "2562047h"
                },
                "options": {
                    "x509": {"template": "{{ fail \"x509 disabled\" }}"},
                    "ssh": {"template": "{\"type\":\"user\",\"keyId\":{{ toJson .KeyID }},\"principals\":[\"alice\"]}"}
                }
            }),
            serde_json::json!({
                "type": "JWK",
                "name": "grafhome-host-656467652d686f7374",
                "key": preserved_host_key,
                "claims": {
                    "defaultHostSSHCertDuration": "24h",
                    "maxHostSSHCertDuration": "2562047h"
                },
                "options": {
                    "x509": {"template": "{{ fail \"x509 disabled\" }}"},
                    "ssh": {"template": "{\"type\":\"host\",\"keyId\":{{ toJson .KeyID }},\"principals\":[\"edge-host\"]}"}
                }
            }),
        ]);
    let live_for_materialize = temp.path().join("live-with-renewals.json");
    std::fs::write(
        &live_for_materialize,
        serde_json::to_vec_pretty(&live_config).unwrap(),
    )
    .unwrap();
    let materialized_path = temp.path().join("materialized-ca.json");
    run(Command::new(env!("CARGO_BIN_EXE_grafhome-ca"))
        .arg("materialize")
        .arg("--config-root")
        .arg(&integration_config)
        .arg("--live-ca-json")
        .arg(&live_for_materialize)
        .arg("--staged-ca-json")
        .arg(&staged_ca_json)
        .arg("--jwk-dir")
        .arg(&jwk_dir)
        .arg("--out-file")
        .arg(&materialized_path)
        .env("PATH", temp.path().join("bin")));
    let materialized = std::fs::read_to_string(materialized_path).unwrap();
    let mut config: serde_json::Value = serde_json::from_str(&materialized).unwrap();
    assert!(
        config["authority"]["provisioners"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item.get("encryptedKey").is_none())
    );
    let preserved_user = config["authority"]["provisioners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "grafhome-user-616c696365-70726f78792d686f7374")
        .unwrap();
    assert_eq!(preserved_user["key"], preserved_user_key);
    assert_eq!(preserved_user["claims"]["maxUserSSHCertDuration"], "48h");
    let preserved_host = config["authority"]["provisioners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "grafhome-host-656467652d686f7374")
        .unwrap();
    assert_eq!(preserved_host["key"], preserved_host_key);
    assert_eq!(preserved_host["claims"]["maxHostSSHCertDuration"], "720h");
    std::fs::create_dir_all(temp.path().join("step/valuedb")).unwrap();

    let config_path = steppath.join("config/rendered-ca.json");
    std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
    {
        let mut child = start_step_ca(&config_path, &password);
        wait_for_health(
            child.as_mut(),
            config["address"].as_str().unwrap(),
            &steppath,
        );
        assert_preserved_renewal_provisioners_sign(
            temp.path(),
            config["address"].as_str().unwrap(),
            &password,
            &jwk_dir,
        );
        assert_effectively_infinite_user_enrollment(
            temp.path(),
            config["address"].as_str().unwrap(),
            &user_enrollment_password,
            &jwk_dir.join("grafhome-user-enrollment.priv.json"),
        );
    }
    let user_enrollment = config["authority"]["provisioners"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|item| item["name"] == "grafhome-user-enrollment")
        .unwrap();
    user_enrollment["claims"]["defaultUserSSHCertDuration"] = serde_json::json!("12h");
    user_enrollment["claims"]["maxUserSSHCertDuration"] = serde_json::json!("168h");
    std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
    {
        let mut child = start_step_ca(&config_path, &password);
        wait_for_health(
            child.as_mut(),
            config["address"].as_str().unwrap(),
            &steppath,
        );
        assert_long_user_enrollment_rejected(
            temp.path(),
            config["address"].as_str().unwrap(),
            &user_enrollment_password,
            &jwk_dir.join("grafhome-user-enrollment.priv.json"),
        );
    }
    add_test_user_client_provisioner(&model, temp.path(), &config_path, &password);
    let mut child = start_step_ca(&config_path, &password);
    wait_for_health(
        child.as_mut(),
        config["address"].as_str().unwrap(),
        &steppath,
    );
    assert_enrollment_authority_policy(
        temp.path(),
        config["address"].as_str().unwrap(),
        &host_enrollment_password,
        &user_enrollment_password,
    );
    exercise_public_export_and_host_certificate_lifecycle(
        &model,
        temp.path(),
        config["address"].as_str().unwrap(),
        &password,
        &host_enrollment_password,
        &user_enrollment_password,
    );
}

fn assert_preserved_renewal_provisioners_sign(
    temp: &std::path::Path,
    address: &str,
    password: &std::path::Path,
    jwk_dir: &std::path::Path,
) {
    let cases = [
        (
            "grafhome-user-616c696365-70726f78792d686f7374",
            "preserved-user",
            "alice",
            false,
            "24h",
        ),
        (
            "grafhome-host-656467652d686f7374",
            "preserved-host",
            "edge-host",
            true,
            "168h",
        ),
    ];

    for (issuer, key_name, principal, host, cert_ttl) in cases {
        let key = temp.join(format!("{key_name}-ssh"));
        run(Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&key));
        let mut token_command = Command::new("step");
        token_command
            .env("STEPPATH", temp.join("step"))
            .arg("ca")
            .arg("token")
            .arg(principal)
            .arg("--ssh");
        if host {
            token_command.arg("--host");
        }
        token_command
            .arg("--principal")
            .arg(principal)
            .arg("--not-after")
            .arg("5m")
            .arg("--cert-not-after")
            .arg(cert_ttl)
            .arg("--issuer")
            .arg(issuer)
            .arg("--key")
            .arg(jwk_dir.join(format!("{key_name}.priv.json")))
            .arg("--password-file")
            .arg(password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt"));
        let signing_token = token(&mut token_command);

        let mut sign_command = Command::new("step");
        sign_command
            .env("STEPPATH", temp.join(format!("{key_name}-step")))
            .arg("ssh")
            .arg("certificate")
            .arg(principal)
            .arg(key.with_extension("pub"));
        if host {
            sign_command.arg("--host");
        } else {
            sign_command.arg("--no-agent");
        }
        sign_command
            .arg("--sign")
            .arg("--token")
            .arg(signing_token.trim())
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt"))
            .arg("--force");
        run(&mut sign_command);
        assert!(
            key.with_file_name(format!("{key_name}-ssh-cert.pub"))
                .is_file()
        );
    }
}

fn prepare_integration_config(
    temp: &std::path::Path,
    password: &std::path::Path,
) -> std::path::PathBuf {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site-config");
    let config_root = temp.join("grafhome-ca");
    copy_dir(&source, &config_root);
    let bin = temp.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let step = stdout(Command::new("which").arg("step"));
    std::fs::copy(step.trim(), bin.join("step")).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(bin.join("step"), std::fs::Permissions::from_mode(0o755)).unwrap();
    for name in [
        "chmod",
        "chown",
        "ssh-keygen",
        "sshd",
        "systemctl",
        "grafhome-ca-helper",
    ] {
        write_executable(&bin.join(name), "#!/bin/sh\nexit 0\n");
    }
    let host_key = temp.join("load-root-model-host-key");
    std::fs::write(&host_key, "test-only-host-key\n").unwrap();
    let deployment_path = config_root.join("config/deployment.env");
    let deployment = std::fs::read_to_string(&deployment_path)
        .unwrap()
        .replace(
            "GRAFHOME_CA_STATE_DIR=/srv/example-ca",
            &format!("GRAFHOME_CA_STATE_DIR={}", temp.display()),
        )
        .replace(
            "GRAFHOME_CA_SERVER_STEPPATH=/etc/step/grafhome",
            &format!(
                "GRAFHOME_CA_SERVER_STEPPATH={}",
                temp.join("server-step").display()
            ),
        )
        .replace(
            "GRAFHOME_CA_ROOT_STEP_BIN=/root/.local/bin/step",
            &format!("GRAFHOME_CA_ROOT_STEP_BIN={}", bin.join("step").display()),
        )
        .replace(
            "GRAFHOME_CA_HELPER_BIN=/root/.local/bin/grafhome-ca",
            &format!(
                "GRAFHOME_CA_HELPER_BIN={}",
                bin.join("grafhome-ca-helper").display()
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
    std::fs::write(deployment_path, deployment).unwrap();
    config_root
}

fn copy_dir(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn write_executable(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn assert_migrated_jwk_matches_public(jwk_dir: &std::path::Path, name: &str) {
    let private = jwk_dir.join(format!("{name}.priv.json"));
    let password = jwk_dir.join(format!("{name}.password"));
    let encrypted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&private).unwrap()).unwrap();
    for member in ["protected", "iv", "ciphertext", "tag", "encrypted_key"] {
        assert!(encrypted[member].is_string(), "missing JWE member {member}");
    }
    let directory = tempdir().unwrap();
    let plaintext = directory.path().join("plaintext.jwk");
    run(Command::new("step")
        .arg("crypto")
        .arg("key")
        .arg("format")
        .arg(&private)
        .arg("--jwk")
        .arg("--password-file")
        .arg(&password)
        .arg("--out")
        .arg(&plaintext)
        .arg("--insecure")
        .arg("--no-password"));
    let plaintext: serde_json::Value =
        serde_json::from_slice(&std::fs::read(plaintext).unwrap()).unwrap();
    let public: serde_json::Value =
        serde_json::from_slice(&std::fs::read(jwk_dir.join(format!("{name}.pub.json"))).unwrap())
            .unwrap();
    assert_eq!(
        jwk_public_material(&plaintext),
        jwk_public_material(&public)
    );
}

fn jwk_public_material(jwk: &serde_json::Value) -> serde_json::Value {
    let object = jwk.as_object().unwrap();
    let members: &[&str] = match object["kty"].as_str().unwrap() {
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "RSA" => &["e", "kty", "n"],
        other => panic!("unexpected JWK type {other}"),
    };
    serde_json::Value::Object(
        members
            .iter()
            .map(|member| ((*member).to_owned(), object[*member].clone()))
            .collect(),
    )
}

fn assert_effectively_infinite_user_enrollment(
    temp: &std::path::Path,
    address: &str,
    password: &std::path::Path,
    enrollment_key: &std::path::Path,
) {
    let key = temp.join("effectively-infinite-user");
    run(Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&key));
    let enrollment_token = token(
        Command::new("step")
            .env("STEPPATH", temp.join("step"))
            .arg("ca")
            .arg("token")
            .arg("alice")
            .arg("--ssh")
            .arg("--principal")
            .arg("alice")
            .arg("--not-after")
            .arg("15m")
            .arg("--cert-not-after")
            .arg("2562047h")
            .arg("--issuer")
            .arg("grafhome-user-enrollment")
            .arg("--key")
            .arg(enrollment_key)
            .arg("--password-file")
            .arg(password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run(Command::new("step")
        .env("STEPPATH", temp.join("effectively-infinite-step"))
        .arg("ssh")
        .arg("certificate")
        .arg("alice")
        .arg(key.with_extension("pub"))
        .arg("--sign")
        .arg("--token")
        .arg(enrollment_token.trim())
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--root")
        .arg(temp.join("step/certs/root_ca.crt"))
        .arg("--force")
        .arg("--no-agent"));
    run(Command::new("ssh-keygen")
        .arg("-L")
        .arg("-f")
        .arg(key.with_file_name("effectively-infinite-user-cert.pub")));
    let output = Command::new("step")
        .arg("ssh")
        .arg("inspect")
        .arg(key.with_file_name("effectively-infinite-user-cert.pub"))
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "step ssh inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let certificate: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(certificate["Type"], "user");
    assert_eq!(certificate["Principals"], serde_json::json!(["alice"]));
    let valid_after_year = certificate["ValidAfter"].as_str().unwrap()[..4]
        .parse::<i32>()
        .unwrap();
    let valid_before_year = certificate["ValidBefore"].as_str().unwrap()[..4]
        .parse::<i32>()
        .unwrap();
    assert!(
        valid_before_year - valid_after_year >= 290,
        "effectively-infinite certificate validity was unexpectedly short: {} to {}",
        certificate["ValidAfter"],
        certificate["ValidBefore"]
    );
}

fn assert_command_available(command: &str) {
    let status = Command::new(command)
        .arg("version")
        .status()
        .unwrap_or_else(|err| {
            panic!("{command} is required for GRAFHOME_CA_RUN_STEP_CA_INTEGRATION=1: {err}")
        });
    assert!(status.success(), "{command} version failed");
}

fn start_step_ca(config: &std::path::Path, password: &std::path::Path) -> StepCaChild {
    let child = Command::new("step-ca")
        .arg(config)
        .arg("--password-file")
        .arg(password)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    StepCaChild::new(child)
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn rewrite_state_dir(value: &mut serde_json::Value, from: &str, to: &str) {
    match value {
        serde_json::Value::String(text) => {
            *text = text.replace(from, to);
        }
        serde_json::Value::Array(items) => {
            for item in items {
                rewrite_state_dir(item, from, to);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                rewrite_state_dir(item, from, to);
            }
        }
        _ => {}
    }
}

struct StepCaChild {
    child: Child,
}

impl StepCaChild {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl AsMut<Child> for StepCaChild {
    fn as_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for StepCaChild {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn wait_for_health(child: &mut Child, address: &str, steppath: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("step-ca exited before health check succeeded: {status}");
        }
        let status = Command::new("step")
            .arg("ca")
            .arg("health")
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(steppath.join("certs/root_ca.crt"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        if status.success() {
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("step-ca did not become healthy");
}

fn assert_long_user_enrollment_rejected(
    temp: &std::path::Path,
    address: &str,
    password: &std::path::Path,
    enrollment_key: &std::path::Path,
) {
    let key = temp.join("stale-limit-user");
    run(Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&key));
    let enrollment_token = token(
        Command::new("step")
            .env("STEPPATH", temp.join("step"))
            .arg("ca")
            .arg("token")
            .arg("alice")
            .arg("--ssh")
            .arg("--principal")
            .arg("alice")
            .arg("--not-after")
            .arg("15m")
            .arg("--cert-not-after")
            .arg("8760h")
            .arg("--issuer")
            .arg("grafhome-user-enrollment")
            .arg("--key")
            .arg(enrollment_key)
            .arg("--password-file")
            .arg(password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    let output = Command::new("step")
        .env("STEPPATH", temp.join("stale-client-step"))
        .arg("ssh")
        .arg("certificate")
        .arg("alice")
        .arg(key.with_extension("pub"))
        .arg("--sign")
        .arg("--token")
        .arg(enrollment_token.trim())
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--root")
        .arg(temp.join("step/certs/root_ca.crt"))
        .arg("--force")
        .arg("--no-agent")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "stale enrollment issuer unexpectedly accepted an 8760h certificate"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("greater than maximum accepted duration"),
        "unexpected stale-limit error:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_enrollment_authority_policy(
    temp: &std::path::Path,
    address: &str,
    host_password: &std::path::Path,
    user_password: &std::path::Path,
) {
    let key = temp.join("disallowed-user");
    run(Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&key));
    let disallowed_user_token = token(
        Command::new("step")
            .env("STEPPATH", temp.join("step"))
            .arg("ca")
            .arg("token")
            .arg("mallory")
            .arg("--ssh")
            .arg("--principal")
            .arg("mallory")
            .arg("--not-after")
            .arg("5m")
            .arg("--cert-not-after")
            .arg("24h")
            .arg("--issuer")
            .arg("grafhome-user-enrollment")
            .arg("--key")
            .arg(temp.join("secrets/provisioners/grafhome-user-enrollment.priv.json"))
            .arg("--password-file")
            .arg(user_password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run_fails(
        Command::new("step")
            .env("STEPPATH", temp.join("disallowed-user-step"))
            .arg("ssh")
            .arg("certificate")
            .arg("mallory")
            .arg(key.with_extension("pub"))
            .arg("--sign")
            .arg("--token")
            .arg(disallowed_user_token.trim())
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt"))
            .arg("--force")
            .arg("--no-agent"),
    );

    let key = temp.join("disallowed-host");
    run(Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&key));
    let disallowed_host_token = token(
        Command::new("step")
            .env("STEPPATH", temp.join("step"))
            .arg("ca")
            .arg("token")
            .arg("attacker.example.test")
            .arg("--ssh")
            .arg("--host")
            .arg("--principal")
            .arg("attacker.example.test")
            .arg("--not-after")
            .arg("5m")
            .arg("--cert-not-after")
            .arg("24h")
            .arg("--issuer")
            .arg("grafhome-host-bootstrap")
            .arg("--key")
            .arg(temp.join("secrets/provisioners/grafhome-host-bootstrap.priv.json"))
            .arg("--password-file")
            .arg(host_password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run_fails(
        Command::new("step")
            .env("STEPPATH", temp.join("disallowed-host-step"))
            .arg("ssh")
            .arg("certificate")
            .arg("attacker.example.test")
            .arg(key.with_extension("pub"))
            .arg("--host")
            .arg("--sign")
            .arg("--token")
            .arg(disallowed_host_token.trim())
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt"))
            .arg("--force"),
    );
}

fn exercise_public_export_and_host_certificate_lifecycle(
    model: &grafhome_ca::model::SiteModel,
    temp: &std::path::Path,
    address: &str,
    password: &std::path::Path,
    host_enrollment_password: &std::path::Path,
    user_enrollment_password: &std::path::Path,
) {
    let public_dir = temp.join("public");
    let public_files = grafhome_ca::public_material::collect(model).unwrap();
    grafhome_ca::public_material::write(&public_files, &public_dir).unwrap();
    let fingerprint = std::fs::read_to_string(public_dir.join("root_fingerprint")).unwrap();
    let known_hosts = std::fs::read_to_string(public_dir.join("ssh_known_hosts")).unwrap();
    assert!(known_hosts.contains("@cert-authority"));
    assert!(known_hosts.contains("ca-origin.example.test"));

    let client_steppath = temp.join("client-step");
    run(Command::new("step")
        .env("STEPPATH", &client_steppath)
        .arg("ca")
        .arg("bootstrap")
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--fingerprint")
        .arg(fingerprint.trim()));

    let host_key = temp.join("ssh_host_ed25519_key");
    run(Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&host_key));
    let host_public_key = temp.join("ssh_host_ed25519_key.pub");
    let host_cert = temp.join("ssh_host_ed25519_key-cert.pub");
    let host_token = token(
        Command::new("step")
            .env("STEPPATH", temp.join("step"))
            .arg("ca")
            .arg("token")
            .arg("edge-host")
            .arg("--ssh")
            .arg("--host")
            .arg("--principal")
            .arg("edge-host")
            .arg("--principal")
            .arg("edge-host.example.test")
            .arg("--not-after")
            .arg("15m")
            .arg("--cert-not-after")
            .arg("168h")
            .arg("--issuer")
            .arg("grafhome-host-bootstrap")
            .arg("--key")
            .arg(temp.join("secrets/provisioners/grafhome-host-bootstrap.priv.json"))
            .arg("--password-file")
            .arg(host_enrollment_password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run(Command::new("step")
        .env("STEPPATH", &client_steppath)
        .arg("ssh")
        .arg("certificate")
        .arg("edge-host")
        .arg(&host_public_key)
        .arg("--host")
        .arg("--sign")
        .arg("--token")
        .arg(host_token.trim())
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--root")
        .arg(temp.join("step/certs/root_ca.crt"))
        .arg("--force"));
    assert!(host_cert.exists());

    let user_key = temp.join("id_ed25519");
    run(Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&user_key));
    let user_public_key = temp.join("id_ed25519.pub");
    let user_cert = temp.join("id_ed25519-cert.pub");
    let user_enrollment_token = token(
        Command::new("step")
            .env("STEPPATH", temp.join("step"))
            .arg("ca")
            .arg("token")
            .arg("alice")
            .arg("--ssh")
            .arg("--principal")
            .arg("alice")
            .arg("--not-after")
            .arg("15m")
            .arg("--cert-not-after")
            .arg("8760h")
            .arg("--issuer")
            .arg("grafhome-user-enrollment")
            .arg("--key")
            .arg(temp.join("secrets/provisioners/grafhome-user-enrollment.priv.json"))
            .arg("--password-file")
            .arg(user_enrollment_password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run(Command::new("step")
        .env("STEPPATH", &client_steppath)
        .arg("ssh")
        .arg("certificate")
        .arg("alice")
        .arg(&user_public_key)
        .arg("--sign")
        .arg("--token")
        .arg(user_enrollment_token.trim())
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--root")
        .arg(temp.join("step/certs/root_ca.crt"))
        .arg("--force")
        .arg("--no-agent"));
    assert!(user_cert.exists());

    let excessive_refresh_token = token(
        Command::new("step")
            .env("STEPPATH", &client_steppath)
            .arg("ca")
            .arg("token")
            .arg("alice")
            .arg("--ssh")
            .arg("--principal")
            .arg("alice")
            .arg("--not-after")
            .arg("5m")
            .arg("--cert-not-after")
            .arg("8760h")
            .arg("--issuer")
            .arg("grafhome-user-616c696365-63612d686f7374")
            .arg("--key")
            .arg(temp.join("alice-ca-host.priv.json"))
            .arg("--password-file")
            .arg(password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run_fails(
        Command::new("step")
            .env("STEPPATH", &client_steppath)
            .arg("ssh")
            .arg("certificate")
            .arg("alice")
            .arg(&user_public_key)
            .arg("--sign")
            .arg("--token")
            .arg(excessive_refresh_token.trim())
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt"))
            .arg("--force")
            .arg("--no-agent"),
    );

    let user_refresh_token = token(
        Command::new("step")
            .env("STEPPATH", &client_steppath)
            .arg("ca")
            .arg("token")
            .arg("alice")
            .arg("--ssh")
            .arg("--principal")
            .arg("alice")
            .arg("--not-after")
            .arg("5m")
            .arg("--cert-not-after")
            .arg("24h")
            .arg("--issuer")
            .arg("grafhome-user-616c696365-63612d686f7374")
            .arg("--key")
            .arg(temp.join("alice-ca-host.priv.json"))
            .arg("--password-file")
            .arg(password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run(Command::new("step")
        .env("STEPPATH", &client_steppath)
        .arg("ssh")
        .arg("certificate")
        .arg("alice")
        .arg(&user_public_key)
        .arg("--sign")
        .arg("--token")
        .arg(user_refresh_token.trim())
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--root")
        .arg(temp.join("step/certs/root_ca.crt"))
        .arg("--force")
        .arg("--no-agent"));
    assert!(user_cert.exists());

    let x509_token = token(
        Command::new("step")
            .env("STEPPATH", &client_steppath)
            .arg("ca")
            .arg("token")
            .arg("attacker.example")
            .arg("--issuer")
            .arg("grafhome-user-616c696365-63612d686f7374")
            .arg("--key")
            .arg(temp.join("alice-ca-host.priv.json"))
            .arg("--password-file")
            .arg(password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    run_fails(
        Command::new("step")
            .env("STEPPATH", &client_steppath)
            .arg("ca")
            .arg("certificate")
            .arg("attacker.example")
            .arg(temp.join("attacker.crt"))
            .arg(temp.join("attacker.key"))
            .arg("--token")
            .arg(x509_token.trim())
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt"))
            .arg("--force"),
    );

    let user_host_token = token(
        Command::new("step")
            .env("STEPPATH", &client_steppath)
            .arg("ca")
            .arg("token")
            .arg("user-owned-host")
            .arg("--ssh")
            .arg("--host")
            .arg("--principal")
            .arg("user-owned-host")
            .arg("--not-after")
            .arg("5m")
            .arg("--cert-not-after")
            .arg("24h")
            .arg("--issuer")
            .arg("grafhome-user-616c696365-63612d686f7374")
            .arg("--key")
            .arg(temp.join("alice-ca-host.priv.json"))
            .arg("--password-file")
            .arg(password)
            .arg("--ca-url")
            .arg(format!("https://{address}"))
            .arg("--root")
            .arg(temp.join("step/certs/root_ca.crt")),
    );
    let user_owned_host_key = temp.join("user-owned-host");
    run(Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&user_owned_host_key));
    let user_owned_host_cert = temp.join("user-owned-host-cert.pub");
    run(Command::new("step")
        .env("STEPPATH", &client_steppath)
        .arg("ssh")
        .arg("certificate")
        .arg("user-owned-host")
        .arg(user_owned_host_key.with_extension("pub"))
        .arg("--host")
        .arg("--sign")
        .arg("--token")
        .arg(user_host_token.trim())
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--root")
        .arg(temp.join("step/certs/root_ca.crt"))
        .arg("--force"));
    let cert_details = stdout(
        Command::new("ssh-keygen")
            .arg("-L")
            .arg("-f")
            .arg(&user_owned_host_cert),
    );
    assert!(cert_details.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"));
    assert!(cert_details.contains("Principals:"));
    assert!(cert_details.contains("alice"));
    assert!(!cert_details.contains("host certificate"));
}

fn add_test_user_client_provisioner(
    model: &grafhome_ca::model::SiteModel,
    temp: &std::path::Path,
    config_path: &std::path::Path,
    password: &std::path::Path,
) {
    let public_jwk = temp.join("alice-ca-host.pub.json");
    let private_jwk = temp.join("alice-ca-host.priv.json");
    run(Command::new("step")
        .arg("crypto")
        .arg("jwk")
        .arg("create")
        .arg(&public_jwk)
        .arg(&private_jwk)
        .arg("--password-file")
        .arg(password));
    let template = temp.join("alice-ca-host.tpl");
    std::fs::write(
        &template,
        r#"{
  "type": "user",
  "keyId": {{ toJson .KeyID }},
  "principals": ["alice"],
  "criticalOptions": {{ toJson .CriticalOptions }},
  "extensions": {{ toJson .Extensions }}
}
"#,
    )
    .unwrap();
    let text = grafhome_ca::runtime_provisioners::reconcile_user_client(
        model,
        config_path,
        &public_jwk,
        "grafhome-user-616c696365-63612d686f7374",
        template.to_str().unwrap(),
    )
    .unwrap();
    let config: serde_json::Value = serde_json::from_str(&text).unwrap();
    let provisioner = config["authority"]["provisioners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "grafhome-user-616c696365-63612d686f7374")
        .unwrap();
    assert!(provisioner["claims"]["defaultHostSSHCertDuration"].is_null());
    assert!(provisioner["claims"]["maxHostSSHCertDuration"].is_null());
    let user_enrollment = config["authority"]["provisioners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "grafhome-user-enrollment")
        .unwrap();
    assert_eq!(
        user_enrollment["claims"]["maxUserSSHCertDuration"],
        "2562047h"
    );
    std::fs::write(config_path, text).unwrap();
}

fn token(command: &mut Command) -> String {
    let debug = format!("{command:?}");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "token command failed: {debug}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn stdout(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn run_fails(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
