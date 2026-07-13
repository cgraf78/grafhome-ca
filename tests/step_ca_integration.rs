use std::net::TcpListener;
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
    let jwk_dir = temp.path().join("provisioners");
    std::fs::create_dir(&jwk_dir).unwrap();
    run(Command::new("step")
        .arg("crypto")
        .arg("jwk")
        .arg("create")
        .arg(jwk_dir.join("grafhome-user-enrollment.pub.json"))
        .arg(jwk_dir.join("grafhome-user-enrollment.priv.json"))
        .arg("--password-file")
        .arg(&password));
    let materialized = grafhome_ca::runtime_provisioners::materialize(
        &model,
        steppath.join("config/ca.json"),
        &staged_ca_json,
        &jwk_dir,
    )
    .unwrap();
    let mut config: serde_json::Value = serde_json::from_str(&materialized).unwrap();
    let user_enrollment = config["authority"]["provisioners"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|item| item["name"] == "grafhome-user-enrollment")
        .unwrap();
    user_enrollment["claims"]["defaultUserSSHCertDuration"] = serde_json::json!("12h");
    user_enrollment["claims"]["maxUserSSHCertDuration"] = serde_json::json!("168h");
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
        assert_long_user_enrollment_rejected(
            temp.path(),
            config["address"].as_str().unwrap(),
            &password,
        );
    }
    add_test_user_client_provisioner(&model, temp.path(), &config_path, &password);
    let mut child = start_step_ca(&config_path, &password);
    wait_for_health(
        child.as_mut(),
        config["address"].as_str().unwrap(),
        &steppath,
    );
    exercise_public_export_and_host_certificate_lifecycle(
        &model,
        temp.path(),
        config["address"].as_str().unwrap(),
        &password,
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
            .arg("--provisioner")
            .arg("grafhome-user-enrollment")
            .arg("--provisioner-password-file")
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

fn exercise_public_export_and_host_certificate_lifecycle(
    model: &grafhome_ca::model::SiteModel,
    temp: &std::path::Path,
    address: &str,
    password: &std::path::Path,
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
            .arg("--provisioner")
            .arg("grafhome-host-bootstrap")
            .arg("--provisioner-password-file")
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
            .arg("--provisioner")
            .arg("grafhome-user-enrollment")
            .arg("--provisioner-password-file")
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
        .arg(user_enrollment_token.trim())
        .arg("--ca-url")
        .arg(format!("https://{address}"))
        .arg("--root")
        .arg(temp.join("step/certs/root_ca.crt"))
        .arg("--force")
        .arg("--no-agent"));
    assert!(user_cert.exists());

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
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "token command failed\nstdout:\n{}\nstderr:\n{}",
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
