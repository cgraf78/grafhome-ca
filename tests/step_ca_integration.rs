use std::collections::BTreeMap;
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
    run(Command::new("step")
        .env("STEPPATH", &steppath)
        .arg("ca")
        .arg("provisioner")
        .arg("add")
        .arg("grafhome-user-login")
        .arg("--type")
        .arg("JWK")
        .arg("--create")
        .arg("--ca-config")
        .arg(steppath.join("config/ca.json"))
        .arg("--password-file")
        .arg(&password));
    run(Command::new("step")
        .env("STEPPATH", &steppath)
        .arg("ca")
        .arg("provisioner")
        .arg("add")
        .arg("grafhome-host-renew")
        .arg("--type")
        .arg("SSHPOP")
        .arg("--ca-config")
        .arg(steppath.join("config/ca.json")));
    run(Command::new("step")
        .env("STEPPATH", &steppath)
        .arg("ca")
        .arg("provisioner")
        .arg("add")
        .arg("grafhome-x509-ca-proxy")
        .arg("--type")
        .arg("ACME")
        .arg("--ca-config")
        .arg(steppath.join("config/ca.json")));

    let config_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site-config");
    let model = grafhome_ca::model::SiteModel::load(config_root).unwrap();
    let rendered = grafhome_ca::render::render(&model).unwrap();
    let ca_json = rendered
        .iter()
        .find(|file| file.path.ends_with("step/config/ca.json"))
        .unwrap();
    let generated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(steppath.join("config/ca.json")).unwrap())
            .unwrap();
    let generated_provisioners = generated["authority"]["provisioners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| (item["name"].as_str().unwrap().to_owned(), item.clone()))
        .collect::<BTreeMap<_, _>>();
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
    materialize_runtime_provisioners(&mut config, &generated_provisioners, &model);
    std::fs::create_dir_all(temp.path().join("step/valuedb")).unwrap();

    let config_path = steppath.join("config/rendered-ca.json");
    std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
    let child = Command::new("step-ca")
        .arg(&config_path)
        .arg("--password-file")
        .arg(&password)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = StepCaChild::new(child);
    wait_for_health(
        child.as_mut(),
        config["address"].as_str().unwrap(),
        &steppath,
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

fn materialize_runtime_provisioners(
    config: &mut serde_json::Value,
    generated: &BTreeMap<String, serde_json::Value>,
    model: &grafhome_ca::model::SiteModel,
) {
    let provisioners = config["authority"]["provisioners"].as_array_mut().unwrap();
    for item in provisioners {
        let Some(placeholder) = item.as_str() else {
            continue;
        };
        let name = match placeholder {
            "RUNTIME_SECRET_PLACEHOLDER:GRAFHOME_CA_PROVISIONER_GRAFHOME_HOST_BOOTSTRAP_JSON" => {
                "grafhome-host-bootstrap"
            }
            "RUNTIME_SECRET_PLACEHOLDER:GRAFHOME_CA_PROVISIONER_GRAFHOME_USER_LOGIN_JSON" => {
                "grafhome-user-login"
            }
            other => panic!("unexpected runtime placeholder {other}"),
        };
        let mut replacement = generated.get(name).unwrap().clone();
        replacement["claims"] = grafhome_ca::render::active_provisioner_claims(model, name)
            .expect("active policy provisioner claims render");
        *item = replacement;
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
