//! Lifecycle operation planning.
//!
//! Plans are structured, serializable descriptions of what an operation would
//! do. They are intentionally separate from command execution so tests can mock
//! behavior and operators can review actions before deployment code exists.

use serde::Serialize;

use crate::error::{Error, Result};
use crate::model::SiteModel;
use crate::policy::Host;

/// CA initialization operation key.
pub const OP_INIT_CA: &str = "init-ca";
/// First-time host bootstrap operation key.
pub const OP_HOST_BOOTSTRAP: &str = "host-bootstrap";
/// Single host certificate renewal operation key.
pub const OP_HOST_RENEW: &str = "host-renew";
/// Fleet host certificate renewal operation key.
pub const OP_HOST_RENEW_ALL: &str = "host-renew-all";
/// User certificate issuance operation key.
pub const OP_USER_LOGIN: &str = "user-login";
/// New host policy workflow operation key.
pub const OP_ADD_HOST: &str = "add-host";
/// New user policy workflow operation key.
pub const OP_ADD_USER: &str = "add-user";

/// Render deployment files step key.
pub const STEP_RENDER: &str = "render";
/// Initialize Smallstep mutable state step key.
pub const STEP_INITIALIZE_SMALLSTEP_STATE: &str = "initialize-smallstep-state";
/// Review runtime secret material step key.
pub const STEP_REVIEW_SECRETS: &str = "review-secrets";
/// Activate the step-ca service step key.
pub const STEP_ACTIVATE_SERVICE: &str = "activate-service";
/// Ensure client tooling exists step key.
pub const STEP_INSTALL_CLIENT: &str = "install-client";
/// Bootstrap CA trust step key.
pub const STEP_BOOTSTRAP_TRUST: &str = "bootstrap-trust";
/// Install rendered host files step key.
pub const STEP_INSTALL_RENDERED_FILES: &str = "install-rendered-files";
/// Renew one SSH host certificate step key.
pub const STEP_RENEW_HOST_CERT: &str = "renew-host-cert";
/// Issue one SSH user certificate step key.
pub const STEP_ISSUE_USER_CERT: &str = "issue-user-cert";
/// Edit policy tables step key.
pub const STEP_EDIT_POLICY: &str = "edit-policy";
/// Follow up with host bootstrap step key.
pub const STEP_BOOTSTRAP_HOST: &str = "bootstrap-host";

/// A lifecycle plan for one operator action.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Plan {
    /// Stable operation key.
    pub operation: String,
    /// Human-readable summary.
    pub summary: String,
    /// Ordered action steps.
    pub steps: Vec<PlanStep>,
}

/// One step in a lifecycle plan.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct PlanStep {
    /// Stable step key.
    pub id: String,
    /// What this step accomplishes.
    pub summary: String,
    /// Hosts where this step applies; empty means repo-local or operator-local.
    pub hosts: Vec<String>,
    /// Commands an operator or future executor would run.
    pub commands: Vec<String>,
    /// Site-rendered or host-local files involved in the step.
    pub files: Vec<String>,
    /// Whether this step needs explicit operator approval/input.
    pub manual: bool,
}

/// Plan CA initialization without executing it.
pub fn init_ca(model: &SiteModel) -> Result<Plan> {
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let ca_api = required_endpoint(model, "ca_api")?;
    Ok(Plan {
        operation: OP_INIT_CA.to_owned(),
        summary: format!(
            "initialize step-ca on {} and expose it through {}",
            ca_origin.target, ca_api.dns_name
        ),
        steps: vec![
            PlanStep {
                id: STEP_RENDER.to_owned(),
                summary: "render reviewed CA, systemd, Apache, SSH, and principals files".to_owned(),
                hosts: Vec::new(),
                commands: vec![format!(
                    "grafhome-ca render --out-dir <staging-dir> --config-root {}",
                    model.config_root.display()
                )],
                files: vec!["<staging-dir>/hosts/...".to_owned()],
                manual: false,
            },
            PlanStep {
                id: STEP_INITIALIZE_SMALLSTEP_STATE.to_owned(),
                summary: "initialize or import Smallstep CA state on the CA origin host".to_owned(),
                hosts: vec![ca_origin.target.clone()],
                commands: vec![
                    format!("install -d -m 0750 {}", model.deployment.ca_steppath()),
                    "step ca init --ssh --deployment-type standalone --name grafhome-ca".to_owned(),
                ],
                files: vec![
                    format!("{}/config/ca.json", model.deployment.ca_steppath()),
                    model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"].clone(),
                ],
                manual: true,
            },
            PlanStep {
                id: STEP_REVIEW_SECRETS.to_owned(),
                summary: "replace runtime provisioner placeholders with complete Smallstep-generated provisioner objects"
                    .to_owned(),
                hosts: vec![ca_origin.target.clone()],
                commands: vec!["step ca provisioner add ...".to_owned()],
                files: vec![format!("{}/config/ca.json", model.deployment.ca_steppath())],
                manual: true,
            },
            PlanStep {
                id: STEP_ACTIVATE_SERVICE.to_owned(),
                summary: "enable step-ca only after rendered config and secrets are reviewed".to_owned(),
                hosts: vec![ca_origin.target.clone()],
                commands: vec![
                    "systemctl daemon-reload".to_owned(),
                    "systemctl enable --now step-ca.service".to_owned(),
                ],
                files: vec!["/etc/systemd/system/step-ca.service".to_owned()],
                manual: true,
            },
        ],
    })
}

/// Plan host bootstrap without executing it.
pub fn host_bootstrap(model: &SiteModel, host: &str) -> Result<Plan> {
    let host = required_host(model, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    Ok(Plan {
        operation: OP_HOST_BOOTSTRAP.to_owned(),
        summary: format!("bootstrap {} for Grafhome SSH certificates", host.host),
        steps: vec![
            PlanStep {
                id: STEP_INSTALL_CLIENT.to_owned(),
                summary: "ensure step CLI and grafhome-ca helper are installed".to_owned(),
                hosts: vec![host.host.clone()],
                commands: vec![
                    "shdeps update step".to_owned(),
                    "shdeps update grafhome-ca".to_owned(),
                ],
                files: vec![model.deployment.values["GRAFHOME_CA_HELPER_BIN"].clone()],
                manual: false,
            },
            PlanStep {
                id: STEP_BOOTSTRAP_TRUST.to_owned(),
                summary: "bootstrap CA trust for the host root account".to_owned(),
                hosts: vec![host.host.clone()],
                commands: vec![format!(
                    "STEPPATH={} {} ca bootstrap --ca-url {} --fingerprint <root-fingerprint>",
                    model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"],
                    model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"],
                    ca_api.url()
                )],
                files: vec![model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"].clone()],
                manual: true,
            },
            PlanStep {
                id: STEP_INSTALL_RENDERED_FILES.to_owned(),
                summary: "install reviewed host-specific SSH and renewal config".to_owned(),
                hosts: vec![host.host.clone()],
                commands: vec![format!("install rendered files for host {}", host.host)],
                files: vec![format!("hosts/{}/...", host.host)],
                manual: true,
            },
        ],
    })
}

/// Plan host certificate renewal without executing it.
pub fn host_renew(model: &SiteModel, host: &str) -> Result<Plan> {
    let host = required_host(model, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let provisioner = required_provisioner(model, "host_renew")?;
    let ca_url = ca_api.url();
    let host_cert = host_cert_path(model);
    Ok(Plan {
        operation: OP_HOST_RENEW.to_owned(),
        summary: format!("renew SSH host certificate for {}", host.host),
        steps: vec![PlanStep {
            id: STEP_RENEW_HOST_CERT.to_owned(),
            summary: "renew host SSH certificate through Smallstep SSHPOP".to_owned(),
            hosts: vec![host.host.clone()],
            commands: vec![host_renew_command(model, &ca_url, &provisioner.name)],
            files: vec![host_cert],
            manual: host.renewal_owner == "manual",
        }],
    })
}

/// Plan certificate renewal for every host with an SSH server and renewal owner.
pub fn host_renew_all(model: &SiteModel) -> Result<Plan> {
    let ca_api = required_endpoint(model, "ca_api")?;
    let provisioner = required_provisioner(model, "host_renew")?;
    let ca_url = ca_api.url();
    let host_cert = host_cert_path(model);
    let steps = renewable_hosts(model)
        .map(|host| PlanStep {
            id: STEP_RENEW_HOST_CERT.to_owned(),
            summary: format!("renew SSH host certificate on {}", host.host),
            hosts: vec![host.host.clone()],
            commands: vec![host_renew_command(model, &ca_url, &provisioner.name)],
            files: vec![host_cert.clone()],
            manual: host.renewal_owner == "manual",
        })
        .collect::<Vec<_>>();

    Ok(Plan {
        operation: OP_HOST_RENEW_ALL.to_owned(),
        summary: format!(
            "renew SSH host certificates for {} managed hosts",
            steps.len()
        ),
        steps,
    })
}

/// Plan user certificate issuance without executing it.
pub fn user_login(model: &SiteModel, user: &str, device: Option<&str>) -> Result<Plan> {
    let user = model.policy.user(user).ok_or_else(|| Error::Validation {
        field: format!("policy/users.tsv:{user}"),
        message: "unknown user".to_owned(),
    })?;
    if user.status != "active" {
        return Err(Error::Validation {
            field: format!("policy/users.tsv:{}.status", user.user),
            message: "user must be active for certificate issuance".to_owned(),
        });
    }
    let ca_api = required_endpoint(model, "ca_api")?;
    let devices = select_user_login_devices(model, &user.user, device)?;
    let user_steppath = format!("~/{}", model.deployment.values["GRAFHOME_CA_USER_STEPPATH"]);
    let commands = devices
        .iter()
        .map(|device| {
            let public_key = user_public_key_path(&device.key_name);
            format!(
                "STEPPATH={} step ssh certificate --ca-url {} --provisioner {} --sign --principal {} --not-after {} {} {}",
                user_steppath,
                ca_api.url(),
                user.provisioner,
                user.principal,
                user.cert_ttl,
                user.principal,
                public_key
            )
        })
        .collect::<Vec<_>>();
    let mut files = Vec::new();
    for device in devices {
        files.push(user_public_key_path(&device.key_name));
        files.push(user_cert_path(&device.key_name));
    }
    Ok(Plan {
        operation: OP_USER_LOGIN.to_owned(),
        summary: format!("issue short-lived SSH user certificate for {}", user.user),
        steps: vec![PlanStep {
            id: STEP_ISSUE_USER_CERT.to_owned(),
            summary: "request a fresh user SSH certificate for an existing local key".to_owned(),
            hosts: Vec::new(),
            commands,
            files,
            manual: true,
        }],
    })
}

/// Plan policy updates needed for a new host.
pub fn add_host(model: &SiteModel, host: &str) -> Result<Plan> {
    if model.policy.host(host).is_some() {
        return Err(Error::Validation {
            field: format!("policy/hosts.tsv:{host}"),
            message: "host already exists".to_owned(),
        });
    }
    Ok(Plan {
        operation: OP_ADD_HOST.to_owned(),
        summary: format!("add new host {host} to Grafhome CA policy"),
        steps: vec![
            PlanStep {
                id: STEP_EDIT_POLICY.to_owned(),
                summary: "add host, principal, user-host, and emergency access rows".to_owned(),
                hosts: Vec::new(),
                commands: vec![
                    "edit policy/*.tsv".to_owned(),
                    "grafhome-ca check".to_owned(),
                ],
                files: vec![
                    "policy/hosts.tsv".to_owned(),
                    "policy/principals.tsv".to_owned(),
                    "policy/user-hosts.tsv".to_owned(),
                    "policy/emergency-access.tsv".to_owned(),
                ],
                manual: true,
            },
            PlanStep {
                id: STEP_BOOTSTRAP_HOST.to_owned(),
                summary: "run host-bootstrap plan after policy is merged".to_owned(),
                hosts: vec![host.to_owned()],
                commands: vec![format!("grafhome-ca plan host-bootstrap --host {host}")],
                files: vec![],
                manual: true,
            },
        ],
    })
}

/// Plan policy updates needed for a new user.
pub fn add_user(model: &SiteModel, user: &str) -> Result<Plan> {
    reject_root_user_arg(user)?;
    if model.policy.user(user).is_some() {
        return Err(Error::Validation {
            field: format!("policy/users.tsv:{user}"),
            message: "user already exists".to_owned(),
        });
    }
    Ok(Plan {
        operation: OP_ADD_USER.to_owned(),
        summary: format!("add new user {user} to Grafhome CA policy"),
        steps: vec![
            PlanStep {
                id: STEP_EDIT_POLICY.to_owned(),
                summary: "add user, principal, client-device, and user-host rows".to_owned(),
                hosts: Vec::new(),
                commands: vec![
                    "edit policy/*.tsv".to_owned(),
                    "grafhome-ca check".to_owned(),
                ],
                files: vec![
                    "policy/users.tsv".to_owned(),
                    "policy/principals.tsv".to_owned(),
                    "policy/client-devices.tsv".to_owned(),
                    "policy/user-hosts.tsv".to_owned(),
                ],
                manual: true,
            },
            PlanStep {
                id: STEP_ISSUE_USER_CERT.to_owned(),
                summary: "issue a user cert after policy is merged and reviewed".to_owned(),
                hosts: Vec::new(),
                commands: vec![format!(
                    "grafhome-ca plan user-login --user {user} --device <device>"
                )],
                files: vec![],
                manual: true,
            },
        ],
    })
}

fn renewable_hosts(model: &SiteModel) -> impl Iterator<Item = &Host> {
    model
        .policy
        .hosts
        .iter()
        .filter(|host| host.ssh_server == "yes" && host.renewal_owner != "none")
}

fn select_user_login_devices<'a>(
    model: &'a SiteModel,
    user: &str,
    device: Option<&str>,
) -> Result<Vec<&'a crate::policy::ClientDevice>> {
    let devices = model
        .policy
        .active_client_devices_for_user(user)
        .collect::<Vec<_>>();
    if let Some(device) = device {
        return devices
            .into_iter()
            .find(|entry| entry.device == device)
            .map(|entry| vec![entry])
            .ok_or_else(|| Error::Validation {
                field: format!("policy/client-devices.tsv:{device}"),
                message: format!("no active client device {device} for user {user}"),
            });
    }
    match devices.len() {
        0 => Err(Error::Validation {
            field: format!("policy/client-devices.tsv:{user}"),
            message: "user has no active client devices".to_owned(),
        }),
        1 => Ok(devices),
        _ => Err(Error::Validation {
            field: format!("policy/client-devices.tsv:{user}"),
            message: "multiple active client devices; pass --device".to_owned(),
        }),
    }
}

fn host_renew_command(model: &SiteModel, ca_url: &str, provisioner: &str) -> String {
    let host_key = &model.deployment.values["GRAFHOME_CA_HOST_KEY_PATH"];
    let host_cert = host_cert_path(model);
    format!(
        "STEPPATH={} {} ssh renew --ca-url {} --provisioner {} {} {}",
        model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"],
        model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"],
        ca_url,
        provisioner,
        host_cert,
        host_key
    )
}

fn host_cert_path(model: &SiteModel) -> String {
    format!(
        "{}-cert.pub",
        model.deployment.values["GRAFHOME_CA_HOST_KEY_PATH"]
    )
}

fn user_public_key_path(key_name: &str) -> String {
    format!("~/.ssh/{key_name}.pub")
}

fn user_cert_path(key_name: &str) -> String {
    format!("~/.ssh/{key_name}-cert.pub")
}

fn reject_root_user_arg(user: &str) -> Result<()> {
    if user == "root" {
        Err(Error::Validation {
            field: "policy/users.tsv:root".to_owned(),
            message: "root SSH identities are not supported".to_owned(),
        })
    } else {
        Ok(())
    }
}

fn required_endpoint<'a>(model: &'a SiteModel, role: &str) -> Result<&'a crate::policy::Endpoint> {
    model
        .policy
        .endpoint(role)
        .ok_or_else(|| Error::Validation {
            field: format!("policy/endpoints.tsv:{role}"),
            message: "missing required endpoint".to_owned(),
        })
}

fn required_host<'a>(model: &'a SiteModel, host: &str) -> Result<&'a crate::policy::Host> {
    model.policy.host(host).ok_or_else(|| Error::Validation {
        field: format!("policy/hosts.tsv:{host}"),
        message: "unknown host".to_owned(),
    })
}

fn required_provisioner<'a>(
    model: &'a SiteModel,
    role: &str,
) -> Result<&'a crate::policy::Provisioner> {
    model
        .policy
        .provisioners
        .iter()
        .find(|provisioner| provisioner.role == role && provisioner.status == "active")
        .ok_or_else(|| Error::Validation {
            field: format!("policy/provisioners.tsv:{role}"),
            message: "missing active provisioner".to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::{
        OP_ADD_HOST, OP_ADD_USER, OP_HOST_BOOTSTRAP, OP_HOST_RENEW, OP_HOST_RENEW_ALL, OP_INIT_CA,
        OP_USER_LOGIN, STEP_ACTIVATE_SERVICE, STEP_BOOTSTRAP_HOST, STEP_BOOTSTRAP_TRUST,
        STEP_EDIT_POLICY, STEP_INITIALIZE_SMALLSTEP_STATE, STEP_INSTALL_CLIENT,
        STEP_INSTALL_RENDERED_FILES, STEP_ISSUE_USER_CERT, STEP_RENDER, STEP_RENEW_HOST_CERT,
        STEP_REVIEW_SECRETS, add_host, add_user, host_bootstrap, host_renew, host_renew_all,
        init_ca, renewable_hosts, user_login,
    };

    #[test]
    fn plans_init_ca_with_manual_mutation_gates() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = init_ca(&model).unwrap();

        assert_eq!(plan.operation, OP_INIT_CA);
        assert_eq!(
            step_ids(&plan),
            vec![
                STEP_RENDER,
                STEP_INITIALIZE_SMALLSTEP_STATE,
                STEP_REVIEW_SECRETS,
                STEP_ACTIVATE_SERVICE
            ]
        );
        assert!(!plan.steps[0].manual);
        assert!(plan.steps[1..].iter().all(|step| step.manual));
        assert_eq!(plan.steps[1].hosts, vec!["ca-host".to_owned()]);
        assert!(plan.steps[2].commands[0].contains("step ca provisioner add"));
        assert!(plan.steps[3].commands[1].contains("systemctl enable --now step-ca.service"));
    }

    #[test]
    fn plans_host_bootstrap_with_targeted_manual_trust_steps() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = host_bootstrap(&model, "proxy-host").unwrap();

        assert_eq!(plan.operation, OP_HOST_BOOTSTRAP);
        assert_eq!(
            step_ids(&plan),
            vec![
                STEP_INSTALL_CLIENT,
                STEP_BOOTSTRAP_TRUST,
                STEP_INSTALL_RENDERED_FILES
            ]
        );
        assert!(
            plan.steps
                .iter()
                .all(|step| step.hosts == vec!["proxy-host".to_owned()])
        );
        assert!(!plan.steps[0].manual);
        assert!(plan.steps[1].manual);
        assert!(plan.steps[1].commands[0].contains("ca bootstrap"));
        assert!(plan.steps[1].commands[0].contains("https://ca.example.test"));
        assert!(plan.steps[1].commands[0].contains("STEPPATH=/etc/step/grafhome"));
    }

    #[test]
    fn plans_single_host_renewal_as_non_manual_local_step() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = host_renew(&model, "edge-host").unwrap();

        assert_eq!(plan.operation, OP_HOST_RENEW);
        assert_eq!(step_ids(&plan), vec![STEP_RENEW_HOST_CERT]);
        assert_eq!(plan.steps[0].hosts, vec!["edge-host".to_owned()]);
        assert!(!plan.steps[0].manual);
        assert!(plan.steps[0].commands[0].contains("step ssh renew"));
        assert!(plan.steps[0].commands[0].contains("--provisioner grafhome-host-renew"));
        assert!(plan.steps[0].commands[0].contains("STEPPATH=/etc/step/grafhome"));
        assert!(plan.steps[0].commands[0].contains("/etc/ssh/ssh_host_ed25519_key-cert.pub"));
    }

    #[test]
    fn plans_all_host_renewals_for_managed_ssh_servers() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = host_renew_all(&model).unwrap();
        let hosts = plan
            .steps
            .iter()
            .map(|step| step.hosts[0].as_str())
            .collect::<Vec<_>>();

        assert_eq!(plan.operation, OP_HOST_RENEW_ALL);
        assert_eq!(
            hosts,
            vec!["ca-host", "proxy-host", "edge-host", "laptop-a"]
        );
        assert!(
            renewable_hosts(&model)
                .all(|host| host.renewal_owner == "systemd" || host.renewal_owner == "dot-cron")
        );
        assert!(plan.steps.iter().all(|step| !step.manual));
        assert!(
            plan.steps
                .iter()
                .all(|step| step.id == STEP_RENEW_HOST_CERT)
        );
        assert!(
            plan.steps
                .iter()
                .all(|step| step.commands[0].contains("--ca-url https://ca.example.test"))
        );
    }

    #[test]
    fn host_renew_all_preserves_manual_renewal_owner_gate() {
        let mut model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        model
            .policy
            .hosts
            .iter_mut()
            .find(|host| host.host == "laptop-a")
            .unwrap()
            .renewal_owner = "manual".to_owned();
        let plan = host_renew_all(&model).unwrap();
        let laptop = plan
            .steps
            .iter()
            .find(|step| step.hosts == vec!["laptop-a".to_owned()])
            .unwrap();

        assert!(laptop.manual);
    }

    #[test]
    fn plans_user_login_without_running_step() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = user_login(&model, "alice", Some("ca-host")).unwrap();

        assert_eq!(plan.operation, OP_USER_LOGIN);
        assert_eq!(step_ids(&plan), vec![STEP_ISSUE_USER_CERT]);
        assert!(plan.steps[0].hosts.is_empty());
        assert!(plan.steps[0].manual);
        assert!(plan.steps[0].commands[0].contains("step ssh certificate"));
        assert!(plan.steps[0].commands[0].contains("--sign"));
        assert!(plan.steps[0].commands[0].contains("--provisioner grafhome-user-login"));
        assert!(plan.steps[0].commands[0].contains("STEPPATH=~/.config/grafhome/step"));
        assert!(
            plan.steps[0]
                .commands
                .iter()
                .any(|command| command.contains("~/.ssh/alice_ca_host_ed25519.pub"))
        );
        assert!(
            plan.steps[0]
                .files
                .contains(&"~/.ssh/alice_ca_host_ed25519-cert.pub".to_owned())
        );
    }

    #[test]
    fn user_login_plan_requires_device_for_multi_device_users() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let error = user_login(&model, "alice", None).unwrap_err().to_string();

        assert!(error.contains("multiple active client devices"));
    }

    #[test]
    fn user_login_plan_rejects_unknown_device() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let error = user_login(&model, "alice", Some("missing"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("no active client device missing"));
    }

    #[test]
    fn user_login_plan_rejects_disabled_user() {
        let mut model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        model
            .policy
            .users
            .iter_mut()
            .find(|user| user.user == "alice")
            .unwrap()
            .status = "disabled".to_owned();
        let error = user_login(&model, "alice", Some("ca-host"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("user must be active"));
    }

    #[test]
    fn rejects_unknown_host_plan() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let error = host_bootstrap(&model, "missing").unwrap_err().to_string();

        assert!(error.contains("unknown host"));
    }

    #[test]
    fn add_host_plan_refuses_existing_hosts() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let error = add_host(&model, "ca-host").unwrap_err().to_string();

        assert!(error.contains("host already exists"));
    }

    #[test]
    fn plans_new_host_policy_workflow() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = add_host(&model, "new-host").unwrap();

        assert_eq!(plan.operation, OP_ADD_HOST);
        assert_eq!(step_ids(&plan), vec![STEP_EDIT_POLICY, STEP_BOOTSTRAP_HOST]);
        assert!(plan.steps[0].files.contains(&"policy/hosts.tsv".to_owned()));
        assert!(
            plan.steps[0]
                .files
                .contains(&"policy/user-hosts.tsv".to_owned())
        );
        assert_eq!(plan.steps[1].hosts, vec!["new-host".to_owned()]);
        assert_eq!(
            plan.steps[1].commands,
            vec!["grafhome-ca plan host-bootstrap --host new-host"]
        );
    }

    #[test]
    fn plans_new_user_policy_workflow() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = add_user(&model, "new-user").unwrap();

        assert_eq!(plan.operation, OP_ADD_USER);
        assert_eq!(
            step_ids(&plan),
            vec![STEP_EDIT_POLICY, STEP_ISSUE_USER_CERT]
        );
        assert!(plan.steps[0].files.contains(&"policy/users.tsv".to_owned()));
        assert!(
            plan.steps[0]
                .files
                .contains(&"policy/principals.tsv".to_owned())
        );
        assert!(plan.steps[1].hosts.is_empty());
        assert_eq!(
            plan.steps[1].commands,
            vec!["grafhome-ca plan user-login --user new-user --device <device>"]
        );
    }

    #[test]
    fn add_user_plan_refuses_root_user() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let error = add_user(&model, "root").unwrap_err().to_string();

        assert!(error.contains("root SSH identities are not supported"));
    }

    #[test]
    fn add_user_plan_refuses_existing_users() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let error = add_user(&model, "alice").unwrap_err().to_string();

        assert!(error.contains("user already exists"));
    }

    fn step_ids(plan: &super::Plan) -> Vec<&str> {
        plan.steps.iter().map(|step| step.id.as_str()).collect()
    }
}
