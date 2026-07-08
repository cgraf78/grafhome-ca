//! Lifecycle operation planning.
//!
//! Plans are structured, serializable descriptions of what an operation would
//! do. They are intentionally separate from command execution so tests can mock
//! behavior and operators can review actions before deployment code exists.

use std::path::PathBuf;

use serde::Serialize;

use crate::policy::Host;
use crate::render::RenderedFile;
use crate::{
    error::{Error, Result},
    model::SiteModel,
};

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
/// Export public CA trust material step key.
pub const STEP_EXPORT_PUBLIC_MATERIAL: &str = "export-public-material";
/// Activate the step-ca service step key.
pub const STEP_ACTIVATE_SERVICE: &str = "activate-service";
/// Ensure client tooling exists step key.
pub const STEP_INSTALL_CLIENT: &str = "install-client";
/// Bootstrap CA trust step key.
pub const STEP_BOOTSTRAP_TRUST: &str = "bootstrap-trust";
/// Install rendered host files step key.
pub const STEP_INSTALL_RENDERED_FILES: &str = "install-rendered-files";
/// Issue the first SSH host certificate step key.
pub const STEP_ISSUE_HOST_CERT: &str = "issue-host-cert";
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
    let bootstrap = required_provisioner(model, "host_bootstrap")?;
    let provisioner_review_commands =
        runtime_provisioner_review_commands(model, &ca_origin.target, &bootstrap.name);
    let install_steps = rendered_install_steps(model, &[&ca_origin.target, &ca_api.target])?;
    let install_hosts = unique_hosts([ca_origin.target.clone(), ca_api.target.clone()]);
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
                    "grafhome-ca render --out-dir {} --config-root {}",
                    sh("<staging-dir>"),
                    sh_display(&model.config_root)
                )],
                files: vec!["<staging-dir>/hosts/...".to_owned()],
                manual: false,
            },
            PlanStep {
                id: STEP_INITIALIZE_SMALLSTEP_STATE.to_owned(),
                summary: "initialize or import Smallstep CA state on the CA origin host".to_owned(),
                hosts: vec![ca_origin.target.clone()],
                commands: vec![
                    format!(
                        "install -d -m 0750 {} {}",
                        sh(&model.deployment.ca_steppath()),
                        sh(&parent_dir(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"])),
                    ),
                    format!(
                        "umask 077; test -s {} || {} crypto rand --format ascii 48 > {}",
                        sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
                        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                        sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
                    ),
                    format!(
                        "STEPPATH={} {} ca init --ssh --deployment-type standalone --name grafhome-ca --dns {} --dns {} --address {} --with-ca-url {} --provisioner {} --password-file {} --provisioner-password-file {}",
                        sh(&model.deployment.ca_steppath()),
                        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                        sh(&ca_api.dns_name),
                        sh(&ca_origin.dns_name),
                        sh(&format!("{}:{}", ca_origin.address, ca_origin.port)),
                        sh(&ca_api.url()),
                        sh(&bootstrap.name),
                        sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
                        sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
                    ),
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
                commands: provisioner_review_commands,
                files: vec![
                    format!("{}/config/ca.json", model.deployment.ca_steppath()),
                    staged_ca_config_path(model, &ca_origin.target),
                ],
                manual: true,
            },
            PlanStep {
                id: STEP_INSTALL_RENDERED_FILES.to_owned(),
                summary: "install reviewed rendered files for the CA origin and proxy hosts"
                    .to_owned(),
                hosts: install_hosts,
                commands: install_steps,
                files: vec![
                    format!("<staging-dir>/hosts/{}/...", ca_origin.target),
                    format!("<staging-dir>/hosts/{}/...", ca_api.target),
                ],
                manual: true,
            },
            PlanStep {
                id: STEP_EXPORT_PUBLIC_MATERIAL.to_owned(),
                summary: "export root fingerprint and SSH CA public keys for rollout".to_owned(),
                hosts: vec![ca_origin.target.clone()],
                commands: vec![format!(
                    "grafhome-ca export-public --out-dir {} --config-root {}",
                    sh("<public-material-dir>"),
                    sh_display(&model.config_root)
                )],
                files: vec![
                    "<public-material-dir>/root_fingerprint".to_owned(),
                    "<public-material-dir>/user_ca_keys.pem".to_owned(),
                    "<public-material-dir>/ssh_known_hosts".to_owned(),
                    "<public-material-dir>/manifest.json".to_owned(),
                ],
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
    let bootstrap = required_provisioner(model, "host_bootstrap")?;
    let mut steps = vec![
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
                "STEPPATH={} {} ca bootstrap --ca-url {} --fingerprint \"$(cat {})\"",
                sh(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
                sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                sh(&ca_api.url()),
                sh("<public-material-dir>/root_fingerprint")
            )],
            files: vec![
                model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"].clone(),
                "<public-material-dir>/root_fingerprint".to_owned(),
            ],
            manual: true,
        },
    ];
    if host.ssh_server == "yes" {
        steps.push(PlanStep {
            id: STEP_ISSUE_HOST_CERT.to_owned(),
            summary: "issue the initial SSH host certificate before enabling HostCertificate"
                .to_owned(),
            hosts: vec![host.host.clone()],
            commands: vec![host_certificate_command(
                model,
                host,
                &ca_api.url(),
                &bootstrap.name,
                &bootstrap.default_ttl,
            )],
            files: vec![host_public_key_path(model), host_cert_path(model)],
            manual: true,
        });
    }
    let install_commands = host_bootstrap_install_steps(model, host)?;
    steps.push(PlanStep {
        id: STEP_INSTALL_RENDERED_FILES.to_owned(),
        summary: "install reviewed host-specific SSH config and public trust files".to_owned(),
        hosts: vec![host.host.clone()],
        commands: install_commands,
        files: vec![
            format!("hosts/{}/...", host.host),
            "<public-material-dir>/user_ca_keys.pem".to_owned(),
            "<public-material-dir>/ssh_known_hosts".to_owned(),
        ],
        manual: true,
    });
    Ok(Plan {
        operation: OP_HOST_BOOTSTRAP.to_owned(),
        summary: format!("bootstrap {} for Grafhome SSH certificates", host.host),
        steps,
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
    let user_steppath = format!(
        "$HOME/{}",
        model.deployment.values["GRAFHOME_CA_USER_STEPPATH"]
    );
    let commands = devices
        .iter()
        .map(|device| {
            let public_key = user_public_key_path(&device.key_name);
            format!(
                "STEPPATH={} step ssh certificate --ca-url {} --provisioner {} --provisioner-password-file {} --sign --principal {} --not-after {} {} {}",
                user_steppath,
                sh(&ca_api.url()),
                sh(&user.provisioner),
                sh("<user-login-provisioner-password-file>"),
                sh(&user.principal),
                sh(&user.cert_ttl),
                sh(&user.principal),
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
                commands: vec![format!(
                    "grafhome-ca plan host-bootstrap --host {}",
                    sh(host)
                )],
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
                    "grafhome-ca plan user-login --user {} --device {}",
                    sh(user),
                    sh("<device>")
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
        sh(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
        sh(ca_url),
        sh(provisioner),
        sh(&host_cert),
        sh(host_key)
    )
}

fn host_certificate_command(
    model: &SiteModel,
    host: &Host,
    ca_url: &str,
    provisioner: &str,
    ttl: &str,
) -> String {
    let principal_args = host
        .principals
        .split(',')
        .map(str::trim)
        .filter(|principal| !principal.is_empty())
        .map(|principal| format!("--principal {}", sh(principal)))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "STEPPATH={} {} ssh certificate --ca-url {} --provisioner {} --provisioner-password-file {} --host --sign --force {} --not-after {} {} {}",
        sh(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
        sh(ca_url),
        sh(provisioner),
        sh("<host-bootstrap-provisioner-password-file>"),
        principal_args,
        sh(ttl),
        sh(&host.host),
        sh(&host_public_key_path(model))
    )
}

fn host_cert_path(model: &SiteModel) -> String {
    format!(
        "{}-cert.pub",
        model.deployment.values["GRAFHOME_CA_HOST_KEY_PATH"]
    )
}

fn host_public_key_path(model: &SiteModel) -> String {
    format!(
        "{}.pub",
        model.deployment.values["GRAFHOME_CA_HOST_KEY_PATH"]
    )
}

fn rendered_install_steps(model: &SiteModel, hosts: &[&str]) -> Result<Vec<String>> {
    rendered_install_steps_filtered(model, hosts, |_| true)
}

fn host_bootstrap_install_steps(model: &SiteModel, host: &Host) -> Result<Vec<String>> {
    let mut commands = Vec::new();
    if host.ssh_server == "yes" {
        commands.push(install_public_material_command(
            "user_ca_keys.pem",
            &absolute_deployment_child(model, "GRAFHOME_CA_SSH_TRUST_DIR", "user_ca_keys.pem")?,
        ));
    }
    if host.ssh_client == "yes" {
        commands.push(install_public_material_command(
            "ssh_known_hosts",
            &absolute_deployment_child(model, "GRAFHOME_CA_SSH_TRUST_DIR", "ssh_known_hosts")?,
        ));
    }

    commands.extend(rendered_install_steps_filtered(
        model,
        &[&host.host],
        |file| !is_public_trust_placeholder(file),
    )?);
    Ok(commands)
}

fn rendered_install_steps_filtered(
    model: &SiteModel,
    hosts: &[&str],
    keep: impl Fn(&RenderedFile) -> bool,
) -> Result<Vec<String>> {
    let mut commands = crate::render::render(model)?
        .into_iter()
        .filter(|file| keep(file))
        .filter_map(|file| {
            let (host, target) = rendered_target(&file)?;
            if !hosts.iter().any(|expected| *expected == host) {
                return None;
            }
            Some(rendered_install_command(&file, &target))
        })
        .collect::<Vec<_>>();
    commands.sort();
    commands.dedup();
    Ok(commands)
}

fn rendered_target(file: &RenderedFile) -> Option<(String, String)> {
    let mut components = file.path.components();
    let first = components.next()?.as_os_str().to_string_lossy();
    let host = components.next()?.as_os_str().to_string_lossy();
    if first != "hosts" {
        return None;
    }
    let target = components
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    Some((host.to_string(), format!("/{target}")))
}

fn rendered_install_command(file: &RenderedFile, target: &str) -> String {
    format!(
        "install -D -m {:04o} {} {}",
        file.mode,
        sh(&format!("<staging-dir>/{}", file.path.display())),
        sh(target)
    )
}

fn is_public_trust_placeholder(file: &RenderedFile) -> bool {
    let Some((_, target)) = rendered_target(file) else {
        return false;
    };
    target.ends_with("/user_ca_keys.pem") || target.ends_with("/ssh_known_hosts")
}

fn install_public_material_command(file_name: &str, target: &str) -> String {
    format!(
        "install -D -m 0644 {} {}",
        sh(&format!("<public-material-dir>/{file_name}")),
        sh(target)
    )
}

fn absolute_deployment_child(model: &SiteModel, key: &str, child: &str) -> Result<String> {
    let base = &model.deployment.values[key];
    let path = PathBuf::from(base).join(child);
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Validation {
            field: format!("config/deployment.env:{key}"),
            message: "path is not valid UTF-8".to_owned(),
        })
}

fn runtime_provisioner_review_commands(
    model: &SiteModel,
    ca_host: &str,
    bootstrap_provisioner: &str,
) -> Vec<String> {
    let ca_config = format!("{}/config/ca.json", model.deployment.ca_steppath());
    let staged_ca_config = staged_ca_config_path(model, ca_host);
    let password_file = &model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"];
    let step_bin = &model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"];
    let mut commands = Vec::new();

    for provisioner in model
        .policy
        .provisioners
        .iter()
        .filter(|entry| entry.status == "active" && entry.r#type == "JWK")
        .filter(|entry| entry.name != bootstrap_provisioner)
    {
        commands.push(format!(
            "STEPPATH={} {} ca provisioner add {} --type JWK --create --ca-config {} --password-file {}",
            sh(&model.deployment.ca_steppath()),
            sh(step_bin),
            sh(&provisioner.name),
            sh(&ca_config),
            sh(password_file)
        ));
    }

    for provisioner in model
        .policy
        .provisioners
        .iter()
        .filter(|entry| entry.status == "active" && entry.r#type == "JWK")
    {
        commands.push(format!(
            "copy authority.provisioners entry named {} from {} into {} at \"{}\"",
            sh(&provisioner.name),
            sh(&ca_config),
            sh(&staged_ca_config),
            crate::render::provisioner_placeholder(&provisioner.name)
        ));
    }

    commands
}

fn staged_ca_config_path(model: &SiteModel, ca_host: &str) -> String {
    format!(
        "<staging-dir>/hosts/{}/{}",
        ca_host,
        format!("{}/config/ca.json", model.deployment.ca_steppath()).trim_start_matches('/')
    )
}

fn parent_dir(path: &str) -> String {
    std::path::Path::new(path)
        .parent()
        .map(|parent| parent.display().to_string())
        .unwrap_or_else(|| ".".to_owned())
}

fn sh_display(path: &std::path::Path) -> String {
    sh(&path.display().to_string())
}

fn sh(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value
        .bytes()
        .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'%' | b'+' | b'='))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn unique_hosts<const N: usize>(hosts: [String; N]) -> Vec<String> {
    let mut hosts = hosts.into_iter().collect::<Vec<_>>();
    hosts.sort();
    hosts.dedup();
    hosts
}

fn user_public_key_path(key_name: &str) -> String {
    format!("$HOME/.ssh/{key_name}.pub")
}

fn user_cert_path(key_name: &str) -> String {
    format!("$HOME/.ssh/{key_name}-cert.pub")
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
        STEP_EDIT_POLICY, STEP_EXPORT_PUBLIC_MATERIAL, STEP_INITIALIZE_SMALLSTEP_STATE,
        STEP_INSTALL_CLIENT, STEP_INSTALL_RENDERED_FILES, STEP_ISSUE_HOST_CERT,
        STEP_ISSUE_USER_CERT, STEP_RENDER, STEP_RENEW_HOST_CERT, STEP_REVIEW_SECRETS, add_host,
        add_user, host_bootstrap, host_renew, host_renew_all, init_ca, renewable_hosts, sh,
        user_login,
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
                STEP_INSTALL_RENDERED_FILES,
                STEP_EXPORT_PUBLIC_MATERIAL,
                STEP_ACTIVATE_SERVICE
            ]
        );
        assert!(!plan.steps[0].manual);
        assert!(plan.steps[1..].iter().all(|step| step.manual));
        assert_eq!(plan.steps[1].hosts, vec!["ca-host".to_owned()]);
        assert!(plan.steps[1].commands[0].contains("/srv/example-ca/secrets"));
        assert!(plan.steps[1].commands[1].contains("crypto rand --format ascii 48"));
        assert!(plan.steps[1].commands[2].contains("--dns ca.example.test"));
        assert!(plan.steps[1].commands[2].contains("--dns ca-origin.example.test"));
        assert!(plan.steps[1].commands[2].contains("--address 198.51.100.20:8443"));
        assert!(plan.steps[1].commands[2].contains("--with-ca-url https://ca.example.test"));
        assert!(plan.steps[2].commands[0].contains("ca provisioner add grafhome-user-login"));
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains(
                    "RUNTIME_SECRET_PLACEHOLDER:GRAFHOME_CA_PROVISIONER_GRAFHOME_HOST_BOOTSTRAP_JSON"
                ))
        );
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains(
                    "RUNTIME_SECRET_PLACEHOLDER:GRAFHOME_CA_PROVISIONER_GRAFHOME_USER_LOGIN_JSON"
                ))
        );
        assert!(
            !plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("..."))
        );
        assert!(
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command.contains("/srv/example-ca/step/config/ca.json"))
        );
        assert!(
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command
                    .contains("/etc/apache2/conf-available/grafhome-ca-proxy.conf"))
        );
        assert!(plan.steps[4].commands[0].contains("export-public"));
        assert!(plan.steps[5].commands[1].contains("systemctl enable --now step-ca.service"));
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
                STEP_ISSUE_HOST_CERT,
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
        assert!(
            plan.steps[1].commands[0].contains("$(cat '<public-material-dir>/root_fingerprint')")
        );
        assert!(plan.steps[1].commands[0].contains("STEPPATH=/etc/step/grafhome"));
        assert!(plan.steps[2].commands[0].contains("step ssh certificate"));
        assert!(plan.steps[2].commands[0].contains("--host"));
        assert!(
            plan.steps[2].commands[0].contains(
                "--provisioner-password-file '<host-bootstrap-provisioner-password-file>'"
            )
        );
        assert!(plan.steps[2].commands[0].contains("--principal proxy-host"));
        assert!(plan.steps[2].commands[0].contains("--principal ca.example.test"));
        assert!(plan.steps[2].commands[0].contains("/etc/ssh/ssh_host_ed25519_key.pub"));
        assert!(
            plan.steps[2]
                .files
                .contains(&"/etc/ssh/ssh_host_ed25519_key-cert.pub".to_owned())
        );
        assert!(
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command
                    == "install -D -m 0644 '<public-material-dir>/user_ca_keys.pem' /etc/ssh/grafhome/user_ca_keys.pem")
        );
        assert!(
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command
                    == "install -D -m 0644 '<public-material-dir>/ssh_known_hosts' /etc/ssh/grafhome/ssh_known_hosts")
        );
        assert!(
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command.contains("/etc/ssh/sshd_config.d/grafhome-ca.conf"))
        );
        assert!(
            !plan.steps[3]
                .commands
                .iter()
                .any(|command| command.starts_with("install rendered files"))
        );
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
        assert!(
            plan.steps[0].commands[0]
                .contains("--provisioner-password-file '<user-login-provisioner-password-file>'")
        );
        assert!(plan.steps[0].commands[0].contains("STEPPATH=$HOME/.config/grafhome/step"));
        assert!(
            plan.steps[0]
                .commands
                .iter()
                .any(|command| command.contains("$HOME/.ssh/alice_ca_host_ed25519.pub"))
        );
        assert!(
            plan.steps[0]
                .files
                .contains(&"$HOME/.ssh/alice_ca_host_ed25519-cert.pub".to_owned())
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
            vec!["grafhome-ca plan user-login --user new-user --device '<device>'"]
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

    #[test]
    fn shell_quotes_dynamic_plan_arguments() {
        assert_eq!(
            sh("/etc/ssh/ssh_host_ed25519_key"),
            "/etc/ssh/ssh_host_ed25519_key"
        );
        assert_eq!(
            sh("<public-material-dir>/root_fingerprint"),
            "'<public-material-dir>/root_fingerprint'"
        );
        assert_eq!(
            sh("path with spaces/and'a quote"),
            "'path with spaces/and'\"'\"'a quote'"
        );
    }

    fn step_ids(plan: &super::Plan) -> Vec<&str> {
        plan.steps.iter().map(|step| step.id.as_str()).collect()
    }
}
