//! Lifecycle operation planning.
//!
//! Plans are structured, serializable descriptions of what an operation would
//! do. They are intentionally separate from command execution so tests can mock
//! behavior and operators can review actions before deployment code exists.

use std::path::PathBuf;

use serde::Serialize;

use crate::enrollment::user_provisioner_name;
use crate::policy::{ClientDevice, Host, User};
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
/// CA state backup and restore-test operation key.
pub const OP_BACKUP_CA: &str = "backup-ca";
/// Live rollout verification operation key.
pub const OP_VERIFY_LIVE: &str = "verify-live";
/// Proxy X.509 certificate operation key.
pub const OP_PROXY_CERT: &str = "proxy-cert";
/// New host policy workflow operation key.
pub const OP_ADD_HOST: &str = "add-host";
/// New user policy workflow operation key.
pub const OP_ADD_USER: &str = "add-user";
/// Create a short-lived host enrollment token operation key.
pub const OP_CREATE_HOST_TOKEN: &str = "create-host-token";
/// Consume a host enrollment token operation key.
pub const OP_ENROLL_HOST: &str = "enroll-host";
/// Create a short-lived user enrollment token operation key.
pub const OP_CREATE_USER_TOKEN: &str = "create-user-token";
/// Consume a user enrollment token operation key.
pub const OP_ENROLL_USER: &str = "enroll-user";
/// Ensure a user SSH certificate exists operation key.
pub const OP_SSH_ENSURE: &str = "ssh-ensure";

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
/// Backup CA state step key.
pub const STEP_BACKUP_CA_STATE: &str = "backup-ca-state";
/// Restore-test CA backup step key.
pub const STEP_RESTORE_TEST_BACKUP: &str = "restore-test-backup";
/// Ensure client tooling exists step key.
pub const STEP_INSTALL_CLIENT: &str = "install-client";
/// Bootstrap CA trust step key.
pub const STEP_BOOTSTRAP_TRUST: &str = "bootstrap-trust";
/// Install rendered host files step key.
pub const STEP_INSTALL_RENDERED_FILES: &str = "install-rendered-files";
/// Renew one SSH host certificate step key.
pub const STEP_RENEW_HOST_CERT: &str = "renew-host-cert";
/// Issue or renew proxy X.509 certificate step key.
pub const STEP_PROXY_CERT: &str = "proxy-cert";
/// Verify live CA API step key.
pub const STEP_VERIFY_CA_API: &str = "verify-ca-api";
/// Verify live SSH rollout step key.
pub const STEP_VERIFY_SSH: &str = "verify-ssh";
/// Verify live proxy TLS step key.
pub const STEP_VERIFY_PROXY_TLS: &str = "verify-proxy-tls";
/// Edit policy tables step key.
pub const STEP_EDIT_POLICY: &str = "edit-policy";
/// Follow up with host bootstrap step key.
pub const STEP_BOOTSTRAP_HOST: &str = "bootstrap-host";
/// Create host enrollment token step key.
pub const STEP_CREATE_HOST_TOKEN: &str = "create-host-token";
/// Consume host enrollment token step key.
pub const STEP_CONSUME_HOST_TOKEN: &str = "consume-host-token";
/// Create user enrollment token step key.
pub const STEP_CREATE_USER_TOKEN: &str = "create-user-token";
/// Consume user enrollment token step key.
pub const STEP_CONSUME_USER_TOKEN: &str = "consume-user-token";
/// Create local user provisioner key step key.
pub const STEP_CREATE_USER_PROVISIONER_KEY: &str = "create-user-provisioner-key";
/// Authorize constrained user provisioner step key.
pub const STEP_REGISTER_USER_PROVISIONER: &str = "authorize-user-provisioner";
/// Ensure local user certificate step key.
pub const STEP_ENSURE_USER_CERT: &str = "ensure-user-cert";

/// Default enrollment token lifetime.
pub const DEFAULT_ENROLLMENT_TOKEN_TTL: &str = "15m";
const USER_STEP_BIN: &str = "step";

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
    let service_user = &model.deployment.values["GRAFHOME_CA_SERVICE_USER"];
    let password_file = &model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"];
    let password_parent = parent_dir(password_file);
    let provisioner_review_commands =
        runtime_provisioner_review_commands(model, &ca_origin.target, &bootstrap.name);
    let install_steps =
        init_ca_rendered_install_steps(model, &[&ca_origin.target, &ca_api.target])?;
    let install_hosts = unique_hosts([ca_origin.target.clone(), ca_api.target.clone()]);
    let mut steps = vec![
        PlanStep {
            id: STEP_RENDER.to_owned(),
            summary: "render reviewed CA, systemd, Apache, SSH, and principals files".to_owned(),
            hosts: Vec::new(),
            commands: vec![format!(
                "grafhome-ca render --clean --out-dir {} --config-root {}",
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
                    "getent group {} || groupadd --system {}",
                    sh(service_user),
                    sh(service_user),
                ),
                format!(
                    "if ! id -u {} >/dev/null 2>&1; then service_shell=\"$(command -v nologin || true)\"; if test -z \"$service_shell\"; then for candidate in /usr/sbin/nologin /usr/bin/nologin /sbin/nologin /bin/false /usr/bin/false; do test ! -x \"$candidate\" || {{ service_shell=\"$candidate\"; break; }}; done; fi; test -n \"$service_shell\"; useradd --system --gid {} --home-dir {} --shell \"$service_shell\" --comment {} {}; fi",
                    sh(service_user),
                    sh(service_user),
                    sh(&model.deployment.values["GRAFHOME_CA_STATE_DIR"]),
                    sh("Grafhome CA service"),
                    sh(service_user),
                ),
                format!(
                    "id {}",
                    sh(service_user),
                ),
                format!(
                    "getent group {}",
                    sh(service_user),
                ),
                format!(
                    "install -d -o {} -g {} -m 0750 {} {}",
                    sh(service_user),
                    sh(service_user),
                    sh(&model.deployment.values["GRAFHOME_CA_STATE_DIR"]),
                    sh(&model.deployment.ca_steppath()),
                ),
                format!(
                    "install -d -o {} -g {} -m 0700 {}",
                    sh(service_user),
                    sh(service_user),
                    sh(&password_parent),
                ),
                format!(
                    "test -s {} || install -o {} -g {} -m 0600 /dev/null {}",
                    sh(password_file),
                    sh(service_user),
                    sh(service_user),
                    sh(password_file),
                ),
                format!(
                    "test -s {} || {} crypto rand --format ascii 48 > {}",
                    sh(password_file),
                    sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                    sh(password_file),
                ),
                format!(
                    "chown {}:{} {}",
                    sh(service_user),
                    sh(service_user),
                    sh(password_file),
                ),
                format!(
                    "chmod 0600 {}",
                    sh(password_file),
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
                    sh(password_file),
                    sh(password_file),
                ),
                format!(
                    "chown -R {}:{} {}",
                    sh(service_user),
                    sh(service_user),
                    sh(&model.deployment.values["GRAFHOME_CA_STATE_DIR"]),
                ),
                format!(
                    "chown {}:{} {}",
                    sh(service_user),
                    sh(service_user),
                    sh(password_file),
                ),
                format!(
                    "chmod 0600 {}",
                    sh(password_file),
                ),
            ],
            files: vec![
                format!("{}/config/ca.json", model.deployment.ca_steppath()),
                password_file.clone(),
            ],
            manual: true,
        },
        PlanStep {
            id: STEP_REVIEW_SECRETS.to_owned(),
            summary: "materialize runtime JWK provisioners into the staged CA config without using the live admin API"
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
            summary: "install reviewed rendered files for the CA origin and proxy hosts".to_owned(),
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
            summary: "repair CA service ownership and enable the service after review".to_owned(),
            hosts: vec![ca_origin.target.clone()],
            commands: vec![
                format!(
                    "chown -R {}:{} {}",
                    sh(&model.deployment.values["GRAFHOME_CA_SERVICE_USER"]),
                    sh(&model.deployment.values["GRAFHOME_CA_SERVICE_USER"]),
                    sh(&model.deployment.values["GRAFHOME_CA_STATE_DIR"]),
                ),
                format!(
                    "chown {}:{} {}",
                    sh(&model.deployment.values["GRAFHOME_CA_SERVICE_USER"]),
                    sh(&model.deployment.values["GRAFHOME_CA_SERVICE_USER"]),
                    sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
                ),
                format!(
                    "chmod 0600 {}",
                    sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
                ),
                "systemctl daemon-reload".to_owned(),
                "systemctl enable --now step-ca.service".to_owned(),
            ],
            files: vec![
                format!("{}/config/ca.json", model.deployment.ca_steppath()),
                model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"].clone(),
                "/etc/systemd/system/step-ca.service".to_owned(),
            ],
            manual: true,
        },
    ];
    steps.extend(backup_steps(model)?);
    Ok(Plan {
        operation: OP_INIT_CA.to_owned(),
        summary: format!(
            "initialize step-ca on {} and expose it through {}",
            ca_origin.target, ca_api.dns_name
        ),
        steps,
    })
}

/// Plan host bootstrap without executing it.
pub fn host_bootstrap(model: &SiteModel, host: &str) -> Result<Plan> {
    let host = required_host(model, host)?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let _bootstrap = required_provisioner(model, "host_bootstrap")?;
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
            id: STEP_CREATE_HOST_TOKEN.to_owned(),
            summary: "create and consume a short-lived host enrollment token before enabling HostCertificate".to_owned(),
            hosts: unique_hosts([host.host.clone(), ca_origin.target.clone()]),
            commands: vec![
                "grafhome-ca approve-host".to_owned(),
                format!("grafhome-ca enroll-host --host {}", sh(&host.host)),
            ],
            files: vec![host_public_key_path(model), host_cert_path(model)],
            manual: true,
        });
    }
    let mut install_commands = host_bootstrap_install_steps(model, host)?;
    if host.ssh_server == "yes" {
        install_commands.push("sshd -t".to_owned());
        install_commands.push("systemctl reload ssh || systemctl reload sshd".to_owned());
    }
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
    let host_cert = host_cert_path(model);
    Ok(Plan {
        operation: OP_HOST_RENEW.to_owned(),
        summary: format!("renew SSH host certificate for {}", host.host),
        steps: vec![PlanStep {
            id: STEP_RENEW_HOST_CERT.to_owned(),
            summary: "renew host SSH certificate with its scoped JWK credential".to_owned(),
            hosts: vec![host.host.clone()],
            commands: vec![host_renew_command(&host.host)],
            files: vec![host_cert],
            manual: host.renewal_owner == "manual",
        }],
    })
}

/// Plan certificate renewal for every host with an SSH server and renewal owner.
pub fn host_renew_all(model: &SiteModel) -> Result<Plan> {
    let host_cert = host_cert_path(model);
    let steps = renewable_hosts(model)
        .map(|host| PlanStep {
            id: STEP_RENEW_HOST_CERT.to_owned(),
            summary: format!("renew SSH host certificate on {}", host.host),
            hosts: vec![host.host.clone()],
            commands: vec![host_renew_command(&host.host)],
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

/// Plan CA state backup and restore-test without executing it.
pub fn backup_ca(model: &SiteModel) -> Result<Plan> {
    let ca_origin = required_endpoint(model, "ca_origin")?;
    Ok(Plan {
        operation: OP_BACKUP_CA.to_owned(),
        summary: "backup CA state and prove the backup can be restored before host trust rollout"
            .to_owned(),
        steps: backup_steps(model)?
            .into_iter()
            .map(|mut step| {
                step.hosts = vec![ca_origin.target.clone()];
                step
            })
            .collect(),
    })
}

/// Plan live non-mutating verification checks without executing them.
pub fn verify_live(model: &SiteModel, host: Option<&str>) -> Result<Plan> {
    let ca_api = required_endpoint(model, "ca_api")?;
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let hosts = match host {
        Some(name) => vec![required_host(model, name)?],
        None => model.policy.hosts.iter().collect::<Vec<_>>(),
    };
    let mut steps = vec![
        PlanStep {
            id: STEP_VERIFY_CA_API.to_owned(),
            summary: "verify the CA API and exported root fingerprint".to_owned(),
            hosts: vec![ca_origin.target.clone()],
            commands: vec![
                format!(
                    "STEPPATH={} {} ca health --ca-url {}",
                    sh(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
                    sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                    sh(&ca_api.url())
                ),
                format!(
                    "test \"$(STEPPATH={} {} certificate fingerprint {})\" = \"$(cat {})\"",
                    sh(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
                    sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                    sh(&format!(
                        "{}/step/certs/root_ca.crt",
                        model.deployment.values["GRAFHOME_CA_STATE_DIR"]
                    )),
                    sh("<public-material-dir>/root_fingerprint")
                ),
            ],
            files: vec![
                format!(
                    "{}/step/certs/root_ca.crt",
                    model.deployment.values["GRAFHOME_CA_STATE_DIR"]
                ),
                "<public-material-dir>/root_fingerprint".to_owned(),
            ],
            manual: true,
        },
        PlanStep {
            id: STEP_VERIFY_PROXY_TLS.to_owned(),
            summary: "verify proxy TLS for the public CA endpoint".to_owned(),
            hosts: vec![ca_api.target.clone()],
            commands: vec![
                format!("test -s {}", sh(&proxy_cert_path(model, ca_api))),
                format!("test -s {}", sh(&proxy_key_path(model, ca_api))),
                format!("test -s {}", sh(&proxy_root_cert_path(model))),
                format!(
                    "cmp -s {} {}",
                    sh(&proxy_root_cert_path(model)),
                    sh("<public-material-dir>/root_ca.crt")
                ),
                format!(
                    "openssl x509 -in {} -noout -checkend 604800",
                    sh(&proxy_cert_path(model, ca_api))
                ),
                format!(
                    "openssl s_client -connect {}:{} -servername {} -CAfile {} -verify_hostname {} -verify_return_error </dev/null",
                    sh(&ca_api.dns_name),
                    ca_api.port,
                    sh(&ca_api.dns_name),
                    sh("<public-material-dir>/root_ca.crt"),
                    sh(&ca_api.dns_name)
                ),
            ],
            files: vec![
                proxy_cert_path(model, ca_api),
                proxy_key_path(model, ca_api),
                proxy_root_cert_path(model),
                "<public-material-dir>/root_ca.crt".to_owned(),
            ],
            manual: true,
        },
    ];
    for host in hosts {
        steps.push(verify_host_step(model, host)?);
    }
    Ok(Plan {
        operation: OP_VERIFY_LIVE.to_owned(),
        summary: "verify live CA, proxy TLS, and SSH trust rollout state".to_owned(),
        steps,
    })
}

/// Plan proxy X.509 certificate issuance or renewal without executing it.
pub fn proxy_cert(model: &SiteModel) -> Result<Plan> {
    let ca_api = required_endpoint(model, "ca_api")?;
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let provisioner = required_provisioner(model, "proxy_x509")?;
    let cert = proxy_cert_path(model, ca_api);
    let key = proxy_key_path(model, ca_api);
    let challenge_dir = PathBuf::from(&model.deployment.values["GRAFHOME_CA_PROXY_ACME_WEBROOT"])
        .join(".well-known/acme-challenge")
        .display()
        .to_string();
    Ok(Plan {
        operation: OP_PROXY_CERT.to_owned(),
        summary: format!(
            "issue or renew proxy TLS certificate for {} on {}",
            ca_api.dns_name, ca_api.target
        ),
        steps: vec![
            PlanStep {
                id: STEP_PROXY_CERT.to_owned(),
                summary: "issue proxy certificate through the configured ACME provisioner"
                    .to_owned(),
                hosts: vec![ca_api.target.clone()],
                commands: vec![
                    format!(
                        "install -d -m 0750 {}",
                        sh(&model.deployment.values["GRAFHOME_CA_PROXY_TLS_DIR"])
                    ),
                    install_public_material_command("root_ca.crt", &proxy_root_cert_path(model)),
                    format!("install -d -m 0755 {}", sh(&challenge_dir)),
                    format!(
                        "STEPPATH={} {} ca certificate {} {} {} --ca-url {} --provisioner {} --san {} --not-after {} --force --webroot {}",
                        sh(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
                        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                        sh(&ca_api.dns_name),
                        sh(&cert),
                        sh(&key),
                        sh(&ca_origin.url()),
                        sh(&provisioner.name),
                        sh(&ca_api.dns_name),
                        sh(&provisioner.default_ttl),
                        sh(&model.deployment.values["GRAFHOME_CA_PROXY_ACME_WEBROOT"])
                    ),
                    format!("openssl x509 -in {} -noout -text", sh(&cert)),
                ],
                files: vec![cert, key, proxy_root_cert_path(model)],
                manual: true,
            },
            PlanStep {
                id: STEP_VERIFY_PROXY_TLS.to_owned(),
                summary: "verify the proxy serves the issued certificate after Apache is reloaded"
                    .to_owned(),
                hosts: vec![ca_api.target.clone()],
                commands: vec![format!(
                    "openssl s_client -connect {}:{} -servername {} -CAfile {} -verify_hostname {} -verify_return_error </dev/null",
                    sh(&ca_api.dns_name),
                    ca_api.port,
                    sh(&ca_api.dns_name),
                    sh("<public-material-dir>/root_ca.crt"),
                    sh(&ca_api.dns_name)
                )],
                files: vec!["<public-material-dir>/root_ca.crt".to_owned()],
                manual: true,
            },
        ],
    })
}

/// Plan creation of a short-lived host enrollment token.
pub fn create_host_token(
    model: &SiteModel,
    host: &str,
    token_ttl: Option<&str>,
    cert_ttl: Option<&str>,
) -> Result<Plan> {
    let host = required_host(model, host)?;
    if host.ssh_server != "yes" {
        return Err(Error::Validation {
            field: format!("policy/hosts.tsv:{}.ssh_server", host.host),
            message: "host enrollment requires ssh_server=yes".to_owned(),
        });
    }
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let bootstrap = required_provisioner(model, "host_bootstrap")?;
    let token_ttl = checked_ttl(
        "create-host-token.ttl",
        token_ttl.unwrap_or(DEFAULT_ENROLLMENT_TOKEN_TTL),
    )?;
    let cert_ttl = checked_ttl(
        "create-host-token.cert_ttl",
        cert_ttl.unwrap_or(&bootstrap.default_ttl),
    )?;

    Ok(Plan {
        operation: OP_CREATE_HOST_TOKEN.to_owned(),
        summary: format!("create a short-lived host enrollment token for {}", host.host),
        steps: vec![PlanStep {
            id: STEP_CREATE_HOST_TOKEN.to_owned(),
            summary: "run on the CA origin as the CA operator; copy only the printed token to the target host".to_owned(),
            hosts: vec![ca_origin.target.clone()],
            commands: vec![host_token_command(
                model,
                host,
                &bootstrap.name,
                &ca_api.url(),
                token_ttl,
                cert_ttl,
            )],
            files: vec![
                model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"].clone(),
                format!("{}/certs/root_ca.crt", model.deployment.ca_steppath()),
            ],
            manual: true,
        }],
    })
}

/// Plan consumption of a host enrollment token on the target host.
pub fn enroll_host(model: &SiteModel, host: &str) -> Result<Plan> {
    let host = required_host(model, host)?;
    if host.ssh_server != "yes" {
        return Err(Error::Validation {
            field: format!("policy/hosts.tsv:{}.ssh_server", host.host),
            message: "host enrollment requires ssh_server=yes".to_owned(),
        });
    }
    let ca_api = required_endpoint(model, "ca_api")?;
    Ok(Plan {
        operation: OP_ENROLL_HOST.to_owned(),
        summary: format!("enroll {} with a host SSH certificate", host.host),
        steps: vec![PlanStep {
            id: STEP_CONSUME_HOST_TOKEN.to_owned(),
            summary: "run on the target host as root with the short-lived host enrollment token"
                .to_owned(),
            hosts: vec![host.host.clone()],
            commands: vec![
                host_enroll_command(model, host, &ca_api.url()),
                "sshd -t".to_owned(),
                "systemctl reload ssh || systemctl reload sshd".to_owned(),
            ],
            files: vec![host_public_key_path(model), host_cert_path(model)],
            manual: true,
        }],
    })
}

/// Plan creation of a short-lived user enrollment token.
pub fn create_user_token(
    model: &SiteModel,
    user: &str,
    host: &str,
    token_ttl: Option<&str>,
    cert_ttl: Option<&str>,
) -> Result<Plan> {
    let user = active_user(model, user)?;
    let device = required_user_device(model, &user.user, host)?;
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let ca_api = required_endpoint(model, "ca_api")?;
    let token_ttl = checked_ttl(
        "create-user-token.ttl",
        token_ttl.unwrap_or(DEFAULT_ENROLLMENT_TOKEN_TTL),
    )?;
    let cert_ttl = checked_ttl(
        "create-user-token.cert_ttl",
        cert_ttl.unwrap_or(&user.cert_ttl),
    )?;

    Ok(Plan {
        operation: OP_CREATE_USER_TOKEN.to_owned(),
        summary: format!(
            "create a short-lived user enrollment token for {} on {}",
            user.user, device.device
        ),
        steps: vec![PlanStep {
            id: STEP_CREATE_USER_TOKEN.to_owned(),
            summary: "run on the CA origin as the CA operator; copy only the printed token to the user device".to_owned(),
            hosts: vec![ca_origin.target.clone()],
            commands: vec![user_token_command(
                model,
                user,
                &ca_api.url(),
                token_ttl,
                cert_ttl,
            )],
            files: vec![
                model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"].clone(),
                format!("{}/certs/root_ca.crt", model.deployment.ca_steppath()),
            ],
            manual: true,
        }],
    })
}

/// Plan first-time user enrollment on a client host.
pub fn enroll_user(model: &SiteModel, user: &str, host: &str) -> Result<Plan> {
    let user = active_user(model, user)?;
    let device = required_user_device(model, &user.user, host)?;
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let material_dir = user_device_material_dir(&user.user, &device.device);
    let public_jwk = format!("{material_dir}/provisioner.pub.json");
    let private_jwk = format!("{material_dir}/provisioner.priv.json");

    Ok(Plan {
        operation: OP_ENROLL_USER.to_owned(),
        summary: format!("enroll {} for user SSH certificates on {}", user.user, device.device),
        steps: vec![
            PlanStep {
                id: STEP_CONSUME_USER_TOKEN.to_owned(),
                summary: "run once on the user device; copy its public request to the CA and paste the returned grant into the waiting command".to_owned(),
                hosts: vec![device.device.clone()],
                commands: vec![format!(
                    "grafhome-ca enroll-user --user {} --host {}",
                    sh(&user.user),
                    sh(&device.device)
                )],
                files: vec![
                    user_private_key_path(&device.key_name),
                    user_public_key_path(&device.key_name),
                    user_cert_path(&device.key_name),
                    public_jwk.clone(),
                    private_jwk.clone(),
                ],
                manual: true,
            },
            PlanStep {
                id: STEP_REGISTER_USER_PROVISIONER.to_owned(),
                summary: "run on the CA origin as root; paste and approve the public request, then copy the secret grant back".to_owned(),
                hosts: vec![ca_origin.target.clone()],
                commands: vec!["grafhome-ca approve-user".to_owned()],
                files: vec![format!(
                    "{}/config/ca.json",
                    model.deployment.ca_steppath()
                )],
                manual: true,
            },
        ],
    })
}

/// Plan local user SSH cert refresh before an SSH connection.
pub fn ssh_ensure(model: &SiteModel, user: &str, host: Option<&str>) -> Result<Plan> {
    let user = active_user(model, user)?;
    let device = match host {
        Some(host) => required_user_device(model, &user.user, host)?,
        None => select_single_user_device(model, &user.user)?,
    };
    let ca_api = required_endpoint(model, "ca_api")?;
    let provisioner_name = user_provisioner_name(&user.user, &device.device);
    let private_jwk = format!(
        "{}/provisioner.priv.json",
        user_device_material_dir(&user.user, &device.device)
    );

    Ok(Plan {
        operation: OP_SSH_ENSURE.to_owned(),
        summary: format!(
            "ensure {} has a fresh SSH certificate on {}",
            user.user, device.device
        ),
        steps: vec![PlanStep {
            id: STEP_ENSURE_USER_CERT.to_owned(),
            summary: "run locally from ssh Match exec or ds before opening the SSH connection"
                .to_owned(),
            hosts: vec![device.device.clone()],
            commands: vec![user_refresh_command(
                model,
                user,
                device,
                &ca_api.url(),
                &provisioner_name,
                &private_jwk,
            )],
            files: vec![
                private_jwk,
                user_public_key_path(&device.key_name),
                user_cert_path(&device.key_name),
            ],
            manual: false,
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
                id: STEP_CREATE_USER_TOKEN.to_owned(),
                summary:
                    "run the client enrollment command and approve its request on the CA origin"
                        .to_owned(),
                hosts: Vec::new(),
                commands: vec![
                    format!(
                        "grafhome-ca enroll-user --user {} --host {}",
                        sh(user),
                        sh("<client-host>")
                    ),
                    "grafhome-ca approve-user".to_owned(),
                ],
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

fn active_user<'a>(model: &'a SiteModel, user: &str) -> Result<&'a User> {
    let user = model.policy.user(user).ok_or_else(|| Error::Validation {
        field: format!("policy/users.tsv:{user}"),
        message: "unknown user".to_owned(),
    })?;
    if user.status != "active" {
        return Err(Error::Validation {
            field: format!("policy/users.tsv:{}.status", user.user),
            message: "user must be active for certificate enrollment".to_owned(),
        });
    }
    Ok(user)
}

fn required_user_device<'a>(
    model: &'a SiteModel,
    user: &str,
    host: &str,
) -> Result<&'a ClientDevice> {
    model
        .policy
        .active_client_devices_for_user(user)
        .find(|device| device.device == host)
        .ok_or_else(|| Error::Validation {
            field: format!("policy/client-devices.tsv:{host}"),
            message: format!("no active client host {host} for user {user}"),
        })
}

fn select_single_user_device<'a>(model: &'a SiteModel, user: &str) -> Result<&'a ClientDevice> {
    let devices = model
        .policy
        .active_client_devices_for_user(user)
        .collect::<Vec<_>>();
    match devices.len() {
        0 => Err(Error::Validation {
            field: format!("policy/client-devices.tsv:{user}"),
            message: "user has no active client hosts".to_owned(),
        }),
        1 => Ok(devices[0]),
        _ => Err(Error::Validation {
            field: format!("policy/client-devices.tsv:{user}"),
            message: "multiple active client hosts; pass --host".to_owned(),
        }),
    }
}

fn backup_steps(model: &SiteModel) -> Result<Vec<PlanStep>> {
    let ca_origin = required_endpoint(model, "ca_origin")?;
    let state_dir = &model.deployment.values["GRAFHOME_CA_STATE_DIR"];
    let parent = parent_dir(state_dir);
    let basename = std::path::Path::new(state_dir)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Validation {
            field: "config/deployment.env:GRAFHOME_CA_STATE_DIR".to_owned(),
            message: "state directory must have a final path component".to_owned(),
        })?;
    let backup_file = "<backup-file>";
    let restore_dir = "<restore-test-dir>";
    Ok(vec![
        PlanStep {
            id: STEP_BACKUP_CA_STATE.to_owned(),
            summary: "create an operator-controlled backup of CA state before host trust rollout"
                .to_owned(),
            hosts: vec![ca_origin.target.clone()],
            commands: vec![
                format!(
                    "backup_file={}; install -d -m 0700 \"$(dirname \"$backup_file\")\"",
                    sh(backup_file)
                ),
                format!(
                    "backup_file={}; tar -C {} -cpf \"$backup_file\" {}",
                    sh(backup_file),
                    sh(&parent),
                    sh(basename)
                ),
                format!("backup_file={}; test -s \"$backup_file\"", sh(backup_file)),
            ],
            files: vec![state_dir.clone(), backup_file.to_owned()],
            manual: true,
        },
        PlanStep {
            id: STEP_RESTORE_TEST_BACKUP.to_owned(),
            summary: "restore-test the CA state backup before any host trusts the CA".to_owned(),
            hosts: vec![ca_origin.target.clone()],
            commands: vec![
                format!(
                    "restore_dir={}; install -d -m 0700 \"$restore_dir\"; tar -C \"$restore_dir\" -xpf {}",
                    sh(restore_dir),
                    sh(backup_file)
                ),
                format!(
                    "restore_dir={}; test -s \"$restore_dir\"/{}/step/certs/root_ca.crt",
                    sh(restore_dir),
                    sh(basename)
                ),
                format!(
                    "restore_dir={}; test -s \"$restore_dir\"/{}/step/secrets/intermediate_ca_key",
                    sh(restore_dir),
                    sh(basename)
                ),
                format!(
                    "restore_dir={}; STEPPATH=\"$restore_dir\"/{}/step {} certificate fingerprint \"$restore_dir\"/{}/step/certs/root_ca.crt",
                    sh(restore_dir),
                    sh(basename),
                    sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
                    sh(basename)
                ),
            ],
            files: vec![backup_file.to_owned(), restore_dir.to_owned()],
            manual: true,
        },
    ])
}

fn verify_host_step(model: &SiteModel, host: &Host) -> Result<PlanStep> {
    let mut commands = Vec::new();
    let mut files = Vec::new();
    if host.ssh_server == "yes" {
        let user_ca_keys =
            absolute_deployment_child(model, "GRAFHOME_CA_SSH_TRUST_DIR", "user_ca_keys.pem")?;
        let revoked =
            absolute_deployment_child(model, "GRAFHOME_CA_SSH_TRUST_DIR", "revoked_user_certs")?;
        let host_cert = host_cert_path(model);
        commands.extend([
            format!("test -s {}", sh(&user_ca_keys)),
            format!("test -e {}", sh(&revoked)),
            format!("test -s {}", sh(&host_cert)),
            format!(
                "sshd -T | grep -Fx {}",
                sh(&format!("trustedusercakeys {user_ca_keys}"))
            ),
            format!(
                "sshd -T | grep -Fx {}",
                sh(&format!("hostcertificate {host_cert}"))
            ),
            format!("ssh-keygen -L -f {}", sh(&host_cert)),
        ]);
        files.extend([user_ca_keys, revoked, host_cert]);
    }
    if host.ssh_client == "yes" {
        let known_hosts =
            absolute_deployment_child(model, "GRAFHOME_CA_SSH_TRUST_DIR", "ssh_known_hosts")?;
        commands.push(format!("test -s {}", sh(&known_hosts)));
        commands.push(format!(
            "ssh -G {} | grep -E {}",
            sh(first_host_principal(host)),
            sh(&format!("^globalknownhostsfile .*{known_hosts}"))
        ));
        files.push(known_hosts);
    }
    if commands.is_empty() {
        commands.push("true # host has no SSH server/client rollout checks".to_owned());
    }
    Ok(PlanStep {
        id: STEP_VERIFY_SSH.to_owned(),
        summary: format!("verify SSH CA rollout on {}", host.host),
        hosts: vec![host.host.clone()],
        commands,
        files,
        manual: true,
    })
}

fn first_host_principal(host: &Host) -> &str {
    host.principals
        .split(',')
        .map(str::trim)
        .find(|principal| !principal.is_empty())
        .unwrap_or(&host.host)
}

fn proxy_cert_path(model: &SiteModel, ca_api: &crate::policy::Endpoint) -> String {
    format!(
        "{}/{}.crt",
        model.deployment.values["GRAFHOME_CA_PROXY_TLS_DIR"].trim_end_matches('/'),
        ca_api.dns_name
    )
}

fn proxy_key_path(model: &SiteModel, ca_api: &crate::policy::Endpoint) -> String {
    format!(
        "{}/{}.key",
        model.deployment.values["GRAFHOME_CA_PROXY_TLS_DIR"].trim_end_matches('/'),
        ca_api.dns_name
    )
}

fn proxy_root_cert_path(model: &SiteModel) -> String {
    format!(
        "{}/root_ca.crt",
        model.deployment.values["GRAFHOME_CA_PROXY_TLS_DIR"].trim_end_matches('/'),
    )
}

fn host_token_command(
    model: &SiteModel,
    host: &Host,
    provisioner: &str,
    ca_url: &str,
    token_ttl: &str,
    cert_ttl: &str,
) -> String {
    let principal_args = host_principal_args(host);
    format!(
        "STEPPATH={} {} ca token {} --ssh --host {} --not-after {} --cert-not-after {} --provisioner {} --provisioner-password-file {} --ca-url {} --root {}",
        sh(&model.deployment.ca_steppath()),
        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
        sh(&host.host),
        principal_args,
        sh(token_ttl),
        sh(cert_ttl),
        sh(provisioner),
        sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
        sh(ca_url),
        sh(&ca_root_cert_path(model))
    )
}

fn host_enroll_command(model: &SiteModel, host: &Host, ca_url: &str) -> String {
    format!(
        "STEPPATH={} {} ssh certificate {} {} --host --sign --token {} --ca-url {} --root {} --force",
        sh(&model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]),
        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
        sh(&host.host),
        sh(&host_public_key_path(model)),
        sh("<host-enrollment-token>"),
        sh(ca_url),
        sh(&server_root_cert_path(model))
    )
}

fn host_renew_command(host: &str) -> String {
    format!("grafhome-ca renew-host --host {}", sh(host))
}

fn user_token_command(
    model: &SiteModel,
    user: &User,
    ca_url: &str,
    token_ttl: &str,
    cert_ttl: &str,
) -> String {
    format!(
        "STEPPATH={} {} ca token {} --ssh --principal {} --not-after {} --cert-not-after {} --provisioner {} --provisioner-password-file {} --ca-url {} --root {}",
        sh(&model.deployment.ca_steppath()),
        sh(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]),
        sh(&user.principal),
        sh(&user.principal),
        sh(token_ttl),
        sh(cert_ttl),
        sh(&user.provisioner),
        sh(&model.deployment.values["GRAFHOME_CA_PASSWORD_FILE"]),
        sh(ca_url),
        sh(&ca_root_cert_path(model))
    )
}

fn user_refresh_command(
    model: &SiteModel,
    user: &User,
    device: &ClientDevice,
    ca_url: &str,
    provisioner: &str,
    private_jwk: &str,
) -> String {
    format!(
        "TOKEN=\"$(STEPPATH={} {} ca token {} --ssh --principal {} --not-after 5m --cert-not-after {} --issuer {} --key {} --password-file {} --ca-url {} --root {})\"; STEPPATH={} {} ssh certificate {} {} --sign --token \"$TOKEN\" --ca-url {} --root {} --force --no-agent",
        sh_home(&user_steppath(model)),
        USER_STEP_BIN,
        sh(&user.principal),
        sh(&user.principal),
        sh(&user.cert_ttl),
        sh(provisioner),
        sh_home(private_jwk),
        sh("<user-owned-password-file>"),
        sh(ca_url),
        sh_home(&user_root_cert_path(model)),
        sh_home(&user_steppath(model)),
        USER_STEP_BIN,
        sh(&user.principal),
        sh_home(&user_public_key_path(&device.key_name)),
        sh(ca_url),
        sh_home(&user_root_cert_path(model))
    )
}

fn host_principal_args(host: &Host) -> String {
    host.principals
        .split(',')
        .map(str::trim)
        .filter(|principal| !principal.is_empty())
        .map(|principal| format!("--principal {}", sh(principal)))
        .collect::<Vec<_>>()
        .join(" ")
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

fn ca_root_cert_path(model: &SiteModel) -> String {
    format!("{}/certs/root_ca.crt", model.deployment.ca_steppath())
}

fn server_root_cert_path(model: &SiteModel) -> String {
    format!(
        "{}/certs/root_ca.crt",
        model.deployment.values["GRAFHOME_CA_SERVER_STEPPATH"]
    )
}

fn user_root_cert_path(model: &SiteModel) -> String {
    format!("{}/certs/root_ca.crt", user_steppath(model))
}

fn user_steppath(model: &SiteModel) -> String {
    format!(
        "$HOME/{}",
        model.deployment.values["GRAFHOME_CA_USER_STEPPATH"]
    )
}

fn init_ca_rendered_install_steps(model: &SiteModel, hosts: &[&str]) -> Result<Vec<String>> {
    let ca_config = format!("{}/config/ca.json", model.deployment.ca_steppath());
    let service_user = &model.deployment.values["GRAFHOME_CA_SERVICE_USER"];
    rendered_install_steps_filtered_with(
        model,
        hosts,
        |_| true,
        |file, target| {
            if target == ca_config {
                return format!(
                    "install -D -o {} -g {} -m {:04o} {} {}",
                    sh(service_user),
                    sh(service_user),
                    file.mode,
                    sh(&format!("<staging-dir>/{}", file.path.display())),
                    sh(target)
                );
            }
            rendered_install_command(file, target)
        },
    )
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
    rendered_install_steps_filtered_with(model, hosts, keep, rendered_install_command)
}

fn rendered_install_steps_filtered_with(
    model: &SiteModel,
    hosts: &[&str],
    keep: impl Fn(&RenderedFile) -> bool,
    command: impl Fn(&RenderedFile, &str) -> String,
) -> Result<Vec<String>> {
    let mut commands = crate::render::render(model)?
        .into_iter()
        .filter(|file| keep(file))
        .filter_map(|file| {
            let (host, target) = rendered_target(&file)?;
            if !hosts.iter().any(|expected| *expected == host) {
                return None;
            }
            Some(command(&file, &target))
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
    let service_user = &model.deployment.values["GRAFHOME_CA_SERVICE_USER"];
    let provisioner_dir = runtime_provisioner_secret_dir(password_file);
    let helper_bin = &model.deployment.values["GRAFHOME_CA_HELPER_BIN"];
    let step_bin = &model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"];
    let mut commands = vec![format!(
        "install -d -o {} -g {} -m 0700 {}",
        sh(service_user),
        sh(service_user),
        sh(&provisioner_dir),
    )];

    for provisioner in model
        .policy
        .provisioners
        .iter()
        .filter(|entry| entry.status == "active" && entry.r#type == "JWK")
        .filter(|entry| entry.name != bootstrap_provisioner)
    {
        let public_jwk = format!("{}/{}.pub.json", provisioner_dir, provisioner.name);
        let private_jwk = format!("{}/{}.priv.json", provisioner_dir, provisioner.name);
        commands.push(format!(
            "if test ! -s {} || test ! -s {}; then rm -f {} {}; STEPPATH={} {} crypto jwk create {} {} --password-file {}; fi",
            sh(&public_jwk),
            sh(&private_jwk),
            sh(&public_jwk),
            sh(&private_jwk),
            sh(&model.deployment.ca_steppath()),
            sh(step_bin),
            sh(&public_jwk),
            sh(&private_jwk),
            sh(password_file)
        ));
        commands.push(format!(
            "chown {}:{} {} {}",
            sh(service_user),
            sh(service_user),
            sh(&public_jwk),
            sh(&private_jwk)
        ));
        commands.push(format!(
            "chmod 0600 {} {}",
            sh(&public_jwk),
            sh(&private_jwk)
        ));
    }

    commands.push(format!(
        "{} materialize-runtime-provisioners --config-root {} --live-ca-json {} --staged-ca-json {} --jwk-dir {} --out-file {}",
        sh(helper_bin),
        sh_display(&model.config_root),
        sh(&ca_config),
        sh(&staged_ca_config),
        sh(&provisioner_dir),
        sh(&staged_ca_config)
    ));
    commands.push(format!(
        "jq -e {} {} >/dev/null",
        sh("[.. | strings | select(startswith(\"RUNTIME_SECRET_PLACEHOLDER:\"))] | length == 0"),
        sh(&staged_ca_config)
    ));
    for provisioner in model
        .policy
        .provisioners
        .iter()
        .filter(|entry| entry.status == "active" && entry.r#type == "JWK")
    {
        commands.push(format!(
            "jq -e {} {} >/dev/null",
            sh(&format!(
                "([.authority.provisioners[] | select(.name == \"{}\" and .type == \"JWK\")] | length) == 1",
                provisioner.name
            )),
            sh(&staged_ca_config)
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

fn runtime_provisioner_secret_dir(password_file: &str) -> String {
    std::path::Path::new(&parent_dir(password_file))
        .join("provisioners")
        .display()
        .to_string()
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

fn sh_home(value: &str) -> String {
    let Some(rest) = value.strip_prefix("$HOME/") else {
        return sh(value);
    };
    format!("$HOME/{}", sh(rest))
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

fn user_private_key_path(key_name: &str) -> String {
    format!("$HOME/.ssh/{key_name}")
}

fn user_cert_path(key_name: &str) -> String {
    format!("$HOME/.ssh/{key_name}-cert.pub")
}

fn user_device_material_dir(user: &str, host: &str) -> String {
    format!("$HOME/.config/grafhome-ca/users/{user}/hosts/{host}")
}

fn checked_ttl<'a>(field: &str, ttl: &'a str) -> Result<&'a str> {
    if ttl.is_empty()
        || !ttl
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'.' | b'h' | b'm' | b's'))
    {
        return Err(Error::Validation {
            field: field.to_owned(),
            message: "duration must use Smallstep units such as 15m, 24h, or 168h".to_owned(),
        });
    }
    Ok(ttl)
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
        OP_ADD_HOST, OP_ADD_USER, OP_BACKUP_CA, OP_CREATE_HOST_TOKEN, OP_CREATE_USER_TOKEN,
        OP_ENROLL_HOST, OP_ENROLL_USER, OP_HOST_BOOTSTRAP, OP_HOST_RENEW, OP_HOST_RENEW_ALL,
        OP_INIT_CA, OP_PROXY_CERT, OP_SSH_ENSURE, OP_VERIFY_LIVE, STEP_ACTIVATE_SERVICE,
        STEP_BACKUP_CA_STATE, STEP_BOOTSTRAP_HOST, STEP_BOOTSTRAP_TRUST, STEP_CONSUME_HOST_TOKEN,
        STEP_CONSUME_USER_TOKEN, STEP_CREATE_HOST_TOKEN, STEP_CREATE_USER_TOKEN, STEP_EDIT_POLICY,
        STEP_ENSURE_USER_CERT, STEP_EXPORT_PUBLIC_MATERIAL, STEP_INITIALIZE_SMALLSTEP_STATE,
        STEP_INSTALL_CLIENT, STEP_INSTALL_RENDERED_FILES, STEP_PROXY_CERT,
        STEP_REGISTER_USER_PROVISIONER, STEP_RENDER, STEP_RENEW_HOST_CERT,
        STEP_RESTORE_TEST_BACKUP, STEP_REVIEW_SECRETS, STEP_VERIFY_CA_API, STEP_VERIFY_PROXY_TLS,
        STEP_VERIFY_SSH, add_host, add_user, backup_ca, create_host_token, create_user_token,
        enroll_host, enroll_user, host_bootstrap, host_renew, host_renew_all, init_ca, proxy_cert,
        renewable_hosts, sh, ssh_ensure, verify_live,
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
                STEP_ACTIVATE_SERVICE,
                STEP_BACKUP_CA_STATE,
                STEP_RESTORE_TEST_BACKUP
            ]
        );
        assert!(!plan.steps[0].manual);
        assert!(plan.steps[1..].iter().all(|step| step.manual));
        assert_eq!(plan.steps[1].hosts, vec!["ca-host".to_owned()]);
        assert!(
            plan.steps[1].commands[0].contains("getent group step-ca || groupadd --system step-ca")
        );
        assert!(plan.steps[1].commands[1].contains(
            "if ! id -u step-ca >/dev/null 2>&1; then service_shell=\"$(command -v nologin || true)\";"
        ));
        assert!(!plan.steps[1].commands[1].contains("--shell /usr/bin/nologin"));
        assert!(!plan.steps[1].commands[1].contains("command -v false"));
        assert!(plan.steps[1].commands[1].contains(
            "for candidate in /usr/sbin/nologin /usr/bin/nologin /sbin/nologin /bin/false /usr/bin/false"
        ));
        assert!(plan.steps[1].commands[1].contains(
            "useradd --system --gid step-ca --home-dir /srv/example-ca --shell \"$service_shell\" --comment 'Grafhome CA service' step-ca"
        ));
        assert!(plan.steps[1].commands[2].contains("id step-ca"));
        assert!(plan.steps[1].commands[3].contains("getent group step-ca"));
        assert!(plan.steps[1].commands[4].contains(
            "install -d -o step-ca -g step-ca -m 0750 /srv/example-ca /srv/example-ca/step"
        ));
        assert!(
            plan.steps[1].commands[5]
                .contains("install -d -o step-ca -g step-ca -m 0700 /srv/example-ca/secrets")
        );
        assert!(plan.steps[1].commands[6].contains(
            "install -o step-ca -g step-ca -m 0600 /dev/null /srv/example-ca/secrets/intermediate_ca_password"
        ));
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("crypto rand --format ascii 48"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("--dns ca.example.test"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("--dns ca-origin.example.test"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("--address 198.51.100.20:8443"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("--with-ca-url https://ca.example.test"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("chown -R step-ca:step-ca /srv/example-ca"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains(
                    "chown step-ca:step-ca /srv/example-ca/secrets/intermediate_ca_password"
                ))
        );
        assert!(plan.steps[1].commands.iter().any(|command| {
            command.contains("chmod 0600 /srv/example-ca/secrets/intermediate_ca_password")
        }));
        assert!(
            !plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("umask 077"))
        );
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("crypto jwk create")
                    && command.contains("grafhome-user-enrollment.pub.json")
                    && command.contains("grafhome-user-enrollment.priv.json"))
        );
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("materialize-runtime-provisioners"))
        );
        assert!(
            !plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("ca provisioner add"))
        );
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("grafhome-host-bootstrap")
                    && command.contains("type == \"JWK\""))
        );
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("grafhome-user-enrollment")
                    && command.contains("type == \"JWK\""))
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
                .any(|command| command.contains(
                    "install -D -o step-ca -g step-ca -m 0640 '<staging-dir>/hosts/ca-host/srv/example-ca/step/config/ca.json' /srv/example-ca/step/config/ca.json"
                ))
        );
        assert!(
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command
                    .contains("/etc/apache2/conf-available/grafhome-ca-proxy.conf"))
        );
        assert!(plan.steps[4].commands[0].contains("export-public"));
        assert!(
            plan.steps[5]
                .summary
                .contains("repair CA service ownership")
        );
        assert!(
            plan.steps[5]
                .commands
                .iter()
                .position(|command| command.contains("chown -R step-ca:step-ca /srv/example-ca"))
                .unwrap()
                < plan.steps[5]
                    .commands
                    .iter()
                    .position(|command| command.contains("systemctl enable --now step-ca.service"))
                    .unwrap()
        );
        assert!(
            plan.steps[5]
                .files
                .contains(&"/srv/example-ca/step/config/ca.json".to_owned())
        );
        assert!(plan.steps[6].commands[1].contains("tar -C /srv -cpf"));
        assert!(plan.steps[7].commands[0].contains("tar -C \"$restore_dir\" -xpf"));
        assert!(
            plan.steps[7]
                .commands
                .iter()
                .any(|command| command.contains("intermediate_ca_key"))
        );
    }

    #[test]
    fn init_ca_plan_uses_configured_service_account() {
        let mut model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        model.deployment.values.insert(
            "GRAFHOME_CA_SERVICE_USER".to_owned(),
            "grafhome-ca".to_owned(),
        );
        let plan = init_ca(&model).unwrap();

        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("getent group grafhome-ca"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("useradd --system --gid grafhome-ca"))
        );
        assert!(
            plan.steps[1]
                .commands
                .iter()
                .any(|command| command.contains("chown -R grafhome-ca:grafhome-ca"))
        );
        assert!(plan.steps[3].commands.iter().any(|command| command.contains(
            "install -D -o grafhome-ca -g grafhome-ca -m 0640"
        )));
        assert!(
            plan.steps[5]
                .commands
                .iter()
                .any(|command| command.contains("chown -R grafhome-ca:grafhome-ca"))
        );
    }

    #[test]
    fn host_bootstrap_keeps_generic_rendered_file_installs() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = host_bootstrap(&model, "ca-host").unwrap();

        assert!(plan.steps.iter().any(|step| step.commands.iter().any(
            |command| command.contains(
                "install -D -m 0640 '<staging-dir>/hosts/ca-host/srv/example-ca/step/config/ca.json' /srv/example-ca/step/config/ca.json"
            )
        )));
        assert!(!plan.steps.iter().any(|step| {
            step.commands
                .iter()
                .any(|command| command.contains("install -D -o step-ca -g step-ca"))
        }));
    }

    #[test]
    fn plans_backup_ca_with_restore_test_gate() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = backup_ca(&model).unwrap();

        assert_eq!(plan.operation, OP_BACKUP_CA);
        assert_eq!(
            step_ids(&plan),
            vec![STEP_BACKUP_CA_STATE, STEP_RESTORE_TEST_BACKUP]
        );
        assert!(plan.steps.iter().all(|step| step.manual));
        assert!(plan.steps[0].commands[1].contains("tar -C /srv -cpf"));
        assert!(
            plan.steps[1]
                .summary
                .contains("before any host trusts the CA")
        );
    }

    #[test]
    fn plans_proxy_cert_with_configured_acme_webroot() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = proxy_cert(&model).unwrap();

        assert_eq!(plan.operation, OP_PROXY_CERT);
        assert_eq!(
            step_ids(&plan),
            vec![STEP_PROXY_CERT, STEP_VERIFY_PROXY_TLS]
        );
        assert!(
            plan.steps[0].commands[2]
                .contains("install -d -m 0755 /var/www/html/.well-known/acme-challenge")
        );
        assert!(plan.steps[0].commands[1].contains(
            "install -D -m 0644 '<public-material-dir>/root_ca.crt' /etc/ssl/example-ca/root_ca.crt"
        ));
        assert!(plan.steps[0].commands[3].contains("step ca certificate"));
        assert!(plan.steps[0].commands[3].contains("--provisioner grafhome-x509-ca-proxy"));
        assert!(plan.steps[0].commands[3].contains("--webroot /var/www/html"));
        assert!(!plan.steps[0].commands[3].contains("<acme-challenge-mode>"));
        assert!(
            plan.steps[0]
                .files
                .contains(&"/etc/ssl/example-ca/ca.example.test.crt".to_owned())
        );
        assert!(
            plan.steps[0]
                .files
                .contains(&"/etc/ssl/example-ca/root_ca.crt".to_owned())
        );
    }

    #[test]
    fn plans_live_verification_checks() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = verify_live(&model, Some("proxy-host")).unwrap();

        assert_eq!(plan.operation, OP_VERIFY_LIVE);
        assert_eq!(
            step_ids(&plan),
            vec![STEP_VERIFY_CA_API, STEP_VERIFY_PROXY_TLS, STEP_VERIFY_SSH]
        );
        assert!(plan.steps[0].commands[0].contains("step ca health"));
        assert!(
            plan.steps[1]
                .commands
                .contains(&"test -s /etc/ssl/example-ca/root_ca.crt".to_owned())
        );
        assert!(
            plan.steps[1].commands.contains(
                &"cmp -s /etc/ssl/example-ca/root_ca.crt '<public-material-dir>/root_ca.crt'"
                    .to_owned()
            )
        );
        assert!(plan.steps[1].commands[5].contains("openssl s_client"));
        assert!(plan.steps[1].commands[5].contains("-verify_hostname ca.example.test"));
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("sshd -T"))
        );
        assert!(
            plan.steps[2]
                .commands
                .iter()
                .any(|command| command.contains("ssh -G"))
        );
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
                STEP_CREATE_HOST_TOKEN,
                STEP_INSTALL_RENDERED_FILES
            ]
        );
        assert_eq!(plan.steps[0].hosts, vec!["proxy-host".to_owned()]);
        assert_eq!(plan.steps[1].hosts, vec!["proxy-host".to_owned()]);
        assert_eq!(
            plan.steps[2].hosts,
            vec!["ca-host".to_owned(), "proxy-host".to_owned()]
        );
        assert_eq!(plan.steps[3].hosts, vec!["proxy-host".to_owned()]);
        assert!(!plan.steps[0].manual);
        assert!(plan.steps[1].manual);
        assert!(plan.steps[1].commands[0].contains("ca bootstrap"));
        assert!(plan.steps[1].commands[0].contains("https://ca.example.test"));
        assert!(
            plan.steps[1].commands[0].contains("$(cat '<public-material-dir>/root_fingerprint')")
        );
        assert!(plan.steps[1].commands[0].contains("STEPPATH=/etc/step/grafhome"));
        assert_eq!(
            plan.steps[2].commands,
            vec![
                "grafhome-ca approve-host",
                "grafhome-ca enroll-host --host proxy-host"
            ]
        );
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
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command == "sshd -t")
        );
        assert!(
            plan.steps[3]
                .commands
                .iter()
                .any(|command| command == "systemctl reload ssh || systemctl reload sshd")
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
        assert_eq!(
            plan.steps[0].commands[0],
            "grafhome-ca renew-host --host edge-host"
        );
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
                .all(|step| step.commands[0].starts_with("grafhome-ca renew-host --host "))
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
    fn plans_host_token_creation_with_short_lived_token_and_configured_cert_ttl() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = create_host_token(&model, "proxy-host", None, Some("168h")).unwrap();

        assert_eq!(plan.operation, OP_CREATE_HOST_TOKEN);
        assert_eq!(step_ids(&plan), vec![STEP_CREATE_HOST_TOKEN]);
        assert_eq!(plan.steps[0].hosts, vec!["ca-host".to_owned()]);
        assert!(plan.steps[0].manual);
        assert!(plan.steps[0].commands[0].contains("step ca token proxy-host"));
        assert!(plan.steps[0].commands[0].contains("--ssh --host"));
        assert!(plan.steps[0].commands[0].contains("--principal proxy-host"));
        assert!(plan.steps[0].commands[0].contains("--not-after 15m"));
        assert!(plan.steps[0].commands[0].contains("--cert-not-after 168h"));
        assert!(plan.steps[0].commands[0].contains(
            "--provisioner-password-file /srv/example-ca/secrets/intermediate_ca_password"
        ));
    }

    #[test]
    fn plans_host_enrollment_without_provisioner_password_on_target() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = enroll_host(&model, "proxy-host").unwrap();

        assert_eq!(plan.operation, OP_ENROLL_HOST);
        assert_eq!(step_ids(&plan), vec![STEP_CONSUME_HOST_TOKEN]);
        assert_eq!(plan.steps[0].hosts, vec!["proxy-host".to_owned()]);
        assert!(plan.steps[0].commands[0].contains("step ssh certificate proxy-host"));
        assert!(plan.steps[0].commands[0].contains("--token '<host-enrollment-token>'"));
        assert!(!plan.steps[0].commands[0].contains("--provisioner-password-file"));
        assert!(plan.steps[0].commands[1].contains("sshd -t"));
    }

    #[test]
    fn plans_user_token_creation_for_client_host() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = create_user_token(&model, "alice", "ca-host", None, Some("24h")).unwrap();

        assert_eq!(plan.operation, OP_CREATE_USER_TOKEN);
        assert_eq!(step_ids(&plan), vec![STEP_CREATE_USER_TOKEN]);
        assert_eq!(plan.steps[0].hosts, vec!["ca-host".to_owned()]);
        assert!(plan.steps[0].commands[0].contains("step ca token alice"));
        assert!(plan.steps[0].commands[0].contains("--principal alice"));
        assert!(plan.steps[0].commands[0].contains("--not-after 15m"));
        assert!(plan.steps[0].commands[0].contains("--cert-not-after 24h"));
        assert!(plan.steps[0].commands[0].contains("--provisioner grafhome-user-enrollment"));
    }

    #[test]
    fn token_creation_reports_missing_ca_api_endpoint() {
        let mut model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        model
            .policy
            .endpoints
            .retain(|endpoint| endpoint.role != "ca_api");

        let host_error = create_host_token(&model, "ca-host", None, None)
            .unwrap_err()
            .to_string();
        let user_error = create_user_token(&model, "alice", "ca-host", None, None)
            .unwrap_err()
            .to_string();

        assert!(host_error.contains("missing required endpoint"));
        assert!(host_error.contains("ca_api"));
        assert!(user_error.contains("missing required endpoint"));
        assert!(user_error.contains("ca_api"));
    }

    #[test]
    fn plans_user_enrollment_with_constrained_device_jwk() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = enroll_user(&model, "alice", "ca-host").unwrap();

        assert_eq!(plan.operation, OP_ENROLL_USER);
        assert_eq!(
            step_ids(&plan),
            vec![STEP_CONSUME_USER_TOKEN, STEP_REGISTER_USER_PROVISIONER]
        );
        assert_eq!(
            plan.steps[0].commands,
            vec!["grafhome-ca enroll-user --user alice --host ca-host"]
        );
        assert_eq!(plan.steps[1].commands, vec!["grafhome-ca approve-user"]);
        assert_eq!(plan.steps[0].hosts, vec!["ca-host"]);
        assert_eq!(plan.steps[1].hosts, vec!["ca-host"]);
    }

    #[test]
    fn plans_ssh_ensure_as_non_manual_local_reissue() {
        let model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let plan = ssh_ensure(&model, "alice", Some("ca-host")).unwrap();

        assert_eq!(plan.operation, OP_SSH_ENSURE);
        assert_eq!(step_ids(&plan), vec![STEP_ENSURE_USER_CERT]);
        assert!(!plan.steps[0].manual);
        assert_eq!(plan.steps[0].hosts, vec!["ca-host".to_owned()]);
        assert!(plan.steps[0].commands[0].contains("ca token alice"));
        assert!(
            plan.steps[0].commands[0].contains("--issuer grafhome-user-616c696365-63612d686f7374")
        );
        assert!(plan.steps[0].commands[0].contains("--cert-not-after 24h"));
        assert!(plan.steps[0].commands[0].contains("step ssh certificate alice"));
    }

    #[test]
    fn user_enrollment_plan_rejects_disabled_user() {
        let mut model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        model
            .policy
            .users
            .iter_mut()
            .find(|user| user.user == "alice")
            .unwrap()
            .status = "disabled".to_owned();
        let error = create_user_token(&model, "alice", "ca-host", None, None)
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
            vec![STEP_EDIT_POLICY, STEP_CREATE_USER_TOKEN]
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
            vec![
                "grafhome-ca enroll-user --user new-user --host '<client-host>'",
                "grafhome-ca approve-user"
            ]
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
