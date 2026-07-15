//! Human-oriented policy document loading and serialization.
//!
//! The public TOML layout is intentionally organized around the units people
//! edit. The rest of the crate consumes the normalized [`Policy`] model, so
//! document layout changes cannot leak into authorization or rendering logic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    CA_POLICY_PATH, Endpoint, HOST_POLICY_DIR, Host, LEGACY_POLICY_PATHS,
    PROVISIONER_ROLE_USER_ENROLLMENT, Policy, Provisioner, USERS_POLICY_PATH, User, UserClient,
    UserRemote, provisioner_role_rank, read_typed_document,
};
use crate::error::{Error, Result};

/// Policy document layout detected below a config root.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Format {
    /// Canonical host-centric policy documents.
    Canonical,
    /// Compatibility layout with six normalized array-of-table documents.
    Legacy,
}

/// One canonical policy file ready to be written below a policy directory.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct CanonicalFile {
    /// Path relative to the policy directory.
    pub path: PathBuf,
    /// Complete TOML document.
    pub contents: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaDocument {
    endpoints: BTreeMap<String, EndpointPolicy>,
    provisioners: BTreeMap<String, ProvisionerPolicy>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointPolicy {
    dns_name: String,
    target: String,
    address: String,
    port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisionerPolicy {
    name: String,
    r#type: String,
    default_ttl: String,
    max_ttl: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewal_default_ttl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewal_max_ttl: Option<String>,
    status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UsersDocument {
    #[serde(default)]
    require_ssh_admin_access: bool,
    users: BTreeMap<String, UserPolicy>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UserPolicy {
    principal: String,
    cert_ttl: String,
    #[serde(default, skip_serializing_if = "is_false")]
    ssh_admin: bool,
    status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostDocument {
    ssh_server: bool,
    ssh_client: bool,
    principals: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    user_access: BTreeMap<String, HostUserAccess>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostUserAccess {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enrollment: Option<EnrollmentPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    logins: Vec<LoginPolicy>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentPolicy {
    #[serde(default, skip_serializing_if = "is_false")]
    allow_effectively_infinite_cert: bool,
    status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LoginPolicy {
    unix_account: String,
    status: String,
}

/// Detect the policy layout while rejecting ambiguous mixed-format trees.
pub fn detect(root: &Path) -> Result<Format> {
    let canonical = root.join(CA_POLICY_PATH).exists();
    let legacy = LEGACY_POLICY_PATHS
        .iter()
        .filter(|path| **path != USERS_POLICY_PATH)
        .any(|path| root.join(path).exists());
    match (canonical, legacy) {
        (true, false) => Ok(Format::Canonical),
        (false, true) => Ok(Format::Legacy),
        (true, true) => Err(Error::Validation {
            field: "policy format".to_owned(),
            message: "canonical ca.toml cannot be mixed with legacy policy files".to_owned(),
        }),
        (false, false) => Err(Error::Validation {
            field: "policy format".to_owned(),
            message: "missing policy/ca.toml or legacy policy documents".to_owned(),
        }),
    }
}

/// Return the complete policy input inventory in deterministic order.
pub fn input_paths(root: &Path) -> Result<Vec<PathBuf>> {
    match detect(root)? {
        Format::Legacy => Ok(LEGACY_POLICY_PATHS.iter().map(PathBuf::from).collect()),
        Format::Canonical => {
            let mut paths = vec![
                PathBuf::from(CA_POLICY_PATH),
                PathBuf::from(USERS_POLICY_PATH),
            ];
            paths.extend(host_paths(root)?);
            Ok(paths)
        }
    }
}

/// Load canonical documents into the normalized internal model.
pub fn load(root: &Path) -> Result<Policy> {
    let ca: CaDocument = read_document(root.join(CA_POLICY_PATH))?;
    let users: UsersDocument = read_document(root.join(USERS_POLICY_PATH))?;

    let endpoints = ca
        .endpoints
        .into_iter()
        .map(|(role, endpoint)| Endpoint {
            role,
            dns_name: endpoint.dns_name,
            target: endpoint.target,
            address: endpoint.address,
            port: endpoint.port,
            scheme: "https".to_owned(),
        })
        .collect::<Vec<_>>();
    let mut provisioners = ca
        .provisioners
        .into_iter()
        .map(|(role, provisioner)| Provisioner {
            role,
            name: provisioner.name,
            r#type: provisioner.r#type,
            default_ttl: provisioner.default_ttl,
            max_ttl: provisioner.max_ttl,
            renewal_default_ttl: provisioner.renewal_default_ttl,
            renewal_max_ttl: provisioner.renewal_max_ttl,
            status: provisioner.status,
        })
        .collect::<Vec<_>>();
    provisioners.sort_by_key(|provisioner| provisioner_role_rank(&provisioner.role));
    let user_provisioner = provisioners
        .iter()
        .find(|provisioner| provisioner.role == PROVISIONER_ROLE_USER_ENROLLMENT)
        .map(|provisioner| provisioner.name.clone());
    if !users.users.is_empty() && user_provisioner.is_none() {
        return Err(Error::Validation {
            field: "policy/ca.toml:provisioners.user_enrollment".to_owned(),
            message: "required when users are configured".to_owned(),
        });
    }
    let user_provisioner = user_provisioner.unwrap_or_default();
    let policy_users = users
        .users
        .into_iter()
        .map(|(user, policy)| User {
            user,
            principal: policy.principal,
            provisioner: user_provisioner.clone(),
            cert_ttl: policy.cert_ttl,
            ssh_admin: policy.ssh_admin,
            status: policy.status,
        })
        .collect::<Vec<_>>();

    let mut hosts = Vec::new();
    let mut user_clients = Vec::new();
    let mut user_remotes = Vec::new();
    for relative in host_paths(root)? {
        let host = host_name(&relative)?;
        let document: HostDocument = read_document(root.join(&relative))?;
        hosts.push(Host {
            host: host.clone(),
            ssh_server: document.ssh_server,
            ssh_client: document.ssh_client,
            principals: document.principals,
        });
        for (user, access) in document.user_access {
            if let Some(enrollment) = access.enrollment {
                user_clients.push(UserClient {
                    host: host.clone(),
                    user: user.clone(),
                    allow_effectively_infinite_cert: enrollment.allow_effectively_infinite_cert,
                    status: enrollment.status,
                });
            }
            user_remotes.extend(access.logins.into_iter().map(|login| UserRemote {
                user: user.clone(),
                host: host.clone(),
                unix_account: login.unix_account,
                allow_ssh: true,
                status: login.status,
            }));
        }
    }

    Ok(Policy {
        root: root.to_path_buf(),
        endpoints,
        hosts,
        users: policy_users,
        require_ssh_admin_access: users.require_ssh_admin_access,
        provisioners,
        user_clients,
        user_remotes,
    })
}

/// Serialize a normalized policy into canonical host-centric documents.
pub(super) fn canonical_files(policy: &Policy) -> Result<Vec<CanonicalFile>> {
    let ca = CaDocument {
        endpoints: policy
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.role.clone(),
                    EndpointPolicy {
                        dns_name: endpoint.dns_name.clone(),
                        target: endpoint.target.clone(),
                        address: endpoint.address.clone(),
                        port: endpoint.port,
                    },
                )
            })
            .collect(),
        provisioners: policy
            .provisioners
            .iter()
            .map(|provisioner| {
                (
                    provisioner.role.clone(),
                    ProvisionerPolicy {
                        name: provisioner.name.clone(),
                        r#type: provisioner.r#type.clone(),
                        default_ttl: provisioner.default_ttl.clone(),
                        max_ttl: provisioner.max_ttl.clone(),
                        renewal_default_ttl: provisioner.renewal_default_ttl.clone(),
                        renewal_max_ttl: provisioner.renewal_max_ttl.clone(),
                        status: provisioner.status.clone(),
                    },
                )
            })
            .collect(),
    };
    let users = UsersDocument {
        require_ssh_admin_access: policy.require_ssh_admin_access,
        users: policy
            .users
            .iter()
            .map(|user| {
                (
                    user.user.clone(),
                    UserPolicy {
                        principal: user.principal.clone(),
                        cert_ttl: user.cert_ttl.clone(),
                        ssh_admin: user.ssh_admin,
                        status: user.status.clone(),
                    },
                )
            })
            .collect(),
    };

    let mut files = vec![
        canonical_file(policy_output_path(CA_POLICY_PATH), &ca)?,
        canonical_file(policy_output_path(USERS_POLICY_PATH), &users)?,
    ];
    for host in &policy.hosts {
        if !valid_name(&host.host) {
            return Err(Error::Validation {
                field: "policy host inventory".to_owned(),
                message: format!(
                    "host {} cannot be represented as a safe policy filename",
                    host.host
                ),
            });
        }
        let mut user_access = BTreeMap::<String, HostUserAccess>::new();
        for enrollment in policy
            .user_clients
            .iter()
            .filter(|enrollment| enrollment.host == host.host)
        {
            user_access
                .entry(enrollment.user.clone())
                .or_default()
                .enrollment = Some(EnrollmentPolicy {
                allow_effectively_infinite_cert: enrollment.allow_effectively_infinite_cert,
                status: enrollment.status.clone(),
            });
        }
        for login in policy
            .user_remotes
            .iter()
            .filter(|login| login.host == host.host)
        {
            let status = if login.allow_ssh || login.status != "active" {
                login.status.clone()
            } else {
                // The canonical format represents authorization by relationship
                // presence. Preserve an explicit active deny as inert history.
                "disabled".to_owned()
            };
            user_access
                .entry(login.user.clone())
                .or_default()
                .logins
                .push(LoginPolicy {
                    unix_account: login.unix_account.clone(),
                    status,
                });
        }
        let document = HostDocument {
            ssh_server: host.ssh_server,
            ssh_client: host.ssh_client,
            principals: host.principals.clone(),
            user_access,
        };
        files.push(canonical_file(
            policy_output_path(HOST_POLICY_DIR).join(format!("{}.toml", host.host)),
            &document,
        )?);
    }
    Ok(files)
}

fn host_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let directory = root.join(HOST_POLICY_DIR);
    let entries = std::fs::read_dir(&directory).map_err(|source| Error::io(&directory, source))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| Error::io(&directory, source))?;
        let path = entry.path();
        let relative = PathBuf::from(HOST_POLICY_DIR).join(entry.file_name());
        if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
            return Err(Error::Validation {
                field: relative.display().to_string(),
                message: "host policy directory may contain only .toml files".to_owned(),
            });
        }
        host_name(&relative)?;
        paths.push(relative);
    }
    paths.sort();
    Ok(paths)
}

fn host_name(relative: &Path) -> Result<String> {
    let name = relative
        .file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| valid_name(name))
        .ok_or_else(|| Error::Validation {
            field: relative.display().to_string(),
            message: "host filename must match [A-Za-z0-9._-]+.toml".to_owned(),
        })?;
    Ok(name.to_owned())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !matches!(name, "." | "..")
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn read_document<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    read_typed_document(path)
}

fn policy_output_path(path: &str) -> PathBuf {
    PathBuf::from(
        path.strip_prefix("policy/")
            .expect("canonical policy paths live below policy/"),
    )
}

fn canonical_file(path: impl Into<PathBuf>, document: &impl Serialize) -> Result<CanonicalFile> {
    let path = path.into();
    let contents = toml::to_string_pretty(document).map_err(|source| Error::Validation {
        field: path.display().to_string(),
        message: format!("could not serialize canonical policy: {source}"),
    })?;
    Ok(CanonicalFile { path, contents })
}

fn is_false(value: &bool) -> bool {
    !value
}
