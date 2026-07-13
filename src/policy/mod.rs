//! Policy file parsing and validation.
//!
//! Policy files are typed TOML documents so they remain easy to inspect,
//! comment, and edit by hand without reducing booleans or lists to strings.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Policy sentinel for an effectively unlimited certificate lifetime.
pub const UNLIMITED_TTL: &str = "unlimited";

/// Largest whole-hour duration supported by Go's `time.Duration`.
pub const STEP_EFFECTIVE_UNLIMITED_TTL: &str = "2562047h";

/// Convert a policy maximum into the duration accepted by Smallstep.
#[must_use]
pub fn step_max_ttl(max_ttl: &str) -> &str {
    if max_ttl == UNLIMITED_TTL {
        STEP_EFFECTIVE_UNLIMITED_TTL
    } else {
        max_ttl
    }
}

/// Endpoint entry from `policy/endpoints.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Endpoint role. Current values are `ca_api` and `ca_origin`.
    pub role: String,
    /// DNS name clients or proxies use for this endpoint.
    pub dns_name: String,
    /// Host policy name that owns the endpoint.
    pub target: String,
    /// IP address currently associated with the endpoint.
    pub address: String,
    /// TCP port for the endpoint.
    pub port: u16,
    /// URL scheme. Only `https` is supported.
    pub scheme: String,
}

impl Endpoint {
    /// Derived endpoint URL.
    #[must_use]
    pub fn url(&self) -> String {
        let default_port = self.scheme == "https" && self.port == 443;
        if default_port {
            format!("{}://{}", self.scheme, self.dns_name)
        } else {
            format!("{}://{}:{}", self.scheme, self.dns_name, self.port)
        }
    }
}

/// Host entry from `policy/hosts.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// Stable host name used by policy references.
    pub host: String,
    /// Whether this host should accept SSH server connections.
    pub ssh_server: bool,
    /// Whether this host should act as an SSH client.
    pub ssh_client: bool,
    /// Host certificate principals.
    pub principals: Vec<String>,
}

/// User entry from `policy/users.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Stable policy user name.
    pub user: String,
    /// SSH certificate principal granted to this user.
    pub principal: String,
    /// Provisioner used for user certificate issuance.
    pub provisioner: String,
    /// User certificate lifetime.
    pub cert_ttl: String,
    /// Policy status.
    pub status: String,
}

/// Provisioner entry from `policy/provisioners.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provisioner {
    /// Provisioner role in Grafhome policy.
    pub role: String,
    /// Smallstep provisioner name.
    pub name: String,
    /// Smallstep provisioner type.
    pub r#type: String,
    /// Default certificate lifetime.
    pub default_ttl: String,
    /// Maximum certificate lifetime.
    pub max_ttl: String,
    /// Policy status.
    pub status: String,
}

/// User certificate source entry from `policy/user-clients.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserClient {
    /// Enrolled host where the user certificate is stored.
    pub host: String,
    /// Policy user whose SSH certs this host may request.
    pub user: String,
    /// Policy status.
    pub status: String,
}

/// User login destination entry from `policy/user-remotes.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserRemote {
    /// Policy user.
    pub user: String,
    /// Target host.
    pub host: String,
    /// Unix account on the target host.
    pub unix_account: String,
    /// Whether SSH access is allowed.
    pub allow_ssh: bool,
    /// Policy status.
    pub status: String,
}

/// Parsed policy set.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Repository root used to load the policy.
    pub root: PathBuf,
    /// Configured CA endpoints.
    pub endpoints: Vec<Endpoint>,
    /// Managed host inventory.
    pub hosts: Vec<Host>,
    /// Managed users.
    pub users: Vec<User>,
    /// Smallstep provisioners.
    pub provisioners: Vec<Provisioner>,
    /// Hosts where users may enroll and renew certificates.
    pub user_clients: Vec<UserClient>,
    /// User-to-host SSH access map.
    pub user_remotes: Vec<UserRemote>,
}

impl Policy {
    /// Load the initial policy files needed for config-only validation.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let endpoints = read_typed(root.join("policy/endpoints.toml"), "endpoints")?;
        let hosts = read_typed(root.join("policy/hosts.toml"), "hosts")?;
        let users = read_typed(root.join("policy/users.toml"), "users")?;
        let provisioners = read_typed(root.join("policy/provisioners.toml"), "provisioners")?;
        let user_clients = read_typed(root.join("policy/user-clients.toml"), "user_clients")?;
        let user_remotes = read_typed(root.join("policy/user-remotes.toml"), "user_remotes")?;
        let policy = Self {
            root: root.to_path_buf(),
            endpoints,
            hosts,
            users,
            provisioners,
            user_clients,
            user_remotes,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Return an endpoint by role.
    #[must_use]
    pub fn endpoint(&self, role: &str) -> Option<&Endpoint> {
        self.endpoints.iter().find(|endpoint| endpoint.role == role)
    }

    /// Return a host by policy name.
    #[must_use]
    pub fn host(&self, name: &str) -> Option<&Host> {
        self.hosts.iter().find(|host| host.host == name)
    }

    /// Return a user by policy name.
    #[must_use]
    pub fn user(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|user| user.user == name)
    }

    /// Active user-host rows that grant SSH access.
    pub fn active_ssh_access(&self) -> impl Iterator<Item = &UserRemote> {
        self.user_remotes.iter().filter(|access| {
            access.status == "active"
                && access.allow_ssh
                && self
                    .user(&access.user)
                    .is_some_and(|user| user.status == "active")
        })
    }

    /// Active client hosts for a policy user.
    pub fn active_user_clients(&self, user: &str) -> impl Iterator<Item = &UserClient> {
        self.user_clients
            .iter()
            .filter(move |client| client.status == "active" && client.user == user)
    }

    fn validate(&self) -> Result<()> {
        let mut roles = BTreeSet::new();
        for endpoint in &self.endpoints {
            if !matches!(endpoint.role.as_str(), "ca_api" | "ca_origin") {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.toml:{}.role", endpoint.role),
                    message: "endpoint role must be ca_api or ca_origin".to_owned(),
                });
            }
            if !roles.insert(endpoint.role.as_str()) {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.toml:{}.role", endpoint.role),
                    message: "duplicate endpoint role".to_owned(),
                });
            }
            if endpoint.scheme != "https" {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.toml:{}.scheme", endpoint.role),
                    message: "only https endpoints are supported".to_owned(),
                });
            }
        }
        for required in ["ca_api", "ca_origin"] {
            if !roles.contains(required) {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.toml:{required}"),
                    message: "missing required endpoint role".to_owned(),
                });
            }
        }

        let hosts = self
            .hosts
            .iter()
            .map(|host| host.host.clone())
            .collect::<BTreeSet<_>>();
        if hosts.len() != self.hosts.len() {
            return Err(Error::Validation {
                field: "policy/hosts.toml:host".to_owned(),
                message: "duplicate host".to_owned(),
            });
        }
        for endpoint in &self.endpoints {
            if !hosts.contains(&endpoint.target) {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.toml:{}.target", endpoint.role),
                    message: format!("unknown host {}", endpoint.target),
                });
            }
        }

        self.validate_relations(&hosts)?;
        Ok(())
    }

    fn validate_relations(&self, hosts: &BTreeSet<String>) -> Result<()> {
        let users = unique_values(
            "policy/users.toml",
            self.users.iter().map(|user| user.user.as_str()),
            "user",
        )?;
        let user_principals = unique_values(
            "policy/users.toml",
            self.users.iter().map(|user| user.principal.as_str()),
            "principal",
        )?;
        let provisioners = unique_values(
            "policy/provisioners.toml",
            self.provisioners
                .iter()
                .map(|provisioner| provisioner.name.as_str()),
            "name",
        )?;
        unique_values(
            "policy/provisioners.toml",
            self.provisioners
                .iter()
                .map(|provisioner| provisioner.role.as_str()),
            "role",
        )?;

        for user in &self.users {
            let name = user.user.as_str();
            reject_root_identity("policy/users.toml", name, "user", name)?;
            reject_root_identity("policy/users.toml", name, "principal", &user.principal)?;
            ensure_contains(
                "policy/users.toml",
                name,
                "provisioner",
                &user.provisioner,
                provisioners.iter(),
            )?;
            let provisioner = self
                .provisioners
                .iter()
                .find(|provisioner| provisioner.name == user.provisioner)
                .expect("provisioner existence was validated");
            if provisioner.role != "user_enrollment" {
                return Err(Error::Validation {
                    field: format!("policy/users.toml:{name}.provisioner"),
                    message: "user provisioner must use role user_enrollment".to_owned(),
                });
            }
            validate_step_duration("policy/users.toml", name, "cert_ttl", &user.cert_ttl)?;
        }

        for provisioner in &self.provisioners {
            validate_step_duration(
                "policy/provisioners.toml",
                &provisioner.role,
                "default_ttl",
                &provisioner.default_ttl,
            )?;
            if provisioner.max_ttl == UNLIMITED_TTL {
                if provisioner.role != "user_enrollment" {
                    return Err(Error::Validation {
                        field: format!("policy/provisioners.toml:{}.max_ttl", provisioner.role),
                        message: "unlimited is supported only for user_enrollment".to_owned(),
                    });
                }
            } else {
                validate_step_duration(
                    "policy/provisioners.toml",
                    &provisioner.role,
                    "max_ttl",
                    &provisioner.max_ttl,
                )?;
            }
        }

        // Certificate principals share one Smallstep namespace. A collision
        // could make a user certificate valid as a host, or vice versa.
        let mut certificate_principals = user_principals;
        for host in &self.hosts {
            for principal in &host.principals {
                if !certificate_principals.insert(principal.clone()) {
                    return Err(Error::Validation {
                        field: format!("policy/hosts.toml:{}.principals", host.host),
                        message: format!("duplicate certificate principal {principal}"),
                    });
                }
            }
        }

        let mut access_rows = BTreeSet::new();
        for access in &self.user_remotes {
            ensure_contains(
                "policy/user-remotes.toml",
                &access.user,
                "user",
                &access.user,
                users.iter(),
            )?;
            ensure_contains(
                "policy/user-remotes.toml",
                &access.user,
                "host",
                &access.host,
                hosts.iter(),
            )?;
            let remote = self
                .host(&access.host)
                .expect("remote host existence was validated");
            if access.allow_ssh && !remote.ssh_server {
                return Err(Error::Validation {
                    field: format!("policy/user-remotes.toml:{}.host", access.user),
                    message: format!("host {} is not an SSH server", access.host),
                });
            }
            if access.allow_ssh {
                reject_root_identity(
                    "policy/user-remotes.toml",
                    &access.user,
                    "unix_account",
                    &access.unix_account,
                )?;
            }
            let key = (
                access.user.clone(),
                access.host.clone(),
                access.unix_account.clone(),
            );
            if !access_rows.insert(key) {
                return Err(Error::Validation {
                    field: format!("policy/user-remotes.toml:{}", access.user),
                    message: format!(
                        "duplicate access row for {}@{} as {}",
                        access.user, access.host, access.unix_account
                    ),
                });
            }
        }

        let mut clients = BTreeSet::new();
        for client in &self.user_clients {
            ensure_contains(
                "policy/user-clients.toml",
                &client.host,
                "host",
                &client.host,
                hosts.iter(),
            )?;
            ensure_contains(
                "policy/user-clients.toml",
                &client.host,
                "user",
                &client.user,
                users.iter(),
            )?;
            let host = self
                .host(&client.host)
                .expect("client host existence was validated");
            if !host.ssh_client {
                return Err(Error::Validation {
                    field: format!("policy/user-clients.toml:{}.host", client.user),
                    message: format!("host {} is not an SSH client", client.host),
                });
            }
            if !clients.insert((client.user.clone(), client.host.clone())) {
                return Err(Error::Validation {
                    field: format!("policy/user-clients.toml:{}", client.host),
                    message: format!(
                        "duplicate user client {} for user {}",
                        client.host, client.user
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Read a TOML policy document into a JSON value for schema validation.
pub fn read_document(path: impl AsRef<Path>) -> Result<serde_json::Value> {
    let path = path.as_ref();
    let document = read_toml(path)?;
    Ok(serde_json::to_value(document).expect("TOML document serializes as JSON"))
}

fn read_toml(path: &Path) -> Result<toml::Value> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
    toml::from_str::<toml::Value>(&text).map_err(|source| Error::Toml {
        path: path.to_path_buf(),
        source,
    })
}

fn read_typed<T>(path: impl AsRef<Path>, table: &str) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let path = path.as_ref();
    let mut document = read_toml(path)?;
    let object = document.as_table_mut().ok_or_else(|| Error::Parse {
        path: path.to_path_buf(),
        line: 1,
        message: "policy document must be a TOML table".to_owned(),
    })?;
    if object.len() != 1 || !object.contains_key(table) {
        return Err(Error::Parse {
            path: path.to_path_buf(),
            line: 1,
            message: format!("policy document must contain only [[{table}]] entries"),
        });
    }
    object
        .remove(table)
        .expect("table exists")
        .try_into()
        .map_err(|source| Error::Toml {
            path: path.to_path_buf(),
            source,
        })
}

fn unique_values<'a>(
    table: &str,
    values: impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<BTreeSet<String>> {
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value.to_owned()) {
            return Err(Error::Validation {
                field: format!("{table}:{key}"),
                message: format!("duplicate {key} {value}"),
            });
        }
    }
    Ok(unique)
}

fn reject_root_identity(table: &str, row_id: &str, field: &str, identity: &str) -> Result<()> {
    if identity == "root" {
        Err(Error::Validation {
            field: format!("{table}:{row_id}.{field}"),
            message: "root SSH identities are not supported".to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_step_duration(table: &str, row_id: &str, field: &str, duration: &str) -> Result<()> {
    let (digits, unit) = duration.split_at(duration.len().saturating_sub(1));
    let valid = !digits.is_empty()
        && digits.as_bytes()[0] != b'0'
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(unit, "s" | "m" | "h");
    if valid {
        Ok(())
    } else {
        Err(Error::Validation {
            field: format!("{table}:{row_id}.{field}"),
            message: "step-ca durations must use Go-style s, m, or h units".to_owned(),
        })
    }
}

fn ensure_contains<'a>(
    table: &str,
    row_id: &str,
    field: &str,
    value: &str,
    allowed: impl Iterator<Item = &'a String>,
) -> Result<()> {
    if allowed.into_iter().any(|allowed| allowed == value) {
        Ok(())
    } else {
        Err(Error::Validation {
            field: format!("{table}:{row_id}.{field}"),
            message: format!("unknown {field} {value}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::Policy;

    #[test]
    fn checked_in_policy_loads() {
        let policy = Policy::load(crate::example_config_root()).expect("policy loads");

        assert_eq!(
            policy.endpoint("ca_api").unwrap().url(),
            "https://ca.example.test"
        );
        assert_eq!(
            policy.endpoint("ca_origin").unwrap().url(),
            "https://ca-origin.example.test:8443"
        );
    }

    #[test]
    fn accepts_toml_comments() {
        let (dir, policy_dir) = copy_policy();
        let hosts = policy_dir.join("hosts.toml");
        let text = fs::read_to_string(&hosts).unwrap();
        fs::write(&hosts, format!("# Fleet host inventory.\n{text}")).unwrap();

        Policy::load(dir.path()).expect("comments are valid in policy TOML");
    }

    #[test]
    fn rejects_string_instead_of_boolean() {
        let (dir, policy_dir) = copy_policy();
        let hosts = policy_dir.join("hosts.toml");
        let text = fs::read_to_string(&hosts).unwrap().replacen(
            "ssh_server = true",
            "ssh_server = \"yes\"",
            1,
        );
        fs::write(&hosts, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("hosts.toml"));
        assert!(error.contains("boolean"));
    }

    #[test]
    fn rejects_user_client_on_host_without_ssh_client_role() {
        let (dir, policy_dir) = copy_policy();
        let hosts = policy_dir.join("hosts.toml");
        let text = fs::read_to_string(&hosts).unwrap().replacen(
            "ssh_client = true",
            "ssh_client = false",
            1,
        );
        fs::write(&hosts, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("host ca-host is not an SSH client"));
    }

    #[test]
    fn rejects_user_remote_on_host_without_ssh_server_role() {
        let (dir, policy_dir) = copy_policy();
        let hosts = policy_dir.join("hosts.toml");
        let text = fs::read_to_string(&hosts).unwrap().replacen(
            "ssh_server = true",
            "ssh_server = false",
            1,
        );
        fs::write(&hosts, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("host ca-host is not an SSH server"));
    }

    #[test]
    fn rejects_wrong_document_table() {
        let (dir, policy_dir) = copy_policy();
        let hosts = policy_dir.join("hosts.toml");
        let text = fs::read_to_string(&hosts)
            .unwrap()
            .replace("[[hosts]]", "[[host_inventory]]");
        fs::write(&hosts, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("must contain only [[hosts]] entries"));
    }

    #[test]
    fn rejects_dangling_user_provisioner() {
        let (dir, policy_dir) = copy_policy();

        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("grafhome-user-enrollment", "missing-provisioner");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("unknown provisioner missing-provisioner"));
    }

    #[test]
    fn rejects_user_provisioner_with_wrong_role() {
        let (dir, policy_dir) = copy_policy();

        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("grafhome-user-enrollment", "grafhome-host-bootstrap");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("user provisioner must use role user_enrollment"));
    }

    #[test]
    fn rejects_root_user_identity() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("user = \"alice\"", "user = \"root\"")
            .replace("principal = \"alice\"", "principal = \"root\"");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("root SSH identities are not supported"));
    }

    #[test]
    fn rejects_user_principal_that_collides_with_host_principal() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("principal = \"alice\"", "principal = \"ca-host\"");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("duplicate certificate principal ca-host"));
    }

    #[test]
    fn rejects_duplicate_user_principal() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let mut user_text = fs::read_to_string(&users).unwrap();
        user_text.push_str(
            "\n[[users]]\nuser = \"bob\"\nprincipal = \"alice\"\n\
             provisioner = \"grafhome-user-enrollment\"\ncert_ttl = \"24h\"\n\
             status = \"active\"\n",
        );
        fs::write(&users, user_text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("duplicate principal alice"));
    }

    #[test]
    fn rejects_step_duration_day_unit() {
        let (dir, policy_dir) = copy_policy();
        let provisioners = policy_dir.join("provisioners.toml");
        let text = fs::read_to_string(&provisioners).unwrap().replacen(
            "default_ttl = \"168h\"",
            "default_ttl = \"30d\"",
            1,
        );
        fs::write(&provisioners, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("step-ca durations must use Go-style"));
    }

    #[test]
    fn rejects_unlimited_maximum_for_non_user_provisioner() {
        let (dir, policy_dir) = copy_policy();
        let provisioners = policy_dir.join("provisioners.toml");
        let text = fs::read_to_string(&provisioners).unwrap().replacen(
            "max_ttl = \"720h\"",
            "max_ttl = \"unlimited\"",
            1,
        );
        fs::write(&provisioners, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("unlimited is supported only for user_enrollment"));
    }

    fn copy_policy() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        fs::create_dir(&policy_dir).unwrap();

        for entry in fs::read_dir(crate::example_config_root().join("policy")).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), policy_dir.join(entry.file_name())).unwrap();
        }
        (dir, policy_dir)
    }
}
