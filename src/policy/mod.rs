//! Policy file parsing and validation.
//!
//! Policy files are typed TOML documents so they remain easy to inspect,
//! comment, and edit by hand without reducing booleans or lists to strings.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Endpoint entry from `policy/endpoints.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Endpoint role. Current values are `ca_api` and `ca_origin`.
    pub role: String,
    /// Stable policy name for this endpoint.
    pub name: String,
    /// DNS name clients or proxies use for this endpoint.
    pub dns_name: String,
    /// Host policy name that owns the endpoint.
    pub target: String,
    /// Network interface expected to carry this endpoint.
    pub interface: String,
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
    /// Host class, such as `server` or `personal-laptop`.
    pub kind: String,
    /// Whether this host should accept SSH server connections.
    pub ssh_server: bool,
    /// Whether this host should act as an SSH client.
    pub ssh_client: bool,
    /// Scheduler or operator expected to renew this host's certificates.
    pub renewal_owner: String,
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
    /// Default Unix account for this user.
    pub unix_account: String,
    /// Whether root SSH is allowed. Validation rejects `true`.
    pub root_ssh: bool,
    /// Provisioner used for user certificate issuance.
    pub provisioner: String,
    /// User certificate lifetime.
    pub cert_ttl: String,
    /// Policy status.
    pub status: String,
    /// Free-form operator notes.
    pub notes: String,
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
    /// Renewal check cadence.
    pub renewal_check: String,
    /// Policy status.
    pub status: String,
    /// Free-form operator notes.
    pub notes: String,
}

/// Client device entry from `policy/client-devices.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDevice {
    /// Device policy name.
    pub device: String,
    /// Human owner of the device.
    pub owner: String,
    /// Policy user whose SSH certs this device may request.
    pub user: String,
    /// SSH private/public key basename expected on the device.
    pub key_name: String,
    /// Policy status.
    pub status: String,
}

/// Principal entry from `policy/principals.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// SSH certificate principal name.
    pub principal: String,
    /// Principal class.
    pub r#type: String,
    /// Owning policy user, host, or automation identity.
    pub owner: String,
    /// Unix accounts this principal may map to, or `-` for host principals.
    pub allowed_accounts: String,
    /// Free-form operator notes.
    pub notes: String,
}

/// User/host access entry from `policy/user-hosts.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserHostAccess {
    /// Policy user.
    pub user: String,
    /// Target host.
    pub host: String,
    /// Unix account on the target host.
    pub unix_account: String,
    /// Whether SSH access is allowed.
    pub allow_ssh: bool,
    /// Whether sudo is expected for this mapping.
    pub sudo_expected: String,
    /// Policy status.
    pub status: String,
    /// Free-form operator notes.
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Operator {
    user: String,
    host_ref: String,
    unix_account: String,
    privilege: String,
    status: String,
    notes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Automation {
    name: String,
    source_ref: String,
    target_ref: String,
    purpose: String,
    auth_model: String,
    notes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticKey {
    account: String,
    host_ref: String,
    purpose: String,
    class: String,
    required_controls: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmergencyAccess {
    host: String,
    account: String,
    key_id: String,
    storage: String,
    test_interval: String,
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
    /// Client device key inventory.
    pub client_devices: Vec<ClientDevice>,
    /// SSH certificate principals.
    pub principals: Vec<Principal>,
    /// User-to-host SSH access map.
    pub user_hosts: Vec<UserHostAccess>,
    tables: PolicyTables,
}

impl Policy {
    /// Load the initial policy files needed for config-only validation.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let endpoints = read_typed(root.join("policy/endpoints.toml"), "endpoints")?;
        let hosts = read_typed(root.join("policy/hosts.toml"), "hosts")?;
        let users = read_typed(root.join("policy/users.toml"), "users")?;
        let provisioners = read_typed(root.join("policy/provisioners.toml"), "provisioners")?;
        let client_devices = read_typed(root.join("policy/client-devices.toml"), "client_devices")?;
        let principals = read_typed(root.join("policy/principals.toml"), "principals")?;
        let user_hosts = read_typed(root.join("policy/user-hosts.toml"), "user_hosts")?;
        let tables = PolicyTables::load(
            root,
            users.clone(),
            provisioners.clone(),
            client_devices.clone(),
            principals.clone(),
            user_hosts.clone(),
        )?;
        let policy = Self {
            root: root.to_path_buf(),
            endpoints,
            hosts,
            users,
            provisioners,
            client_devices,
            principals,
            user_hosts,
            tables,
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
    pub fn active_ssh_access(&self) -> impl Iterator<Item = &UserHostAccess> {
        self.user_hosts
            .iter()
            .filter(|access| access.status == "active" && access.allow_ssh)
    }

    /// Active client devices for a policy user.
    pub fn active_client_devices_for_user(
        &self,
        user: &str,
    ) -> impl Iterator<Item = &ClientDevice> {
        self.client_devices
            .iter()
            .filter(move |device| device.status == "active" && device.user == user)
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

        self.validate_tables(&hosts)?;
        Ok(())
    }

    fn validate_tables(&self, hosts: &BTreeSet<String>) -> Result<()> {
        let users = unique_values(
            "policy/users.toml",
            self.tables.users.iter().map(|user| user.user.as_str()),
            "user",
        )?;
        let provisioners = unique_values(
            "policy/provisioners.toml",
            self.tables
                .provisioners
                .iter()
                .map(|provisioner| provisioner.name.as_str()),
            "name",
        )?;
        let provisioner_roles = self
            .provisioners
            .iter()
            .map(|provisioner| (provisioner.name.as_str(), provisioner.role.as_str()))
            .collect::<BTreeMap<_, _>>();
        let principals = unique_key_map(
            "policy/principals.toml",
            self.tables
                .principals
                .iter()
                .map(|principal| (principal.principal.as_str(), principal.r#type.as_str())),
            "principal",
        )?;

        let mut host_refs = hosts.clone();
        host_refs.insert("fleet".to_owned());
        for endpoint in &self.endpoints {
            host_refs.insert(format!("{}.target", endpoint.role));
        }

        for user in &self.tables.users {
            let name = user.user.as_str();
            reject_root_identity("policy/users.toml", name, "user", name)?;
            reject_root_identity("policy/users.toml", name, "principal", &user.principal)?;
            reject_root_identity(
                "policy/users.toml",
                name,
                "unix_account",
                &user.unix_account,
            )?;
            ensure_contains(
                "policy/users.toml",
                name,
                "principal",
                &user.principal,
                principals.keys(),
            )?;
            ensure_contains(
                "policy/users.toml",
                name,
                "provisioner",
                &user.provisioner,
                provisioners.iter(),
            )?;
            if provisioner_roles.get(user.provisioner.as_str()) != Some(&"user_enrollment") {
                return Err(Error::Validation {
                    field: format!("policy/users.toml:{name}.provisioner"),
                    message: "user provisioner must use role user_enrollment".to_owned(),
                });
            }
            if user.root_ssh {
                return Err(Error::Validation {
                    field: format!("policy/users.toml:{name}.root_ssh"),
                    message: "root SSH login is not supported".to_owned(),
                });
            }
            validate_step_duration("policy/users.toml", name, "cert_ttl", &user.cert_ttl)?;
        }

        for row in &self.tables.provisioners {
            let role = row.role.as_str();
            validate_step_duration(
                "policy/provisioners.toml",
                role,
                "default_ttl",
                &row.default_ttl,
            )?;
            validate_step_duration("policy/provisioners.toml", role, "max_ttl", &row.max_ttl)?;
            validate_renewal_check(
                "policy/provisioners.toml",
                role,
                "renewal_check",
                &row.renewal_check,
            )?;
        }

        for principal in &self.tables.principals {
            let name = principal.principal.as_str();
            let owner = principal.owner.as_str();
            match principal.r#type.as_str() {
                "user" => {
                    reject_root_identity("policy/principals.toml", name, "principal", name)?;
                    for account in split_list(&principal.allowed_accounts) {
                        reject_root_identity(
                            "policy/principals.toml",
                            name,
                            "allowed_accounts",
                            account,
                        )?;
                    }
                    ensure_contains("policy/principals.toml", name, "owner", owner, users.iter())?
                }
                "host" => {
                    ensure_contains("policy/principals.toml", name, "owner", owner, hosts.iter())?
                }
                _ => {}
            }
        }

        for host in &self.hosts {
            for principal in &host.principals {
                ensure_contains(
                    "policy/hosts.toml",
                    &host.host,
                    "principals",
                    principal,
                    principals.keys(),
                )?;
                if principals.get(principal).map(String::as_str) != Some("host") {
                    return Err(Error::Validation {
                        field: format!("policy/hosts.toml:{}.principals", host.host),
                        message: format!("principal {principal} is not a host principal"),
                    });
                }
            }
        }

        for row in &self.tables.user_hosts {
            let user = row.user.as_str();
            ensure_contains("policy/user-hosts.toml", user, "user", user, users.iter())?;
            ensure_contains(
                "policy/user-hosts.toml",
                user,
                "host",
                &row.host,
                hosts.iter(),
            )?;
            if row.allow_ssh && row.unix_account == "root" {
                return Err(Error::Validation {
                    field: format!("policy/user-hosts.toml:{user}.unix_account"),
                    message: "root SSH login is not supported".to_owned(),
                });
            }
        }

        for row in &self.tables.operators {
            let user = row.user.as_str();
            ensure_contains("policy/operators.toml", user, "user", user, users.iter())?;
            reject_root_identity(
                "policy/operators.toml",
                user,
                "unix_account",
                &row.unix_account,
            )?;
            ensure_contains(
                "policy/operators.toml",
                user,
                "host_ref",
                &row.host_ref,
                host_refs.iter(),
            )?;
        }

        for row in &self.tables.client_devices {
            let device = row.device.as_str();
            ensure_contains(
                "policy/client-devices.toml",
                device,
                "owner",
                &row.owner,
                users.iter(),
            )?;
            ensure_contains(
                "policy/client-devices.toml",
                device,
                "user",
                &row.user,
                users.iter(),
            )?;
        }

        for row in &self.tables.automation {
            let name = row.name.as_str();
            ensure_contains(
                "policy/automation.toml",
                name,
                "source_ref",
                &row.source_ref,
                host_refs.iter(),
            )?;
            ensure_contains(
                "policy/automation.toml",
                name,
                "target_ref",
                &row.target_ref,
                host_refs.iter(),
            )?;
        }

        for row in &self.tables.static_keys {
            let account = row.account.as_str();
            reject_root_identity("policy/static-keys.toml", account, "account", account)?;
            ensure_contains(
                "policy/static-keys.toml",
                account,
                "host_ref",
                &row.host_ref,
                host_refs.iter(),
            )?;
        }

        for row in &self.tables.emergency_access {
            let key_id = row.key_id.as_str();
            ensure_contains(
                "policy/emergency-access.toml",
                key_id,
                "host",
                &row.host,
                hosts.iter(),
            )?;
            ensure_contains(
                "policy/emergency-access.toml",
                key_id,
                "account",
                &row.account,
                users.iter(),
            )?;
            reject_root_identity(
                "policy/emergency-access.toml",
                key_id,
                "account",
                &row.account,
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PolicyTables {
    users: Vec<User>,
    operators: Vec<Operator>,
    provisioners: Vec<Provisioner>,
    client_devices: Vec<ClientDevice>,
    principals: Vec<Principal>,
    user_hosts: Vec<UserHostAccess>,
    automation: Vec<Automation>,
    static_keys: Vec<StaticKey>,
    emergency_access: Vec<EmergencyAccess>,
}

impl PolicyTables {
    fn load(
        root: &Path,
        users: Vec<User>,
        provisioners: Vec<Provisioner>,
        client_devices: Vec<ClientDevice>,
        principals: Vec<Principal>,
        user_hosts: Vec<UserHostAccess>,
    ) -> Result<Self> {
        Ok(Self {
            users,
            operators: read_typed(root.join("policy/operators.toml"), "operators")?,
            provisioners,
            client_devices,
            principals,
            user_hosts,
            automation: read_typed(root.join("policy/automation.toml"), "automation")?,
            static_keys: read_typed(root.join("policy/static-keys.toml"), "static_keys")?,
            emergency_access: read_typed(
                root.join("policy/emergency-access.toml"),
                "emergency_access",
            )?,
        })
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

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
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

fn unique_key_map<'a>(
    table: &str,
    rows: impl Iterator<Item = (&'a str, &'a str)>,
    key: &str,
) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (key_value, mapped_value) in rows {
        if values
            .insert(key_value.to_owned(), mapped_value.to_owned())
            .is_some()
        {
            return Err(Error::Validation {
                field: format!("{table}:{key}"),
                message: format!("duplicate {key} {key_value}"),
            });
        }
    }
    Ok(values)
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

fn validate_renewal_check(table: &str, row_id: &str, field: &str, value: &str) -> Result<()> {
    if value == "manual" {
        return Ok(());
    }
    let duration = value.strip_suffix("-jitter").unwrap_or(value);
    let (digits, unit) = duration.split_at(duration.len().saturating_sub(1));
    let valid = !digits.is_empty()
        && digits.as_bytes()[0] != b'0'
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(unit, "m" | "h");
    if valid {
        Ok(())
    } else {
        Err(Error::Validation {
            field: format!("{table}:{row_id}.{field}"),
            message: "renewal checks must be manual or m/h durations with optional -jitter"
                .to_owned(),
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
            .replace("principal = \"alice\"", "principal = \"root\"")
            .replace("unix_account = \"alice\"", "unix_account = \"root\"");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("root SSH identities are not supported"));
    }

    #[test]
    fn rejects_root_user_principal_allowed_account() {
        let (dir, policy_dir) = copy_policy();
        let principals = policy_dir.join("principals.toml");
        let text = fs::read_to_string(&principals).unwrap().replacen(
            "allowed_accounts = \"alice\"",
            "allowed_accounts = \"root\"",
            1,
        );
        fs::write(&principals, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("root SSH identities are not supported"));
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
    fn rejects_root_static_key_account() {
        let (dir, policy_dir) = copy_policy();
        let static_keys = policy_dir.join("static-keys.toml");
        let mut text = fs::read_to_string(&static_keys).unwrap();
        text.push_str(
            "\n[[static_keys]]\naccount = \"root\"\nhost_ref = \"ca-host\"\n\
             purpose = \"root shell\"\nclass = \"breakglass\"\n\
             required_controls = \"restricted key\"\n",
        );
        fs::write(&static_keys, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("root SSH identities are not supported"));
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
