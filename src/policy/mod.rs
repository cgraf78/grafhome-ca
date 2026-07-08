//! Policy file parsing and validation.
//!
//! Policy files are TSV so they remain easy to inspect and edit by hand, but
//! the rest of the code consumes typed Rust structs rather than raw rows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, Result};

/// Raw TSV record for schema validation.
pub type RawRecord = BTreeMap<String, String>;

/// Endpoint row from `policy/endpoints.tsv`.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    #[serde(deserialize_with = "deserialize_port")]
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

/// Host row from `policy/hosts.tsv`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Host {
    /// Stable host name used by policy references.
    pub host: String,
    /// Host class, such as `server` or `personal-laptop`.
    pub kind: String,
    /// Whether this host should accept SSH server connections.
    pub ssh_server: String,
    /// Whether this host should act as an SSH client.
    pub ssh_client: String,
    /// Scheduler or operator expected to renew this host's certificates.
    pub renewal_owner: String,
    /// Comma-separated host certificate principals.
    pub principals: String,
}

/// User row from `policy/users.tsv`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    /// Stable policy user name.
    pub user: String,
    /// SSH certificate principal granted to this user.
    pub principal: String,
    /// Default Unix account for this user.
    pub unix_account: String,
    /// Whether root SSH is allowed. Validation rejects `yes`.
    pub root_ssh: String,
    /// Provisioner used for user certificate issuance.
    pub provisioner: String,
    /// User certificate lifetime.
    pub cert_ttl: String,
    /// Policy status.
    pub status: String,
    /// Free-form operator notes.
    pub notes: String,
}

/// Provisioner row from `policy/provisioners.tsv`.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// Client device row from `policy/client-devices.tsv`.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// Principal row from `policy/principals.tsv`.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// User/host access row from `policy/user-hosts.tsv`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserHostAccess {
    /// Policy user.
    pub user: String,
    /// Target host.
    pub host: String,
    /// Unix account on the target host.
    pub unix_account: String,
    /// Whether SSH access is allowed.
    pub allow_ssh: String,
    /// Whether sudo is expected for this mapping.
    pub sudo_expected: String,
    /// Policy status.
    pub status: String,
    /// Free-form operator notes.
    pub notes: String,
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
        let endpoints = read_typed::<Endpoint>(
            root.join("policy/endpoints.tsv"),
            &[
                "role",
                "name",
                "dns_name",
                "target",
                "interface",
                "address",
                "port",
                "scheme",
            ],
        )?;
        let hosts = read_typed::<Host>(
            root.join("policy/hosts.tsv"),
            &[
                "host",
                "kind",
                "ssh_server",
                "ssh_client",
                "renewal_owner",
                "principals",
            ],
        )?;
        let users = read_typed::<User>(
            root.join("policy/users.tsv"),
            &[
                "user",
                "principal",
                "unix_account",
                "root_ssh",
                "provisioner",
                "cert_ttl",
                "status",
                "notes",
            ],
        )?;
        let provisioners = read_typed::<Provisioner>(
            root.join("policy/provisioners.tsv"),
            &[
                "role",
                "name",
                "type",
                "default_ttl",
                "max_ttl",
                "renewal_check",
                "status",
                "notes",
            ],
        )?;
        let client_devices = read_typed::<ClientDevice>(
            root.join("policy/client-devices.tsv"),
            &["device", "owner", "user", "key_name", "status"],
        )?;
        let principals = read_typed::<Principal>(
            root.join("policy/principals.tsv"),
            &["principal", "type", "owner", "allowed_accounts", "notes"],
        )?;
        let user_hosts = read_typed::<UserHostAccess>(
            root.join("policy/user-hosts.tsv"),
            &[
                "user",
                "host",
                "unix_account",
                "allow_ssh",
                "sudo_expected",
                "status",
                "notes",
            ],
        )?;
        let tables = PolicyTables::load(root)?;
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
            .filter(|access| access.status == "active" && access.allow_ssh == "yes")
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
                    field: format!("policy/endpoints.tsv:{}.role", endpoint.role),
                    message: "endpoint role must be ca_api or ca_origin".to_owned(),
                });
            }
            if !roles.insert(endpoint.role.as_str()) {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.tsv:{}.role", endpoint.role),
                    message: "duplicate endpoint role".to_owned(),
                });
            }
            if endpoint.scheme != "https" {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.tsv:{}.scheme", endpoint.role),
                    message: "only https endpoints are supported".to_owned(),
                });
            }
        }
        for required in ["ca_api", "ca_origin"] {
            if !roles.contains(required) {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.tsv:{required}"),
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
                field: "policy/hosts.tsv:host".to_owned(),
                message: "duplicate host".to_owned(),
            });
        }
        for endpoint in &self.endpoints {
            if !hosts.contains(&endpoint.target) {
                return Err(Error::Validation {
                    field: format!("policy/endpoints.tsv:{}.target", endpoint.role),
                    message: format!("unknown host {}", endpoint.target),
                });
            }
        }

        self.validate_tables(&hosts)?;
        Ok(())
    }

    fn validate_tables(&self, hosts: &BTreeSet<String>) -> Result<()> {
        let users = unique_values("policy/users.tsv", &self.tables.users, "user")?;
        let provisioners =
            unique_values("policy/provisioners.tsv", &self.tables.provisioners, "name")?;
        let principals = unique_key_map(
            "policy/principals.tsv",
            &self.tables.principals,
            "principal",
            "type",
        )?;

        let mut host_refs = hosts.clone();
        host_refs.insert("fleet".to_owned());
        for endpoint in &self.endpoints {
            host_refs.insert(format!("{}.target", endpoint.role));
        }

        for user in &self.tables.users {
            let name = value(user, "user");
            reject_root_identity("policy/users.tsv", name, "user", name)?;
            reject_root_identity(
                "policy/users.tsv",
                name,
                "principal",
                value(user, "principal"),
            )?;
            reject_root_identity(
                "policy/users.tsv",
                name,
                "unix_account",
                value(user, "unix_account"),
            )?;
            ensure_contains(
                "policy/users.tsv",
                name,
                "principal",
                value(user, "principal"),
                principals.keys(),
            )?;
            ensure_contains(
                "policy/users.tsv",
                name,
                "provisioner",
                value(user, "provisioner"),
                provisioners.iter(),
            )?;
            if value(user, "root_ssh") == "yes" {
                return Err(Error::Validation {
                    field: format!("policy/users.tsv:{name}.root_ssh"),
                    message: "root SSH login is not supported".to_owned(),
                });
            }
            validate_step_duration(
                "policy/users.tsv",
                name,
                "cert_ttl",
                value(user, "cert_ttl"),
            )?;
        }

        for row in &self.tables.provisioners {
            let role = value(row, "role");
            validate_step_duration(
                "policy/provisioners.tsv",
                role,
                "default_ttl",
                value(row, "default_ttl"),
            )?;
            validate_step_duration(
                "policy/provisioners.tsv",
                role,
                "max_ttl",
                value(row, "max_ttl"),
            )?;
            validate_renewal_check(
                "policy/provisioners.tsv",
                role,
                "renewal_check",
                value(row, "renewal_check"),
            )?;
        }

        for principal in &self.tables.principals {
            let name = value(principal, "principal");
            let owner = value(principal, "owner");
            match value(principal, "type") {
                "user" => {
                    reject_root_identity("policy/principals.tsv", name, "principal", name)?;
                    for account in split_list(value(principal, "allowed_accounts")) {
                        reject_root_identity(
                            "policy/principals.tsv",
                            name,
                            "allowed_accounts",
                            account,
                        )?;
                    }
                    ensure_contains("policy/principals.tsv", name, "owner", owner, users.iter())?
                }
                "host" => {
                    ensure_contains("policy/principals.tsv", name, "owner", owner, hosts.iter())?
                }
                _ => {}
            }
        }

        for host in &self.hosts {
            for principal in split_list(&host.principals) {
                ensure_contains(
                    "policy/hosts.tsv",
                    &host.host,
                    "principals",
                    principal,
                    principals.keys(),
                )?;
                if principals.get(principal).map(String::as_str) != Some("host") {
                    return Err(Error::Validation {
                        field: format!("policy/hosts.tsv:{}.principals", host.host),
                        message: format!("principal {principal} is not a host principal"),
                    });
                }
            }
        }

        for row in &self.tables.user_hosts {
            let user = value(row, "user");
            ensure_contains("policy/user-hosts.tsv", user, "user", user, users.iter())?;
            ensure_contains(
                "policy/user-hosts.tsv",
                user,
                "host",
                value(row, "host"),
                hosts.iter(),
            )?;
            if value(row, "allow_ssh") == "yes" && value(row, "unix_account") == "root" {
                return Err(Error::Validation {
                    field: format!("policy/user-hosts.tsv:{user}.unix_account"),
                    message: "root SSH login is not supported".to_owned(),
                });
            }
        }

        for row in &self.tables.operators {
            let user = value(row, "user");
            ensure_contains("policy/operators.tsv", user, "user", user, users.iter())?;
            reject_root_identity(
                "policy/operators.tsv",
                user,
                "unix_account",
                value(row, "unix_account"),
            )?;
            ensure_contains(
                "policy/operators.tsv",
                user,
                "host_ref",
                value(row, "host_ref"),
                host_refs.iter(),
            )?;
        }

        for row in &self.tables.client_devices {
            let device = value(row, "device");
            ensure_contains(
                "policy/client-devices.tsv",
                device,
                "owner",
                value(row, "owner"),
                users.iter(),
            )?;
            ensure_contains(
                "policy/client-devices.tsv",
                device,
                "user",
                value(row, "user"),
                users.iter(),
            )?;
        }

        for row in &self.tables.automation {
            let name = value(row, "name");
            ensure_contains(
                "policy/automation.tsv",
                name,
                "source_ref",
                value(row, "source_ref"),
                host_refs.iter(),
            )?;
            ensure_contains(
                "policy/automation.tsv",
                name,
                "target_ref",
                value(row, "target_ref"),
                host_refs.iter(),
            )?;
        }

        for row in &self.tables.static_keys {
            let account = value(row, "account");
            reject_root_identity("policy/static-keys.tsv", account, "account", account)?;
            ensure_contains(
                "policy/static-keys.tsv",
                account,
                "host_ref",
                value(row, "host_ref"),
                host_refs.iter(),
            )?;
        }

        for row in &self.tables.emergency_access {
            let key_id = value(row, "key_id");
            ensure_contains(
                "policy/emergency-access.tsv",
                key_id,
                "host",
                value(row, "host"),
                hosts.iter(),
            )?;
            ensure_contains(
                "policy/emergency-access.tsv",
                key_id,
                "account",
                value(row, "account"),
                users.iter(),
            )?;
            reject_root_identity(
                "policy/emergency-access.tsv",
                key_id,
                "account",
                value(row, "account"),
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PolicyTables {
    users: Vec<RawRecord>,
    operators: Vec<RawRecord>,
    provisioners: Vec<RawRecord>,
    client_devices: Vec<RawRecord>,
    principals: Vec<RawRecord>,
    user_hosts: Vec<RawRecord>,
    automation: Vec<RawRecord>,
    static_keys: Vec<RawRecord>,
    emergency_access: Vec<RawRecord>,
}

impl PolicyTables {
    fn load(root: &Path) -> Result<Self> {
        Ok(Self {
            users: read_raw(
                root.join("policy/users.tsv"),
                &[
                    "user",
                    "principal",
                    "unix_account",
                    "root_ssh",
                    "provisioner",
                    "cert_ttl",
                    "status",
                    "notes",
                ],
            )?,
            operators: read_raw(
                root.join("policy/operators.tsv"),
                &[
                    "user",
                    "host_ref",
                    "unix_account",
                    "privilege",
                    "status",
                    "notes",
                ],
            )?,
            provisioners: read_raw(
                root.join("policy/provisioners.tsv"),
                &[
                    "role",
                    "name",
                    "type",
                    "default_ttl",
                    "max_ttl",
                    "renewal_check",
                    "status",
                    "notes",
                ],
            )?,
            client_devices: read_raw(
                root.join("policy/client-devices.tsv"),
                &["device", "owner", "user", "key_name", "status"],
            )?,
            principals: read_raw(
                root.join("policy/principals.tsv"),
                &["principal", "type", "owner", "allowed_accounts", "notes"],
            )?,
            user_hosts: read_raw(
                root.join("policy/user-hosts.tsv"),
                &[
                    "user",
                    "host",
                    "unix_account",
                    "allow_ssh",
                    "sudo_expected",
                    "status",
                    "notes",
                ],
            )?,
            automation: read_raw(
                root.join("policy/automation.tsv"),
                &[
                    "name",
                    "source_ref",
                    "target_ref",
                    "purpose",
                    "auth_model",
                    "notes",
                ],
            )?,
            static_keys: read_raw(
                root.join("policy/static-keys.tsv"),
                &[
                    "account",
                    "host_ref",
                    "purpose",
                    "class",
                    "required_controls",
                ],
            )?,
            emergency_access: read_raw(
                root.join("policy/emergency-access.tsv"),
                &["host", "account", "key_id", "storage", "test_interval"],
            )?,
        })
    }
}

/// Read a TSV file into raw records for schema validation.
pub fn read_raw(path: impl AsRef<Path>, expected_headers: &[&str]) -> Result<Vec<RawRecord>> {
    let path = path.as_ref();
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b'\t')
        .comment(None)
        .flexible(false)
        .from_path(path)
        .map_err(|source| Error::Csv {
            path: path.to_path_buf(),
            source,
        })?;

    let headers = reader
        .headers()
        .map_err(|source| Error::Csv {
            path: path.to_path_buf(),
            source,
        })?
        .iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let expected = expected_headers
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if headers != expected {
        return Err(Error::Parse {
            path: path.to_path_buf(),
            line: 1,
            message: format!("expected headers {}", expected_headers.join("\t")),
        });
    }
    if headers.iter().collect::<BTreeSet<_>>().len() != headers.len() {
        return Err(Error::Parse {
            path: path.to_path_buf(),
            line: 1,
            message: "duplicate header".to_owned(),
        });
    }

    let mut rows = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|source| Error::Csv {
            path: path.to_path_buf(),
            source,
        })?;
        let mut row = RawRecord::new();
        for (header, value) in headers.iter().zip(record.iter()) {
            if value.contains('\n') || value.contains('\t') {
                return Err(Error::Parse {
                    path: path.to_path_buf(),
                    line: reader.position().line() as usize,
                    message: "field values may not contain tabs or newlines".to_owned(),
                });
            }
            row.insert(header.clone(), value.to_owned());
        }
        rows.push(row);
    }
    Ok(rows)
}

fn read_typed<T>(path: impl AsRef<Path>, expected_headers: &[&str]) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let path = path.as_ref();
    read_raw(path, expected_headers)?
        .into_iter()
        .map(|row| {
            serde_json::from_value(serde_json::to_value(row).expect("raw row serializes")).map_err(
                |source| Error::Json {
                    path: path.to_path_buf(),
                    source,
                },
            )
        })
        .collect()
}

fn deserialize_port<'de, D>(deserializer: D) -> std::result::Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let port = value
        .parse::<u16>()
        .map_err(|_| serde::de::Error::custom(format!("invalid TCP port {value}")))?;
    if port == 0 {
        Err(serde::de::Error::custom(
            "TCP port must be greater than zero",
        ))
    } else {
        Ok(port)
    }
}

fn value<'a>(row: &'a RawRecord, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or_default()
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

fn unique_values(table: &str, rows: &[RawRecord], key: &str) -> Result<BTreeSet<String>> {
    let mut values = BTreeSet::new();
    for row in rows {
        let value = value(row, key);
        if !values.insert(value.to_owned()) {
            return Err(Error::Validation {
                field: format!("{table}:{key}"),
                message: format!("duplicate {key} {value}"),
            });
        }
    }
    Ok(values)
}

fn unique_key_map(
    table: &str,
    rows: &[RawRecord],
    key: &str,
    mapped_key: &str,
) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for row in rows {
        let key_value = value(row, key);
        if values
            .insert(key_value.to_owned(), value(row, mapped_key).to_owned())
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
    fn rejects_dangling_user_provisioner() {
        let (dir, policy_dir) = copy_policy();

        let users = policy_dir.join("users.tsv");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("grafhome-user-login", "missing-provisioner");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("unknown provisioner missing-provisioner"));
    }

    #[test]
    fn rejects_root_user_identity() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.tsv");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("alice\talice\talice\tno", "root\troot\troot\tno");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("root SSH identities are not supported"));
    }

    #[test]
    fn rejects_root_user_principal_allowed_account() {
        let (dir, policy_dir) = copy_policy();
        let principals = policy_dir.join("principals.tsv");
        let text = fs::read_to_string(&principals)
            .unwrap()
            .replace("alice\tuser\talice\talice", "alice\tuser\talice\troot");
        fs::write(&principals, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("root SSH identities are not supported"));
    }

    #[test]
    fn rejects_step_duration_day_unit() {
        let (dir, policy_dir) = copy_policy();
        let provisioners = policy_dir.join("provisioners.tsv");
        let text = fs::read_to_string(&provisioners)
            .unwrap()
            .replace("720h\t720h", "30d\t720h");
        fs::write(&provisioners, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("step-ca durations must use Go-style"));
    }

    #[test]
    fn rejects_root_static_key_account() {
        let (dir, policy_dir) = copy_policy();
        let static_keys = policy_dir.join("static-keys.tsv");
        let mut text = fs::read_to_string(&static_keys).unwrap();
        text.push_str("root\tca-host\troot shell\tbreakglass\trestricted key\n");
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
