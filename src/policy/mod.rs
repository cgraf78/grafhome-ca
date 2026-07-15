//! Policy file parsing and validation.
//!
//! Policy files are typed TOML documents so they remain easy to inspect,
//! comment, and edit by hand without reducing booleans or lists to strings.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::error::{Error, Result};

mod document;
mod legacy;

pub use document::Format;

/// Canonical global CA policy document.
pub const CA_POLICY_PATH: &str = "policy/ca.toml";
/// Canonical stable user identity document.
pub const USERS_POLICY_PATH: &str = "policy/users.toml";
/// Canonical per-host policy directory.
pub const HOST_POLICY_DIR: &str = "policy/hosts";

/// Public CA endpoint role.
pub const ENDPOINT_ROLE_CA_API: &str = "ca_api";
/// Private CA origin endpoint role.
pub const ENDPOINT_ROLE_CA_ORIGIN: &str = "ca_origin";
/// One-time host bootstrap provisioner role.
pub const PROVISIONER_ROLE_HOST_BOOTSTRAP: &str = "host_bootstrap";
/// Interactive user enrollment provisioner role.
pub const PROVISIONER_ROLE_USER_ENROLLMENT: &str = "user_enrollment";
/// Proxy ACME provisioner role.
pub const PROVISIONER_ROLE_PROXY_X509: &str = "proxy_x509";

pub(crate) const LEGACY_ENDPOINTS_PATH: &str = "policy/endpoints.toml";
pub(crate) const LEGACY_HOSTS_PATH: &str = "policy/hosts.toml";
pub(crate) const LEGACY_PROVISIONERS_PATH: &str = "policy/provisioners.toml";
pub(crate) const LEGACY_USER_CLIENTS_PATH: &str = "policy/user-clients.toml";
pub(crate) const LEGACY_USER_REMOTES_PATH: &str = "policy/user-remotes.toml";
pub(crate) const LEGACY_POLICY_PATHS: [&str; 6] = [
    LEGACY_ENDPOINTS_PATH,
    LEGACY_HOSTS_PATH,
    USERS_POLICY_PATH,
    LEGACY_PROVISIONERS_PATH,
    LEGACY_USER_CLIENTS_PATH,
    LEGACY_USER_REMOTES_PATH,
];

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

/// Return whether one validated Smallstep duration is no longer than another.
#[must_use]
pub fn duration_at_most(duration: &str, maximum: &str) -> bool {
    match (
        duration_nanoseconds(duration),
        duration_nanoseconds(maximum),
    ) {
        (Some(duration), Some(maximum)) => duration <= maximum,
        _ => false,
    }
}

/// Return whether a duration uses the Go-style grammar accepted by Smallstep.
#[must_use]
pub fn valid_step_duration_expression(duration: &str) -> bool {
    duration_nanoseconds(duration).is_some()
}

/// Endpoint entry normalized from `policy/ca.toml`.
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

/// Host entry normalized from `policy/hosts/<host>.toml`.
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
    /// Whether this user satisfies the SSH administrative access safety invariant.
    #[serde(default)]
    pub ssh_admin: bool,
    /// Policy status.
    pub status: String,
}

/// Provisioner entry normalized from `policy/ca.toml`.
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
    /// Default lifetime for certificates issued by device-bound renewal provisioners.
    #[serde(default)]
    pub renewal_default_ttl: Option<String>,
    /// Maximum lifetime for certificates issued by device-bound renewal provisioners.
    #[serde(default)]
    pub renewal_max_ttl: Option<String>,
    /// Policy status.
    pub status: String,
}

/// User certificate enrollment relationship from a host manifest.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserClient {
    /// Enrolled host where the user certificate is stored.
    pub host: String,
    /// Policy user whose SSH certs this host may request.
    pub user: String,
    /// Whether an operator may explicitly approve an effectively-infinite certificate.
    #[serde(default)]
    pub allow_effectively_infinite_cert: bool,
    /// Policy status.
    pub status: String,
}

impl Provisioner {
    /// Default certificate lifetime for a device-bound renewal provisioner.
    #[must_use]
    pub fn renewal_default_ttl(&self) -> &str {
        self.renewal_default_ttl
            .as_deref()
            .unwrap_or(&self.default_ttl)
    }
}

/// User login relationship from a host manifest.
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
    /// Whether every SSH server must retain a designated administrator login path.
    pub require_ssh_admin_access: bool,
    /// Smallstep provisioners.
    pub provisioners: Vec<Provisioner>,
    /// Hosts where users may enroll and renew certificates.
    pub user_clients: Vec<UserClient>,
    /// User-to-host SSH access map.
    pub user_remotes: Vec<UserRemote>,
}

impl Policy {
    /// Maximum lifetime for certificates issued by a device-bound renewal provisioner.
    ///
    /// Legacy user policy could combine an unlimited enrollment maximum with a
    /// user lifetime above the provisioner's default. Deriving the largest
    /// configured finite lifetime preserves that policy during binary-first
    /// rollout without retaining unlimited routine renewal.
    #[must_use]
    pub fn renewal_max_ttl<'a>(&'a self, provisioner: &'a Provisioner) -> &'a str {
        if let Some(maximum) = provisioner.renewal_max_ttl.as_deref() {
            return maximum;
        }
        if provisioner.max_ttl != UNLIMITED_TTL {
            return &provisioner.max_ttl;
        }
        self.users
            .iter()
            .filter(|user| user.status == "active" && user.provisioner == provisioner.name)
            .map(|user| user.cert_ttl.as_str())
            .chain(std::iter::once(provisioner.renewal_default_ttl()))
            .max_by_key(|duration| duration_nanoseconds(duration).unwrap_or_default())
            .expect("renewal default is always a candidate")
    }

    /// Load the initial policy files needed for config-only validation.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let policy = match document::detect(root)? {
            Format::Canonical => document::load(root)?,
            Format::Legacy => legacy::load(root)?,
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
            if !matches!(
                endpoint.role.as_str(),
                ENDPOINT_ROLE_CA_API | ENDPOINT_ROLE_CA_ORIGIN
            ) {
                return Err(Error::Validation {
                    field: ca_policy_field("endpoints", &endpoint.role, "role"),
                    message: "endpoint role must be ca_api or ca_origin".to_owned(),
                });
            }
            if !roles.insert(endpoint.role.as_str()) {
                return Err(Error::Validation {
                    field: ca_policy_field("endpoints", &endpoint.role, "role"),
                    message: "duplicate endpoint role".to_owned(),
                });
            }
            if endpoint.scheme != "https" {
                return Err(Error::Validation {
                    field: ca_policy_field("endpoints", &endpoint.role, "scheme"),
                    message: "only https endpoints are supported".to_owned(),
                });
            }
        }
        for required in [ENDPOINT_ROLE_CA_API, ENDPOINT_ROLE_CA_ORIGIN] {
            if !roles.contains(required) {
                return Err(Error::Validation {
                    field: format!("{CA_POLICY_PATH}:endpoints.{required}"),
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
                field: "policy host inventory".to_owned(),
                message: "duplicate host".to_owned(),
            });
        }
        for endpoint in &self.endpoints {
            if !hosts.contains(&endpoint.target) {
                return Err(Error::Validation {
                    field: ca_policy_field("endpoints", &endpoint.role, "target"),
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
            "policy/ca.toml:provisioners",
            self.provisioners
                .iter()
                .map(|provisioner| provisioner.name.as_str()),
            "name",
        )?;
        unique_values(
            "policy/ca.toml:provisioners",
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
            if provisioner.role != PROVISIONER_ROLE_USER_ENROLLMENT {
                return Err(Error::Validation {
                    field: user_policy_field(name, "provisioner"),
                    message: "user provisioner must use role user_enrollment".to_owned(),
                });
            }
            validate_step_duration("policy/users.toml", name, "cert_ttl", &user.cert_ttl)?;
            if user.ssh_admin && user.status != "active" {
                return Err(Error::Validation {
                    field: user_policy_field(name, "ssh_admin"),
                    message: "SSH administrators must have active status".to_owned(),
                });
            }
        }

        for provisioner in &self.provisioners {
            validate_step_duration(
                "policy/ca.toml:provisioners",
                &provisioner.role,
                "default_ttl",
                &provisioner.default_ttl,
            )?;
            if provisioner.max_ttl == UNLIMITED_TTL {
                if provisioner.role != PROVISIONER_ROLE_USER_ENROLLMENT {
                    return Err(Error::Validation {
                        field: ca_policy_field("provisioners", &provisioner.role, "max_ttl"),
                        message: "unlimited is supported only for user_enrollment".to_owned(),
                    });
                }
            } else {
                validate_step_duration(
                    "policy/ca.toml:provisioners",
                    &provisioner.role,
                    "max_ttl",
                    &provisioner.max_ttl,
                )?;
            }
            if let Some(duration) = &provisioner.renewal_default_ttl {
                validate_step_duration(
                    "policy/ca.toml:provisioners",
                    &provisioner.role,
                    "renewal_default_ttl",
                    duration,
                )?;
            }
            if let Some(duration) = &provisioner.renewal_max_ttl {
                validate_step_duration(
                    "policy/ca.toml:provisioners",
                    &provisioner.role,
                    "renewal_max_ttl",
                    duration,
                )?;
            }
            if !duration_at_most(
                provisioner.renewal_default_ttl(),
                self.renewal_max_ttl(provisioner),
            ) {
                return Err(Error::Validation {
                    field: format!(
                        "policy/ca.toml:provisioners.{}.renewal_max_ttl",
                        provisioner.role
                    ),
                    message: "renewal_max_ttl must be at least renewal_default_ttl".to_owned(),
                });
            }
        }

        for user in &self.users {
            if user.status != "active" {
                continue;
            }
            let provisioner = self
                .provisioners
                .iter()
                .find(|provisioner| provisioner.name == user.provisioner)
                .expect("user provisioner existence was validated");
            if !duration_at_most(&user.cert_ttl, self.renewal_max_ttl(provisioner)) {
                return Err(Error::Validation {
                    field: user_policy_field(&user.user, "cert_ttl"),
                    message: format!(
                        "cert_ttl must not exceed the user provisioner's renewal_max_ttl ({})",
                        self.renewal_max_ttl(provisioner)
                    ),
                });
            }
        }

        // Certificate principals share one Smallstep namespace. A collision
        // could make a user certificate valid as a host, or vice versa.
        let mut certificate_principals = user_principals;
        for host in &self.hosts {
            for principal in &host.principals {
                if !certificate_principals.insert(principal.clone()) {
                    return Err(Error::Validation {
                        field: host_policy_field(&host.host, "principals"),
                        message: format!("duplicate certificate principal {principal}"),
                    });
                }
            }
        }

        let mut access_rows = BTreeSet::new();
        for access in &self.user_remotes {
            let access_table = format!("policy/hosts/{}.toml:user_access", access.host);
            ensure_contains(
                &access_table,
                &access.user,
                "user",
                &access.user,
                users.iter(),
            )?;
            ensure_contains(
                &access_table,
                &access.user,
                "host",
                &access.host,
                hosts.iter(),
            )?;
            let remote = self
                .host(&access.host)
                .expect("remote host existence was validated");
            let grants_ssh = access.allow_ssh && access.status == "active";
            if grants_ssh && !remote.ssh_server {
                return Err(Error::Validation {
                    field: host_policy_field(&access.host, "ssh_server"),
                    message: format!("host {} is not an SSH server", access.host),
                });
            }
            if grants_ssh {
                reject_root_identity(
                    &access_table,
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
                    field: format!("{access_table}.{}", access.user),
                    message: format!(
                        "duplicate access row for {}@{} as {}",
                        access.user, access.host, access.unix_account
                    ),
                });
            }
        }

        // The policy-level switch deliberately owns enforcement separately from
        // the designations it protects. Removing an administrator field cannot
        // silently disable a site that opted into the lockout safeguard.
        let ssh_admins = self
            .users
            .iter()
            .filter(|user| user.ssh_admin && user.status == "active")
            .map(|user| user.user.as_str())
            .collect::<BTreeSet<_>>();
        if self.require_ssh_admin_access {
            if ssh_admins.is_empty() {
                return Err(Error::Validation {
                    field: "policy/users.toml:require_ssh_admin_access".to_owned(),
                    message: "requires at least one active user with ssh_admin = true".to_owned(),
                });
            }
            let hosts_with_admin_access = self
                .active_ssh_access()
                .filter(|access| ssh_admins.contains(access.user.as_str()))
                .map(|access| access.host.as_str())
                .collect::<BTreeSet<_>>();
            for host in self.hosts.iter().filter(|host| host.ssh_server) {
                if !hosts_with_admin_access.contains(host.host.as_str()) {
                    return Err(Error::Validation {
                        field: host_policy_field(&host.host, "user_access"),
                        message: "SSH server must retain an active login path for at least one user with ssh_admin = true".to_owned(),
                    });
                }
            }
        } else if !ssh_admins.is_empty() {
            return Err(Error::Validation {
                field: "policy/users.toml:require_ssh_admin_access".to_owned(),
                message: "must be true when users are designated with ssh_admin = true".to_owned(),
            });
        }

        let mut clients = BTreeSet::new();
        for client in &self.user_clients {
            let access_table = format!("policy/hosts/{}.toml:user_access", client.host);
            ensure_contains(
                &access_table,
                &client.host,
                "host",
                &client.host,
                hosts.iter(),
            )?;
            ensure_contains(
                &access_table,
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
                    field: host_policy_field(&client.host, "ssh_client"),
                    message: format!("host {} is not an SSH client", client.host),
                });
            }
            if !clients.insert((client.user.clone(), client.host.clone())) {
                return Err(Error::Validation {
                    field: format!("{access_table}.{}", client.user),
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

/// Detect the policy document layout below a config root.
pub fn format(root: impl AsRef<Path>) -> Result<Format> {
    document::detect(root.as_ref())
}

/// Return every policy input path relative to a config root.
pub fn input_paths(root: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    document::input_paths(root.as_ref())
}

/// Atomically write canonical policy documents to a new policy directory.
///
/// The destination must not exist. Documents are staged beside it, parsed back
/// into the normalized model, and renamed into place only after validation.
pub fn write_canonical(policy: &Policy, output_dir: impl AsRef<Path>) -> Result<()> {
    let output_dir = output_dir.as_ref();
    if output_dir.exists() {
        return Err(Error::Validation {
            field: output_dir.display().to_string(),
            message: "migration output already exists".to_owned(),
        });
    }
    let files = document::canonical_files(policy)?;
    policy.validate()?;
    let parent = output_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".grafhome-ca-policy-")
        .tempdir_in(parent)
        .map_err(|source| Error::io(parent, source))?;
    let staged_policy = staging.path().join("policy");
    create_policy_directory(&staged_policy)?;

    for file in files {
        let path = staged_policy.join(&file.path);
        if let Some(parent) = path.parent() {
            create_policy_directory(parent)?;
        }
        write_policy_file(&path, file.contents.as_bytes())?;
    }

    // Parsing the staged output catches serializer/document-model drift before
    // the migration can expose a partial or unusable policy tree.
    Policy::load(staging.path())?;
    publish_policy_directory(&staged_policy, output_dir)?;
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "redox"
))]
fn publish_policy_directory(staged_policy: &Path, output_dir: &Path) -> Result<()> {
    match rustix::fs::renameat_with(
        rustix::fs::CWD,
        staged_policy,
        rustix::fs::CWD,
        output_dir,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::EXIST) => Err(Error::Validation {
            field: output_dir.display().to_string(),
            message: "migration output already exists".to_owned(),
        }),
        Err(source) => Err(Error::io(output_dir, source.into())),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "redox"
)))]
fn publish_policy_directory(staged_policy: &Path, output_dir: &Path) -> Result<()> {
    std::fs::rename(staged_policy, output_dir).map_err(|source| Error::io(output_dir, source))
}

fn write_policy_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| Error::io(path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| Error::io(path, source))?;
    }
    file.write_all(contents)
        .map_err(|source| Error::io(path, source))?;
    file.sync_all().map_err(|source| Error::io(path, source))
}

fn create_policy_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|source| Error::io(path, source))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::io(path, source))?;
        Ok(())
    }
    #[cfg(not(unix))]
    builder
        .create(path)
        .map_err(|source| Error::io(path, source))
}

fn read_toml(path: &Path) -> Result<toml::Value> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
    toml::from_str::<toml::Value>(&text).map_err(|source| Error::Toml {
        path: path.to_path_buf(),
        source,
    })
}

fn read_typed_document<T>(path: impl AsRef<Path>) -> Result<T>
where
    T: DeserializeOwned,
{
    let path = path.as_ref();
    read_toml(path)?.try_into().map_err(|source| Error::Toml {
        path: path.to_path_buf(),
        source,
    })
}

fn provisioner_role_rank(role: &str) -> u8 {
    match role {
        PROVISIONER_ROLE_HOST_BOOTSTRAP => 0,
        PROVISIONER_ROLE_USER_ENROLLMENT => 1,
        PROVISIONER_ROLE_PROXY_X509 => 2,
        _ => 3,
    }
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

/// Return a stable diagnostic path for a keyed `ca.toml` field.
#[must_use]
pub fn ca_policy_field(section: &str, entry: &str, field: &str) -> String {
    format!("{CA_POLICY_PATH}:{section}.{entry}.{field}")
}

/// Return a stable diagnostic path for a keyed user field.
#[must_use]
pub fn user_policy_field(user: &str, field: &str) -> String {
    format!("{USERS_POLICY_PATH}:users.{user}.{field}")
}

/// Return a stable diagnostic path for a host-manifest field.
#[must_use]
pub fn host_policy_field(host: &str, field: &str) -> String {
    format!("{HOST_POLICY_DIR}/{host}.toml:{field}")
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
        && matches!(unit, "s" | "m" | "h")
        && duration_nanoseconds(duration).is_some();
    if valid {
        Ok(())
    } else {
        Err(Error::Validation {
            field: format!("{table}:{row_id}.{field}"),
            message: "step-ca durations must use Go-style s, m, or h units".to_owned(),
        })
    }
}

fn duration_nanoseconds(duration: &str) -> Option<u128> {
    let bytes = duration.as_bytes();
    let mut index = 0;
    let mut total = 0_u128;
    while index < bytes.len() {
        let integer_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if integer_start == index {
            return None;
        }
        let integer = duration[integer_start..index].parse::<u128>().ok()?;
        let mut fraction = None;
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            let fraction_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if fraction_start == index {
                return None;
            }
            fraction = Some(fraction_start..index);
        }
        let (unit, unit_len) = if bytes[index..].starts_with(b"ns") {
            (1_u128, 2)
        } else if bytes[index..].starts_with(b"us") {
            (1_000_u128, 2)
        } else if bytes[index..].starts_with(b"ms") {
            (1_000_000_u128, 2)
        } else if bytes[index..].starts_with(b"s") {
            (1_000_000_000_u128, 1)
        } else if bytes[index..].starts_with(b"m") {
            (60_000_000_000_u128, 1)
        } else if bytes[index..].starts_with(b"h") {
            (3_600_000_000_000_u128, 1)
        } else {
            return None;
        };
        index += unit_len;
        let mut component = integer.checked_mul(unit)?;
        if let Some(fraction) = fraction {
            let mut place = unit;
            for digit in &bytes[fraction] {
                place /= 10;
                if place == 0 {
                    break;
                }
                component = component.checked_add(u128::from(digit - b'0') * place)?;
            }
        }
        total = total.checked_add(component)?;
        if total > i64::MAX as u128 {
            return None;
        }
    }
    (index > 0).then_some(total)
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

    use super::{Policy, User, UserClient, UserRemote, duration_at_most};

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
        let user = policy
            .provisioners
            .iter()
            .find(|provisioner| provisioner.role == "user_enrollment")
            .unwrap();
        assert_eq!(user.renewal_default_ttl(), "24h");
        assert_eq!(policy.renewal_max_ttl(user), "48h");
        assert!(
            policy
                .user_clients
                .iter()
                .find(|client| client.host == "ca-host")
                .unwrap()
                .allow_effectively_infinite_cert
        );
    }

    #[test]
    fn old_policy_defaults_to_finite_renewal_without_enabling_infinite_approval() {
        let (dir, policy_dir) = copy_policy();
        let provisioners = policy_dir.join("provisioners.toml");
        let text = fs::read_to_string(&provisioners)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("renewal_"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&provisioners, text).unwrap();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users).unwrap().replacen(
            "cert_ttl = \"24h\"",
            "cert_ttl = \"48h\"",
            1,
        );
        fs::write(&users, text).unwrap();
        let clients = policy_dir.join("user-clients.toml");
        let text = fs::read_to_string(&clients)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("allow_effectively_infinite_cert"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&clients, text).unwrap();

        let policy = Policy::load(dir.path()).expect("pre-renewal-policy format loads");
        let user = policy
            .provisioners
            .iter()
            .find(|provisioner| provisioner.role == "user_enrollment")
            .unwrap();
        assert_eq!(user.max_ttl, super::UNLIMITED_TTL);
        assert_eq!(user.renewal_default_ttl(), "24h");
        assert_eq!(policy.renewal_max_ttl(user), "48h");
        assert!(
            policy
                .user_clients
                .iter()
                .all(|client| !client.allow_effectively_infinite_cert)
        );
    }

    #[test]
    fn old_policy_without_ssh_admin_designations_remains_valid() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .lines()
            .filter(|line| {
                !line.starts_with("require_ssh_admin_access") && !line.starts_with("ssh_admin")
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&users, text).unwrap();

        Policy::load(dir.path()).expect("pre-ssh-admin policy remains valid");
    }

    #[test]
    fn rejects_ssh_server_without_an_active_admin_login_path() {
        let (dir, policy_dir) = copy_policy();
        let remotes = policy_dir.join("user-remotes.toml");
        let text = fs::read_to_string(&remotes).unwrap().replacen(
            "host = \"ca-host\"\nunix_account = \"alice\"\nallow_ssh = true",
            "host = \"ca-host\"\nunix_account = \"alice\"\nallow_ssh = false",
            1,
        );
        fs::write(&remotes, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("policy/hosts/ca-host.toml:user_access"));
        assert!(error.contains("must retain an active login path"));
    }

    #[test]
    fn required_ssh_admin_access_rejects_removing_every_designation() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("ssh_admin"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("users.toml:require_ssh_admin_access"));
        assert!(error.contains("requires at least one active user"));
    }

    #[test]
    fn ssh_admin_designation_requires_the_durable_site_switch() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("require_ssh_admin_access = true\n", "");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("users.toml:require_ssh_admin_access"));
        assert!(error.contains("must be true"));
    }

    #[test]
    fn rejects_inactive_ssh_admin_designation() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("status = \"active\"", "status = \"disabled\"");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("users.toml:users.alice.ssh_admin"));
        assert!(error.contains("must have active status"));
    }

    #[test]
    fn rejects_renewal_maximum_shorter_than_default() {
        let (dir, policy_dir) = copy_policy();
        let provisioners = policy_dir.join("provisioners.toml");
        let text = fs::read_to_string(&provisioners).unwrap().replacen(
            "renewal_max_ttl = \"48h\"",
            "renewal_max_ttl = \"23h\"",
            1,
        );
        fs::write(&provisioners, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();
        assert!(error.contains("renewal_max_ttl must be at least renewal_default_ttl"));
    }

    #[test]
    fn duration_comparison_accepts_an_equal_maximum() {
        assert!(duration_at_most("48h", "48h"));
    }

    #[test]
    fn duration_comparison_accepts_a_compound_duration_below_maximum() {
        assert!(duration_at_most("2h45m", "48h"));
    }

    #[test]
    fn duration_comparison_accepts_a_fractional_duration_below_maximum() {
        assert!(duration_at_most("1.5h", "48h"));
    }

    #[test]
    fn duration_comparison_accepts_a_long_fraction_smallstep_can_truncate() {
        assert!(duration_at_most(
            "1.0000000000000000000000000000000000000000h",
            "48h"
        ));
    }

    #[test]
    fn duration_comparison_rejects_a_duration_just_above_maximum() {
        assert!(!duration_at_most("48h1ns", "48h"));
    }

    #[test]
    fn duration_parser_enforces_the_go_duration_ceiling() {
        assert!(super::valid_step_duration_expression("2562047h"));
        assert!(!super::valid_step_duration_expression("2562048h"));
    }

    #[test]
    fn rejects_user_certificate_lifetime_above_renewal_maximum() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("cert_ttl = \"24h\"", "cert_ttl = \"49h\"");
        fs::write(&users, text).unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();

        assert!(error.contains("cert_ttl must not exceed"));
        assert!(error.contains("renewal_max_ttl (48h)"));
    }

    #[test]
    fn inactive_historical_user_does_not_raise_the_active_renewal_maximum() {
        let (dir, policy_dir) = copy_policy();
        let users = policy_dir.join("users.toml");
        let text = fs::read_to_string(&users)
            .unwrap()
            .replace("cert_ttl = \"24h\"", "cert_ttl = \"8760h\"")
            .replace("ssh_admin = true\n", "")
            .replace("require_ssh_admin_access = true\n", "")
            .replace("status = \"active\"", "status = \"disabled\"");
        fs::write(&users, text).unwrap();

        let policy = Policy::load(dir.path()).expect("inactive historical lifetime is inert");
        let provisioner = policy
            .provisioners
            .iter()
            .find(|provisioner| provisioner.role == "user_enrollment")
            .unwrap();
        assert_eq!(policy.renewal_max_ttl(provisioner), "48h");
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

    #[test]
    fn canonical_migration_preserves_rendering_and_authorization() {
        let legacy_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/legacy-site-config");
        let legacy = crate::model::SiteModel::load(&legacy_root).expect("legacy model loads");
        crate::schema::validate_config_root(&legacy_root).expect("legacy schemas validate");

        let dir = tempdir().unwrap();
        let config = dir.path().join("config");
        fs::create_dir(&config).unwrap();
        fs::copy(
            legacy_root.join("config/deployment.env"),
            config.join("deployment.env"),
        )
        .unwrap();
        super::write_canonical(&legacy.policy, dir.path().join("policy"))
            .expect("canonical policy writes atomically");

        let canonical = crate::model::SiteModel::load(dir.path()).expect("canonical model loads");
        crate::schema::validate_config_root(dir.path()).expect("canonical schemas validate");
        assert_eq!(
            crate::render::render(&legacy).unwrap(),
            crate::render::render(&canonical).unwrap()
        );
        assert_eq!(
            authorization_snapshot(&legacy.policy),
            authorization_snapshot(&canonical.policy)
        );
    }

    #[test]
    fn canonical_round_trip_preserves_relationship_cardinality_roles_and_lifecycle() {
        let legacy_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/legacy-site-config");
        let mut before = crate::model::SiteModel::load(&legacy_root).unwrap();
        before.policy.users.push(User {
            user: "bob".to_owned(),
            principal: "bob".to_owned(),
            provisioner: "grafhome-user-enrollment".to_owned(),
            cert_ttl: "12h".to_owned(),
            ssh_admin: false,
            status: "active".to_owned(),
        });

        // Exercise independent host roles and relationships that exist on only
        // one side of the enrollment/login boundary.
        before.policy.hosts[2].ssh_client = false;
        before.policy.hosts[3].ssh_server = false;
        before
            .policy
            .user_clients
            .retain(|client| client.host != "edge-host");
        before
            .policy
            .user_remotes
            .retain(|login| login.host != "laptop-a");
        before.policy.user_clients.extend([
            UserClient {
                host: "laptop-a".to_owned(),
                user: "bob".to_owned(),
                allow_effectively_infinite_cert: false,
                status: "active".to_owned(),
            },
            UserClient {
                host: "ca-host".to_owned(),
                user: "bob".to_owned(),
                allow_effectively_infinite_cert: true,
                status: "planned".to_owned(),
            },
        ]);
        before.policy.user_remotes.extend([
            UserRemote {
                user: "bob".to_owned(),
                host: "edge-host".to_owned(),
                unix_account: "bob".to_owned(),
                allow_ssh: true,
                status: "active".to_owned(),
            },
            UserRemote {
                user: "bob".to_owned(),
                host: "edge-host".to_owned(),
                unix_account: "builder".to_owned(),
                allow_ssh: true,
                status: "planned".to_owned(),
            },
            UserRemote {
                user: "bob".to_owned(),
                host: "proxy-host".to_owned(),
                unix_account: "bob".to_owned(),
                allow_ssh: true,
                status: "disabled".to_owned(),
            },
        ]);

        let dir = tempdir().unwrap();
        let config = dir.path().join("config");
        fs::create_dir(&config).unwrap();
        fs::copy(
            legacy_root.join("config/deployment.env"),
            config.join("deployment.env"),
        )
        .unwrap();
        super::write_canonical(&before.policy, dir.path().join("policy")).unwrap();
        let after = crate::model::SiteModel::load(dir.path()).unwrap();

        assert_eq!(
            policy_snapshot(&before.policy),
            policy_snapshot(&after.policy)
        );
        assert_eq!(
            crate::render::render(&before).unwrap(),
            crate::render::render(&after).unwrap()
        );
        assert_eq!(
            authorization_snapshot(&before.policy),
            authorization_snapshot(&after.policy)
        );
    }

    #[test]
    fn migration_normalizes_an_explicit_active_login_deny_to_disabled_history() {
        let legacy_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/legacy-site-config");
        let mut policy = Policy::load(legacy_root).unwrap();
        policy.require_ssh_admin_access = false;
        policy.users[0].ssh_admin = false;
        policy.user_remotes[0].allow_ssh = false;
        assert_eq!(policy.active_ssh_access().count(), 3);

        let dir = tempdir().unwrap();
        super::write_canonical(&policy, dir.path().join("policy")).unwrap();
        let canonical = Policy::load(dir.path()).unwrap();

        assert_eq!(canonical.active_ssh_access().count(), 3);
        assert!(
            canonical
                .user_remotes
                .iter()
                .any(|login| login.host == "ca-host" && login.status == "disabled")
        );
    }

    #[test]
    fn migration_preserves_denied_root_history_on_a_non_server_host() {
        let legacy_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/legacy-site-config");
        let mut policy = Policy::load(legacy_root).unwrap();
        let edge = policy
            .hosts
            .iter_mut()
            .find(|host| host.host == "edge-host")
            .unwrap();
        edge.ssh_server = false;
        let denied = policy
            .user_remotes
            .iter_mut()
            .find(|login| login.host == "edge-host")
            .unwrap();
        denied.allow_ssh = false;
        denied.unix_account = "root".to_owned();

        let dir = tempdir().unwrap();
        super::write_canonical(&policy, dir.path().join("policy")).unwrap();
        let canonical = Policy::load(dir.path()).unwrap();
        let history = canonical
            .user_remotes
            .iter()
            .find(|login| login.host == "edge-host")
            .unwrap();

        assert_eq!(history.unix_account, "root");
        assert_eq!(history.status, "disabled");
        assert!(
            !canonical
                .active_ssh_access()
                .any(|login| login.host == "edge-host")
        );
    }

    #[test]
    fn mixed_canonical_and_legacy_documents_are_rejected() {
        let (dir, policy_dir) = copy_policy();
        fs::copy(
            crate::example_config_root().join("policy/ca.toml"),
            policy_dir.join("ca.toml"),
        )
        .unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();

        assert!(error.contains("cannot be mixed"));
    }

    #[test]
    fn migration_refuses_to_replace_an_existing_output_directory() {
        let policy = Policy::load(crate::example_config_root()).unwrap();
        let dir = tempdir().unwrap();
        let output = dir.path().join("policy");
        fs::create_dir(&output).unwrap();

        let error = super::write_canonical(&policy, &output)
            .unwrap_err()
            .to_string();

        assert!(error.contains("migration output already exists"));
    }

    #[test]
    fn migration_publish_does_not_replace_a_concurrently_created_directory() {
        let dir = tempdir().unwrap();
        let staged = dir.path().join("staged-policy");
        let output = dir.path().join("policy");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("marker"), "staged\n").unwrap();
        fs::create_dir(&output).unwrap();

        let error = super::publish_policy_directory(&staged, &output)
            .unwrap_err()
            .to_string();

        assert!(error.contains("migration output already exists"));
        assert!(staged.join("marker").exists());
        assert!(output.exists());
    }

    #[test]
    fn migration_rejects_a_host_name_that_cannot_be_a_safe_filename() {
        let mut policy = Policy::load(crate::example_config_root()).unwrap();
        policy.hosts[0].host = "../../escaped".to_owned();
        let dir = tempdir().unwrap();

        let error = super::write_canonical(&policy, dir.path().join("policy"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("safe policy filename"));
        assert!(!dir.path().join("escaped.toml").exists());
        assert!(!dir.path().join("policy").exists());
    }

    #[test]
    fn canonical_host_directory_rejects_unmodeled_files() {
        let policy = Policy::load(crate::example_config_root()).unwrap();
        let dir = tempdir().unwrap();
        super::write_canonical(&policy, dir.path().join("policy")).unwrap();
        fs::write(dir.path().join("policy/hosts/README"), "unexpected\n").unwrap();

        let error = Policy::load(dir.path()).unwrap_err().to_string();

        assert!(error.contains("may contain only .toml files"));
    }

    #[cfg(unix)]
    #[test]
    fn migration_writes_private_policy_tree_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "GRAFHOME_CA_UMASK_MIGRATION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "policy::tests::migration_writes_private_policy_tree_under_permissive_umask",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let previous_umask = rustix::process::umask(rustix::fs::Mode::empty());
        let policy = Policy::load(crate::example_config_root()).unwrap();
        let dir = tempdir().unwrap();
        super::write_canonical(&policy, dir.path().join("policy")).unwrap();

        for path in [dir.path().join("policy"), dir.path().join("policy/hosts")] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        for path in super::input_paths(dir.path()).unwrap() {
            let mode = fs::metadata(dir.path().join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        rustix::process::umask(previous_umask);
    }

    fn policy_snapshot(policy: &Policy) -> (bool, Vec<String>) {
        let mut entries = policy
            .endpoints
            .iter()
            .map(|entry| serde_json::to_string(entry).unwrap())
            .chain(
                policy
                    .hosts
                    .iter()
                    .map(|entry| serde_json::to_string(entry).unwrap()),
            )
            .chain(
                policy
                    .users
                    .iter()
                    .map(|entry| serde_json::to_string(entry).unwrap()),
            )
            .chain(
                policy
                    .provisioners
                    .iter()
                    .map(|entry| serde_json::to_string(entry).unwrap()),
            )
            .chain(
                policy
                    .user_clients
                    .iter()
                    .map(|entry| serde_json::to_string(entry).unwrap()),
            )
            .chain(
                policy
                    .user_remotes
                    .iter()
                    .map(|entry| serde_json::to_string(entry).unwrap()),
            )
            .collect::<Vec<_>>();
        entries.sort();
        (policy.require_ssh_admin_access, entries)
    }

    fn authorization_snapshot(policy: &Policy) -> (Vec<String>, Vec<String>) {
        let mut enrollments = policy
            .user_clients
            .iter()
            .map(|client| {
                format!(
                    "{}@{}:{}:{}",
                    client.user, client.host, client.status, client.allow_effectively_infinite_cert
                )
            })
            .collect::<Vec<_>>();
        enrollments.sort();
        let mut logins = policy
            .user_remotes
            .iter()
            .map(|login| {
                format!(
                    "{}@{}:{}:{}:{}",
                    login.user, login.host, login.unix_account, login.status, login.allow_ssh
                )
            })
            .collect::<Vec<_>>();
        logins.sort();
        (enrollments, logins)
    }

    fn copy_policy() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        fs::create_dir(&policy_dir).unwrap();

        let legacy = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/legacy-site-config/policy");
        for entry in fs::read_dir(legacy).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), policy_dir.join(entry.file_name())).unwrap();
        }
        (dir, policy_dir)
    }
}
