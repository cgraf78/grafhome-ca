//! Protected CA-origin inventory for enrolled SSH, X.509, and renewal public keys.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::enrollment::{HostRequest, UserRequest};
use crate::error::{Error, Result};
use crate::policy::{RevokedSshKey, RevokedX509Key, canonical_ssh_public_key};
use crate::policy::{valid_host_identity, valid_user_identity};
use crate::x509::{CertificateKey, X509Request, x509_identity};

/// On-disk enrollment registry format.
pub const FORMAT_VERSION: u32 = 1;

/// Lifecycle state for one enrolled public-key pair.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordStatus {
    /// Reserved before CA activation so approval is crash-resumable.
    Pending,
    /// Live CA renewal provisioner.
    Active,
    /// Permanent tombstone; neither key may be enrolled again.
    Revoked,
}

/// The policy tombstone for one revoked enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Revocation {
    /// Tombstone for an SSH host or user key.
    Ssh(RevokedSshKey),
    /// Tombstone for an X.509 certificate key.
    X509(RevokedX509Key),
}

/// One host, user, or certificate enrollment and its two public keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum EnrollmentRecord {
    /// Host-certificate enrollment.
    Host {
        /// Registry lifecycle state.
        status: RecordStatus,
        /// Stable policy host identity.
        host: String,
        /// Canonical plain OpenSSH host public key.
        ssh_public_key: String,
        /// SHA-256 fingerprint of the SSH key.
        ssh_fingerprint: String,
        /// Canonical public half of the device renewal JWK.
        renewal_public_jwk: Value,
        /// SHA-256 thumbprint of the renewal JWK.
        renewal_fingerprint: String,
        /// UTC time when the key pair first entered the registry.
        enrolled_at: String,
        /// UTC time when the key pair became a permanent tombstone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked_at: Option<String>,
    },
    /// User-certificate enrollment bound to one client host.
    User {
        /// Registry lifecycle state.
        status: RecordStatus,
        /// Stable policy user identity.
        user: String,
        /// Stable policy identity of the enrolled client host.
        client_host: String,
        /// Canonical plain OpenSSH user public key.
        ssh_public_key: String,
        /// SHA-256 fingerprint of the SSH key.
        ssh_fingerprint: String,
        /// Canonical public half of the device renewal JWK.
        renewal_public_jwk: Value,
        /// SHA-256 thumbprint of the renewal JWK.
        renewal_fingerprint: String,
        /// UTC time when the key pair first entered the registry.
        enrolled_at: String,
        /// UTC time when the key pair became a permanent tombstone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked_at: Option<String>,
    },
    /// X.509 certificate enrollment on one host.
    X509 {
        /// Registry lifecycle state.
        status: RecordStatus,
        /// Stable policy host identity.
        host: String,
        /// Policy certificate name, unique within its host.
        name: String,
        /// Canonical PEM public key the provisioner pins.
        certificate_public_key: String,
        /// SHA-256 fingerprint of the certificate public key.
        certificate_fingerprint: String,
        /// Canonical public half of the renewal JWK.
        renewal_public_jwk: Value,
        /// SHA-256 thumbprint of the renewal JWK.
        renewal_fingerprint: String,
        /// UTC time when the key pair first entered the registry.
        enrolled_at: String,
        /// UTC time when the key pair became a permanent tombstone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked_at: Option<String>,
    },
}

impl EnrollmentRecord {
    /// Build a canonical pending host record from a public enrollment request.
    pub fn pending_host(request: &HostRequest, now: &str) -> Result<Self> {
        request.validate()?;
        let (ssh_public_key, ssh_fingerprint) = canonical_key(&request.ssh_public_key)?;
        let (renewal_public_jwk, renewal_fingerprint) = canonical_jwk(&request.renewal_public_jwk)?;
        Ok(Self::Host {
            status: RecordStatus::Pending,
            host: request.host.clone(),
            ssh_public_key,
            ssh_fingerprint,
            renewal_public_jwk,
            renewal_fingerprint,
            enrolled_at: now.to_owned(),
            revoked_at: None,
        })
    }

    /// Build a canonical pending user record from a public enrollment request.
    pub fn pending_user(request: &UserRequest, now: &str) -> Result<Self> {
        request.validate()?;
        let (ssh_public_key, ssh_fingerprint) = canonical_key(&request.ssh_public_key)?;
        let (renewal_public_jwk, renewal_fingerprint) = canonical_jwk(&request.renewal_public_jwk)?;
        Ok(Self::User {
            status: RecordStatus::Pending,
            user: request.user.clone(),
            client_host: request.host.clone(),
            ssh_public_key,
            ssh_fingerprint,
            renewal_public_jwk,
            renewal_fingerprint,
            enrolled_at: now.to_owned(),
            revoked_at: None,
        })
    }

    /// Build a canonical pending X.509 record from a public enrollment request.
    pub fn pending_x509(request: &X509Request, now: &str) -> Result<Self> {
        request.validate()?;
        let key = CertificateKey::parse(&request.certificate_public_key)?;
        let (renewal_public_jwk, renewal_fingerprint) = canonical_jwk(&request.renewal_public_jwk)?;
        Ok(Self::X509 {
            status: RecordStatus::Pending,
            host: request.host.clone(),
            name: request.name.clone(),
            certificate_public_key: key.pem(),
            certificate_fingerprint: key.fingerprint(),
            renewal_public_jwk,
            renewal_fingerprint,
            enrolled_at: now.to_owned(),
            revoked_at: None,
        })
    }

    /// Human-readable logical identity.
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::Host { host, .. } => format!("host {host}"),
            Self::User {
                user, client_host, ..
            } => format!("user {user}@{client_host}"),
            Self::X509 { host, name, .. } => x509_identity(host, name),
        }
    }

    /// Current registry lifecycle state.
    #[must_use]
    pub const fn status(&self) -> RecordStatus {
        match self {
            Self::Host { status, .. } | Self::User { status, .. } | Self::X509 { status, .. } => {
                *status
            }
        }
    }

    /// Canonical SSH public key, which an X.509 enrollment does not have.
    #[must_use]
    pub fn ssh_public_key(&self) -> Option<&str> {
        match self {
            Self::Host { ssh_public_key, .. } | Self::User { ssh_public_key, .. } => {
                Some(ssh_public_key)
            }
            Self::X509 { .. } => None,
        }
    }

    /// Fingerprint of the key this enrollment certifies, SSH or X.509.
    #[must_use]
    pub fn key_fingerprint(&self) -> &str {
        match self {
            Self::Host {
                ssh_fingerprint, ..
            }
            | Self::User {
                ssh_fingerprint, ..
            } => ssh_fingerprint,
            Self::X509 {
                certificate_fingerprint,
                ..
            } => certificate_fingerprint,
        }
    }

    /// Display name of the kind of key this enrollment certifies.
    #[must_use]
    pub const fn key_kind(&self) -> &'static str {
        match self {
            Self::Host { .. } | Self::User { .. } => "SSH",
            Self::X509 { .. } => "certificate",
        }
    }

    /// Canonical public renewal JWK.
    #[must_use]
    pub fn renewal_public_jwk(&self) -> &Value {
        match self {
            Self::Host {
                renewal_public_jwk, ..
            }
            | Self::User {
                renewal_public_jwk, ..
            }
            | Self::X509 {
                renewal_public_jwk, ..
            } => renewal_public_jwk,
        }
    }

    /// Renewal JWK thumbprint.
    #[must_use]
    pub fn renewal_fingerprint(&self) -> &str {
        match self {
            Self::Host {
                renewal_fingerprint,
                ..
            }
            | Self::User {
                renewal_fingerprint,
                ..
            }
            | Self::X509 {
                renewal_fingerprint,
                ..
            } => renewal_fingerprint,
        }
    }

    /// Whether this record belongs to the named physical policy host.
    #[must_use]
    pub fn belongs_to_host(&self, expected: &str) -> bool {
        match self {
            Self::Host { host, .. } | Self::X509 { host, .. } => host == expected,
            Self::User { client_host, .. } => client_host == expected,
        }
    }

    /// Whether this is the selected user enrollment.
    #[must_use]
    pub fn matches_user(&self, expected_user: &str, expected_host: Option<&str>) -> bool {
        matches!(
            self,
            Self::User { user, client_host, .. }
                if user == expected_user && expected_host.is_none_or(|host| client_host == host)
        )
    }

    /// Whether this is the selected certificate enrollment.
    #[must_use]
    pub fn matches_x509(&self, expected_host: &str, expected_name: &str) -> bool {
        matches!(
            self,
            Self::X509 { host, name, .. } if host == expected_host && name == expected_name
        )
    }

    /// Convert this record into its tracked revocation entry.
    #[must_use]
    pub fn to_revocation(&self, revoked_at: &str, reason: Option<&str>) -> Revocation {
        match self {
            Self::Host {
                host,
                ssh_public_key,
                ssh_fingerprint,
                renewal_fingerprint,
                ..
            } => Revocation::Ssh(RevokedSshKey::Host {
                host: host.clone(),
                public_key: ssh_public_key.clone(),
                fingerprint: ssh_fingerprint.clone(),
                renewal_fingerprint: renewal_fingerprint.clone(),
                revoked_at: revoked_at.to_owned(),
                reason: reason.map(ToOwned::to_owned),
            }),
            Self::User {
                user,
                client_host,
                ssh_public_key,
                ssh_fingerprint,
                renewal_fingerprint,
                ..
            } => Revocation::Ssh(RevokedSshKey::User {
                user: user.clone(),
                client_host: client_host.clone(),
                public_key: ssh_public_key.clone(),
                fingerprint: ssh_fingerprint.clone(),
                renewal_fingerprint: renewal_fingerprint.clone(),
                revoked_at: revoked_at.to_owned(),
                reason: reason.map(ToOwned::to_owned),
            }),
            Self::X509 {
                host,
                name,
                certificate_fingerprint,
                renewal_fingerprint,
                ..
            } => Revocation::X509(RevokedX509Key {
                host: host.clone(),
                name: name.clone(),
                public_key_fingerprint: certificate_fingerprint.clone(),
                renewal_fingerprint: renewal_fingerprint.clone(),
                revoked_at: revoked_at.to_owned(),
                reason: reason.map(ToOwned::to_owned),
            }),
        }
    }

    fn same_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Host { host: left, .. }, Self::Host { host: right, .. }) => left == right,
            (
                Self::User {
                    user: left_user,
                    client_host: left_host,
                    ..
                },
                Self::User {
                    user: right_user,
                    client_host: right_host,
                    ..
                },
            ) => left_user == right_user && left_host == right_host,
            (
                Self::X509 {
                    host: left_host,
                    name: left_name,
                    ..
                },
                Self::X509 {
                    host: right_host,
                    name: right_name,
                    ..
                },
            ) => left_host == right_host && left_name == right_name,
            _ => false,
        }
    }

    fn same_keys(&self, other: &Self) -> bool {
        self.key_fingerprint() == other.key_fingerprint()
            && self.renewal_fingerprint() == other.renewal_fingerprint()
    }

    fn set_status(&mut self, status: RecordStatus, revoked_at: Option<&str>) {
        match self {
            Self::Host {
                status: current,
                revoked_at: current_revoked_at,
                ..
            }
            | Self::User {
                status: current,
                revoked_at: current_revoked_at,
                ..
            }
            | Self::X509 {
                status: current,
                revoked_at: current_revoked_at,
                ..
            } => {
                *current = status;
                *current_revoked_at = revoked_at.map(ToOwned::to_owned);
            }
        }
    }
}

/// Versioned origin-side enrollment inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRegistry {
    format_version: u32,
    #[serde(default)]
    records: Vec<EnrollmentRecord>,
}

impl Default for EnrollmentRegistry {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            records: Vec::new(),
        }
    }
}

impl EnrollmentRegistry {
    /// Load the protected registry; a missing file is an empty pre-migration registry.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => return Err(Error::io(path, source)),
        };
        if !metadata.file_type().is_file() {
            return Err(Error::Validation {
                field: path.display().to_string(),
                message: "enrollment registry must be a regular file, not a symlink".to_owned(),
            });
        }
        #[cfg(unix)]
        {
            if metadata.uid() != rustix::process::geteuid().as_raw() {
                return Err(Error::Validation {
                    field: path.display().to_string(),
                    message: "enrollment registry must be owned by the invoking CA operator"
                        .to_owned(),
                });
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Validation {
                    field: path.display().to_string(),
                    message: "enrollment registry must have owner-only permissions".to_owned(),
                });
            }
        }
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(source) => return Err(Error::io(path, source)),
        };
        let registry: Self = serde_json::from_slice(&bytes).map_err(|source| Error::Json {
            path: path.to_path_buf(),
            source,
        })?;
        registry.validate(path)?;
        Ok(registry)
    }

    /// Persist the complete registry with owner-only permissions and a durable rename.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate(path)?;
        let parent = path.parent().ok_or_else(|| Error::Validation {
            field: path.display().to_string(),
            message: "registry path must have a parent directory".to_owned(),
        })?;
        prepare_registry_directory(parent)?;
        validate_existing_registry_target(path)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|source| Error::Json {
            path: path.to_path_buf(),
            source,
        })?;
        let mut file = tempfile::Builder::new()
            .prefix(".grafhome-ca-enrollments-")
            .tempfile_in(parent)
            .map_err(|source| Error::io(parent, source))?;
        #[cfg(unix)]
        file.as_file_mut()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| Error::io(file.path(), source))?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|source| Error::io(file.path(), source))?;
        file.as_file_mut()
            .sync_all()
            .map_err(|source| Error::io(file.path(), source))?;
        file.persist(path)
            .map_err(|error| Error::io(path, error.error))?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| Error::io(parent, source))?;
        Ok(())
    }

    /// Reserve an enrollment before CA activation. Exact pending/active retries are idempotent.
    pub fn reserve(&mut self, candidate: EnrollmentRecord) -> Result<bool> {
        self.check_candidate(&candidate)?;
        if self.records.iter().any(|record| {
            record.status() != RecordStatus::Revoked && record.same_identity(&candidate)
        }) {
            return Ok(false);
        }
        self.records.push(candidate);
        Ok(true)
    }

    /// State of an exact non-revoked identity and key-pair match.
    #[must_use]
    pub fn matching_status(&self, candidate: &EnrollmentRecord) -> Option<RecordStatus> {
        self.records
            .iter()
            .find(|record| {
                record.status() != RecordStatus::Revoked
                    && record.same_identity(candidate)
                    && record.same_keys(candidate)
            })
            .map(EnrollmentRecord::status)
    }

    /// Mark an exact pending reservation active, or import an exact live enrollment.
    pub fn activate(&mut self, candidate: EnrollmentRecord) -> Result<bool> {
        self.check_candidate(&candidate)?;
        if let Some(record) = self.records.iter_mut().find(|record| {
            record.status() != RecordStatus::Revoked && record.same_identity(&candidate)
        }) {
            if record.status() == RecordStatus::Active {
                return Ok(false);
            }
            record.set_status(RecordStatus::Active, None);
            return Ok(true);
        }
        let mut active = candidate;
        active.set_status(RecordStatus::Active, None);
        self.records.push(active);
        Ok(true)
    }

    /// Return non-revoked records belonging to a host, including its users.
    #[must_use]
    pub fn live_for_host(&self, host: &str) -> Vec<EnrollmentRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.status() != RecordStatus::Revoked && record.belongs_to_host(host)
            })
            .cloned()
            .collect()
    }

    /// Return every current or historical record belonging to a host.
    #[must_use]
    pub fn records_for_host(&self, host: &str) -> Vec<EnrollmentRecord> {
        self.records
            .iter()
            .filter(|record| record.belongs_to_host(host))
            .cloned()
            .collect()
    }

    /// Return non-revoked records for a selected user scope.
    #[must_use]
    pub fn live_for_user(&self, user: &str, host: Option<&str>) -> Vec<EnrollmentRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.status() != RecordStatus::Revoked && record.matches_user(user, host)
            })
            .cloned()
            .collect()
    }

    /// Return every current or historical record for a selected user scope.
    #[must_use]
    pub fn records_for_user(&self, user: &str, host: Option<&str>) -> Vec<EnrollmentRecord> {
        self.records
            .iter()
            .filter(|record| record.matches_user(user, host))
            .cloned()
            .collect()
    }

    /// Return every current or historical record for one certificate.
    #[must_use]
    pub fn records_for_x509(&self, host: &str, name: &str) -> Vec<EnrollmentRecord> {
        self.records
            .iter()
            .filter(|record| record.matches_x509(host, name))
            .cloned()
            .collect()
    }

    /// Permanently tombstone the exact selected key pairs.
    pub fn mark_revoked(&mut self, selected: &[EnrollmentRecord], revoked_at: &str) -> usize {
        let selected = selected
            .iter()
            .map(|record| (record.key_fingerprint(), record.renewal_fingerprint()))
            .collect::<BTreeSet<_>>();
        let mut changed = 0;
        for record in &mut self.records {
            if record.status() != RecordStatus::Revoked
                && selected.contains(&(record.key_fingerprint(), record.renewal_fingerprint()))
            {
                record.set_status(RecordStatus::Revoked, Some(revoked_at));
                changed += 1;
            }
        }
        changed
    }

    fn check_candidate(&self, candidate: &EnrollmentRecord) -> Result<()> {
        for record in &self.records {
            if record.status() == RecordStatus::Revoked
                && (record.key_fingerprint() == candidate.key_fingerprint()
                    || record.renewal_fingerprint() == candidate.renewal_fingerprint())
            {
                return Err(Error::Validation {
                    field: "enrollment registry".to_owned(),
                    message: format!(
                        "{} reuses a previously revoked {} or renewal key",
                        candidate.identity(),
                        candidate.key_kind()
                    ),
                });
            }
            if record.status() != RecordStatus::Revoked && record.same_identity(candidate) {
                if record.same_keys(candidate) {
                    continue;
                }
                return Err(Error::Validation {
                    field: "enrollment registry".to_owned(),
                    message: format!(
                        "{} already has a different active key pair; revoke it before enrolling replacement keys",
                        candidate.identity()
                    ),
                });
            }
            if record.status() != RecordStatus::Revoked
                && (record.key_fingerprint() == candidate.key_fingerprint()
                    || record.renewal_fingerprint() == candidate.renewal_fingerprint())
            {
                return Err(Error::Validation {
                    field: "enrollment registry".to_owned(),
                    message: format!(
                        "{} reuses a {} or renewal key already assigned to {}",
                        candidate.identity(),
                        candidate.key_kind(),
                        record.identity()
                    ),
                });
            }
        }
        Ok(())
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(Error::Validation {
                field: format!("{}:format_version", path.display()),
                message: format!("must be {FORMAT_VERSION}"),
            });
        }
        let mut live_identities = BTreeSet::new();
        let mut certified_keys = BTreeMap::new();
        let mut renewal_keys = BTreeMap::new();
        for (index, record) in self.records.iter().enumerate() {
            validate_record(path, index, record)?;
            if record.status() != RecordStatus::Revoked
                && !live_identities.insert(record.identity())
            {
                return Err(Error::Validation {
                    field: format!("{}:records[{index}]", path.display()),
                    message: "duplicate live logical identity".to_owned(),
                });
            }
            if let Some(previous) = certified_keys.insert(record.key_fingerprint(), index) {
                return Err(Error::Validation {
                    field: format!("{}:records[{index}].key_fingerprint", path.display()),
                    message: format!("duplicates records[{previous}]"),
                });
            }
            if let Some(previous) = renewal_keys.insert(record.renewal_fingerprint(), index) {
                return Err(Error::Validation {
                    field: format!("{}:records[{index}].renewal_fingerprint", path.display()),
                    message: format!("duplicates records[{previous}]"),
                });
            }
        }
        Ok(())
    }
}

/// Current UTC timestamp in the registry and policy wire format.
pub fn now_utc() -> Result<String> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Validation {
            field: "system clock".to_owned(),
            message: format!("could not format UTC timestamp: {error}"),
        })
}

/// Canonical RFC 7638-style public JWK material and its SHA-256 thumbprint.
pub fn canonical_jwk(value: &Value) -> Result<(Value, String)> {
    let canonical = crate::runtime_provisioners::jwk_public_material(value, "renewal public JWK")?;
    let bytes = serde_json::to_vec(&canonical).expect("canonical public JWK serializes");
    let digest = Sha256::digest(bytes);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    Ok((canonical, format!("SHA256:{encoded}")))
}

fn canonical_key(value: &str) -> Result<(String, String)> {
    canonical_ssh_public_key(value).map_err(|message| Error::Validation {
        field: "enrollment SSH public key".to_owned(),
        message,
    })
}

fn validate_record(path: &Path, index: usize, record: &EnrollmentRecord) -> Result<()> {
    let prefix = format!("{}:records[{index}]", path.display());
    match record {
        EnrollmentRecord::Host { host, .. } => {
            validate_host_name(&format!("{prefix}.host"), host)?;
        }
        EnrollmentRecord::User {
            user, client_host, ..
        } => {
            validate_user_name(&format!("{prefix}.user"), user)?;
            validate_host_name(&format!("{prefix}.client_host"), client_host)?;
        }
        EnrollmentRecord::X509 { host, name, .. } => {
            validate_host_name(&format!("{prefix}.host"), host)?;
            validate_host_name(&format!("{prefix}.name"), name)?;
        }
    }
    validate_certified_key(&prefix, record)?;
    let (canonical_jwk, renewal_fingerprint) = canonical_jwk(record.renewal_public_jwk())?;
    if canonical_jwk != *record.renewal_public_jwk()
        || renewal_fingerprint != record.renewal_fingerprint()
    {
        return Err(Error::Validation {
            field: format!("{prefix}.renewal_public_jwk"),
            message: "renewal public JWK or fingerprint is not canonical".to_owned(),
        });
    }
    let (enrolled_at, revoked_at) = match record {
        EnrollmentRecord::Host {
            enrolled_at,
            revoked_at,
            ..
        }
        | EnrollmentRecord::User {
            enrolled_at,
            revoked_at,
            ..
        }
        | EnrollmentRecord::X509 {
            enrolled_at,
            revoked_at,
            ..
        } => (enrolled_at, revoked_at),
    };
    validate_timestamp(&format!("{prefix}.enrolled_at"), enrolled_at)?;
    match (record.status(), revoked_at) {
        (RecordStatus::Revoked, Some(timestamp)) => {
            validate_timestamp(&format!("{prefix}.revoked_at"), timestamp)?;
        }
        (RecordStatus::Revoked, None) => {
            return Err(Error::Validation {
                field: format!("{prefix}.revoked_at"),
                message: "revoked record requires a timestamp".to_owned(),
            });
        }
        (_, Some(_)) => {
            return Err(Error::Validation {
                field: format!("{prefix}.revoked_at"),
                message: "only revoked records may have a revocation timestamp".to_owned(),
            });
        }
        (_, None) => {}
    }
    Ok(())
}

fn validate_certified_key(prefix: &str, record: &EnrollmentRecord) -> Result<()> {
    let (field, canonical) = match record {
        EnrollmentRecord::Host { ssh_public_key, .. }
        | EnrollmentRecord::User { ssh_public_key, .. } => {
            let (key, fingerprint) = canonical_key(ssh_public_key)?;
            (
                "ssh_public_key",
                key == *ssh_public_key && fingerprint == record.key_fingerprint(),
            )
        }
        EnrollmentRecord::X509 {
            certificate_public_key,
            ..
        } => {
            let key = CertificateKey::parse(certificate_public_key)?;
            (
                "certificate_public_key",
                key.pem() == *certificate_public_key
                    && key.fingerprint() == record.key_fingerprint(),
            )
        }
    };
    if canonical {
        return Ok(());
    }
    Err(Error::Validation {
        field: format!("{prefix}.{field}"),
        message: "public key or fingerprint is not canonical".to_owned(),
    })
}

fn validate_host_name(field: &str, value: &str) -> Result<()> {
    if !valid_host_identity(value) {
        return Err(Error::Validation {
            field: field.to_owned(),
            message: "must match [A-Za-z0-9._-]+".to_owned(),
        });
    }
    Ok(())
}

fn validate_user_name(field: &str, value: &str) -> Result<()> {
    if !valid_user_identity(value) {
        return Err(Error::Validation {
            field: field.to_owned(),
            message: "must match [a-z_][a-z0-9_-]*[$]?".to_owned(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_registry_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(Error::Validation {
                field: path.display().to_string(),
                message: "enrollment registry directory must be a real directory, not a symlink"
                    .to_owned(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|source| Error::io(path, source))?;
        }
        Err(source) => return Err(Error::io(path, source)),
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|source| Error::io(path, source))?;
    if !metadata.file_type().is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Validation {
            field: path.display().to_string(),
            message: "enrollment registry directory must be a real directory owned by the invoking CA operator"
                .to_owned(),
        });
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|source| Error::io(path, source))
}

#[cfg(not(unix))]
fn prepare_registry_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| Error::io(path, source))
}

fn validate_existing_registry_target(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(Error::io(path, source)),
    };
    if !metadata.file_type().is_file() {
        return Err(Error::Validation {
            field: path.display().to_string(),
            message: "enrollment registry target must be a regular file".to_owned(),
        });
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Validation {
            field: path.display().to_string(),
            message: "enrollment registry target must be owned by the invoking CA operator"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_timestamp(field: &str, value: &str) -> Result<()> {
    let timestamp =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .map_err(|_| Error::Validation {
                field: field.to_owned(),
                message: "must be an RFC 3339 timestamp".to_owned(),
            })?;
    if timestamp.offset() != time::UtcOffset::UTC || !value.ends_with('Z') {
        return Err(Error::Validation {
            field: field.to_owned(),
            message: "must be UTC and end in Z".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;
    use tempfile::tempdir;

    use super::{EnrollmentRecord, EnrollmentRegistry, RecordStatus, canonical_jwk};
    use crate::enrollment::{HostRequest, UserRequest};

    const KEY_ONE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOF9AFZbHgCPqUAtsZo9RLg6Fg4R+6rKThonym0jI0x3 first";
    const KEY_TWO: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/YQ6c6N8hXDSaeqEQ1UvUgrymxo5vYQNy/1KO4HPpw second";
    const NOW: &str = "2026-07-24T20:14:15Z";

    fn request(host: &str, key: &str, x: &str) -> HostRequest {
        HostRequest::new(
            host,
            key,
            json!({
                "kid": "ignored",
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": "coordinate-y"
            }),
        )
    }

    const CERT_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpLa4TQ2I6fGxrpsTXIjkONnFqp7+
aVXF2GUB0FzWyZNJBGBdIwsLJSjUsFMF+216+CkBLucOD2YTRAkWruHHcQ==
-----END PUBLIC KEY-----
";
    const CERT_KEY_TWO: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE73fnTG0+dIVc6rYompVn1sa8O2+L
5rW09KuHOpbkZ2TDLVemT/xp2ibhgqZsKwZ1q7NjLFocpQDCHIgPJU9KGQ==
-----END PUBLIC KEY-----
";

    fn x509_record(key: &str, x: &str) -> EnrollmentRecord {
        let request = crate::x509::X509Request::new(
            "phone",
            "nfs-client",
            vec!["phone.example.test".to_owned()],
            key,
            json!({"kty": "EC", "crv": "P-256", "x": x, "y": "coordinate-y"}),
        );
        EnrollmentRecord::pending_x509(&request, NOW).unwrap()
    }

    #[test]
    fn registry_accepts_old_records() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let host =
            EnrollmentRecord::pending_host(&request("phone", KEY_ONE, "first-x"), NOW).unwrap();
        let mut old = serde_json::to_value(&host).unwrap();
        old["status"] = json!("active");
        let text = json!({"format_version": 1, "records": [old]}).to_string();
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let registry = EnrollmentRegistry::load(&path).unwrap();

        assert_eq!(registry.live_for_host("phone").len(), 1);
        assert_eq!(
            registry.live_for_host("phone")[0].ssh_public_key(),
            Some(canonical_ssh(KEY_ONE).as_str())
        );
    }

    fn canonical_ssh(key: &str) -> String {
        super::canonical_key(key).unwrap().0
    }

    #[test]
    fn registry_x509_record_has_no_ssh_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let record = x509_record(CERT_KEY, "first-x");
        assert_eq!(record.ssh_public_key(), None);
        assert_eq!(record.identity(), "x509 nfs-client@phone");
        let mut registry = EnrollmentRegistry::default();
        registry.activate(record.clone()).unwrap();

        registry.save(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("ssh_public_key"));
        assert!(!text.contains("ssh_fingerprint"));
        assert!(text.contains("\"kind\": \"x509\""));
        assert_eq!(EnrollmentRegistry::load(&path).unwrap(), registry);
    }

    #[test]
    fn registry_rejects_a_tampered_x509_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let mut record = serde_json::to_value(x509_record(CERT_KEY, "first-x")).unwrap();
        record["certificate_fingerprint"] = json!("SHA256:wrong");
        let text = json!({"format_version": 1, "records": [record]}).to_string();
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(EnrollmentRegistry::load(&path).is_err());
    }

    #[test]
    fn x509_retry_is_idempotent_and_replacement_requires_revocation() {
        let mut registry = EnrollmentRegistry::default();
        let first = x509_record(CERT_KEY, "first-x");
        assert!(registry.reserve(first.clone()).unwrap());
        assert!(!registry.reserve(first.clone()).unwrap());
        assert_eq!(
            registry.matching_status(&first),
            Some(RecordStatus::Pending)
        );
        assert!(registry.activate(first.clone()).unwrap());
        assert!(!registry.activate(first.clone()).unwrap());

        let replacement = x509_record(CERT_KEY_TWO, "second-x");
        assert!(
            registry
                .reserve(replacement.clone())
                .unwrap_err()
                .to_string()
                .contains("revoke it before")
        );

        let selected = registry.records_for_x509("phone", "nfs-client");
        assert_eq!(registry.mark_revoked(&selected, NOW), 1);
        assert!(registry.reserve(replacement).unwrap());
    }

    #[test]
    fn revoked_x509_keys_stay_unusable_across_identities() {
        let mut registry = EnrollmentRegistry::default();
        let first = x509_record(CERT_KEY, "first-x");
        registry.activate(first.clone()).unwrap();
        registry.mark_revoked(&[first], NOW);

        let same_key = x509_record(CERT_KEY, "second-x");
        assert!(
            registry
                .reserve(same_key)
                .unwrap_err()
                .to_string()
                .contains("revoked certificate")
        );
        let same_renewal = x509_record(CERT_KEY_TWO, "first-x");
        assert!(registry.reserve(same_renewal).is_err());
    }

    #[test]
    fn x509_record_cannot_share_a_renewal_key_with_ssh() {
        let mut registry = EnrollmentRegistry::default();
        let host =
            EnrollmentRecord::pending_host(&request("phone", KEY_ONE, "first-x"), NOW).unwrap();
        registry.activate(host).unwrap();

        assert!(
            registry
                .reserve(x509_record(CERT_KEY, "first-x"))
                .unwrap_err()
                .to_string()
                .contains("already assigned")
        );
    }

    #[test]
    fn x509_records_belong_to_their_host_and_become_tombstones() {
        let mut registry = EnrollmentRegistry::default();
        registry.activate(x509_record(CERT_KEY, "first-x")).unwrap();

        let selected = registry.records_for_host("phone");
        assert_eq!(selected.len(), 1);
        match selected[0].to_revocation(NOW, Some("lost")) {
            super::Revocation::X509(entry) => {
                assert_eq!(entry.host, "phone");
                assert_eq!(entry.name, "nfs-client");
                assert_eq!(entry.public_key_fingerprint, selected[0].key_fingerprint());
                assert_eq!(entry.renewal_fingerprint, selected[0].renewal_fingerprint());
                assert_eq!(entry.reason.as_deref(), Some("lost"));
            }
            super::Revocation::Ssh(_) => panic!("expected an X.509 tombstone"),
        }
    }

    #[test]
    fn canonical_jwk_fingerprint_matches_golden_vector() {
        let (_, fingerprint) = canonical_jwk(&json!({
            "kid": "ignored",
            "kty": "EC",
            "crv": "P-256",
            "x": "first-x",
            "y": "coordinate-y"
        }))
        .unwrap();

        assert_eq!(
            fingerprint,
            concat!("SHA256:vcY4BI33zQeIwYzdWKTuCFGTtZF", "oIGvxiz_NGZ11dFU")
        );
    }

    #[test]
    fn registry_allows_reused_identity_only_after_both_keys_change() {
        let mut registry = EnrollmentRegistry::default();
        let first =
            EnrollmentRecord::pending_host(&request("phone", KEY_ONE, "first-x"), NOW).unwrap();
        registry.reserve(first.clone()).unwrap();
        registry.activate(first.clone()).unwrap();
        let selected = registry.live_for_host("phone");
        registry.mark_revoked(&selected, NOW);

        let reused_ssh =
            EnrollmentRecord::pending_host(&request("replacement", KEY_ONE, "second-x"), NOW)
                .unwrap();
        assert!(
            registry
                .reserve(reused_ssh)
                .unwrap_err()
                .to_string()
                .contains("revoked")
        );
        let reused_renewal =
            EnrollmentRecord::pending_host(&request("replacement", KEY_TWO, "first-x"), NOW)
                .unwrap();
        assert!(
            registry
                .reserve(reused_renewal)
                .unwrap_err()
                .to_string()
                .contains("revoked")
        );

        let replacement =
            EnrollmentRecord::pending_host(&request("phone", KEY_TWO, "second-x"), NOW).unwrap();
        assert!(registry.reserve(replacement.clone()).unwrap());
        assert!(registry.activate(replacement).unwrap());
    }

    #[test]
    fn exact_pending_and_active_retries_are_idempotent() {
        let mut registry = EnrollmentRegistry::default();
        let record =
            EnrollmentRecord::pending_host(&request("phone", KEY_ONE, "first-x"), NOW).unwrap();

        assert!(registry.reserve(record.clone()).unwrap());
        assert!(!registry.reserve(record.clone()).unwrap());
        assert!(registry.activate(record.clone()).unwrap());
        assert!(!registry.activate(record).unwrap());
        assert_eq!(
            registry.live_for_host("phone")[0].status(),
            RecordStatus::Active
        );
    }

    #[test]
    fn registry_round_trips_canonical_public_material_with_private_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("enrollments/registry.json");
        let mut registry = EnrollmentRegistry::default();
        let record =
            EnrollmentRecord::pending_host(&request("phone", KEY_ONE, "first-x"), NOW).unwrap();
        registry.activate(record).unwrap();

        registry.save(&path).unwrap();

        assert_eq!(EnrollmentRegistry::load(&path).unwrap(), registry);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("ignored"));
        assert!(!text.contains(" first"));
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn registry_rejects_invalid_logical_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let mut registry = EnrollmentRegistry::default();
        let record =
            EnrollmentRecord::pending_host(&request("../phone", KEY_ONE, "first-x"), NOW).unwrap();
        registry.activate(record).unwrap();

        assert!(
            registry
                .save(&path)
                .unwrap_err()
                .to_string()
                .contains("must match [A-Za-z0-9._-]+")
        );
    }

    #[test]
    fn registry_accepts_a_machine_account_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let request = UserRequest::new(
            "service$",
            "phone",
            KEY_ONE,
            json!({
                "kty": "EC", "crv": "P-256", "x": "service-x", "y": "service-y"
            }),
        );
        let record = EnrollmentRecord::pending_user(&request, NOW).unwrap();
        let mut registry = EnrollmentRegistry::default();
        registry.activate(record).unwrap();

        registry.save(&path).unwrap();

        assert_eq!(EnrollmentRegistry::load(&path).unwrap(), registry);
    }

    #[cfg(unix)]
    #[test]
    fn registry_save_rejects_a_symlinked_parent_directory() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        let linked = dir.path().join("linked");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let path = linked.join("registry.json");
        let registry = EnrollmentRegistry::default();

        let error = registry.save(&path).unwrap_err().to_string();

        assert!(error.contains("registry directory") || error.contains("symlink"));
        assert!(!real.join("registry.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn registry_load_rejects_insecure_permissions_and_symlinks() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("registry.json");
        let link = dir.path().join("linked-registry.json");
        let mut registry = EnrollmentRegistry::default();
        let record =
            EnrollmentRecord::pending_host(&request("phone", KEY_ONE, "first-x"), NOW).unwrap();
        registry.activate(record).unwrap();
        registry.save(&real).unwrap();

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            EnrollmentRegistry::load(&real)
                .unwrap_err()
                .to_string()
                .contains("owner-only permissions")
        );

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            EnrollmentRegistry::load(&link)
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
    }
}
