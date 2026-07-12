//! Structured handoff documents for host and user enrollment.
//!
//! Enrollment documents stay compact enough to copy through a terminal while
//! retaining typed identity fields that each side can validate before acting.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Current enrollment document format.
pub const VERSION: u32 = 1;

const USER_REQUEST_KIND: &str = "grafhome-user-enrollment-request";
const USER_GRANT_KIND: &str = "grafhome-user-enrollment-grant";
const HOST_REQUEST_KIND: &str = "grafhome-host-enrollment-request";
const HOST_GRANT_KIND: &str = "grafhome-host-enrollment-grant";

/// Return the collision-free provisioner name for one user client host.
pub fn user_provisioner_name(user: &str, host: &str) -> String {
    format!("{}{}", user_provisioner_prefix(user), encode_identity(host))
}

/// Return the collision-free provisioner prefix shared by one user's client hosts.
pub fn user_provisioner_prefix(user: &str) -> String {
    format!("grafhome-user-{}-", encode_identity(user))
}

/// Return the collision-free suffix shared by user provisioners on one host.
pub fn user_provisioner_host_suffix(host: &str) -> String {
    format!("-{}", encode_identity(host))
}

/// Return the collision-free provisioner name for one host.
pub fn host_provisioner_name(host: &str) -> String {
    format!("grafhome-host-{}", encode_identity(host))
}

/// Decode a scoped user provisioner into its user and host identities.
pub fn parse_user_provisioner_name(name: &str) -> Option<(String, String)> {
    let encoded = name.strip_prefix("grafhome-user-")?;
    let (user, host) = encoded.split_once('-')?;
    Some((decode_identity(user)?, decode_identity(host)?))
}

/// Decode a scoped host provisioner into its host identity.
pub fn parse_host_provisioner_name(name: &str) -> Option<String> {
    decode_identity(name.strip_prefix("grafhome-host-")?)
}

fn encode_identity(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_identity(value: &str) -> Option<String> {
    if value.len() % 2 != 0 {
        return None;
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect::<Option<Vec<_>>>()?;
    String::from_utf8(bytes).ok()
}

/// Public material prepared by a host before CA approval.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostRequest {
    /// Enrollment document schema version.
    pub version: u32,
    /// Stable document discriminator.
    pub kind: String,
    /// Policy host requesting enrollment.
    pub host: String,
    /// Existing OpenSSH host public key that the certificate must cover.
    pub ssh_public_key: String,
    /// Public half of the host-owned JWK used for later issuance.
    pub renewal_public_jwk: Value,
}

impl HostRequest {
    /// Build a host request from locally generated public keys.
    pub fn new(
        host: impl Into<String>,
        ssh_public_key: impl Into<String>,
        renewal_public_jwk: Value,
    ) -> Self {
        Self {
            version: VERSION,
            kind: HOST_REQUEST_KIND.to_owned(),
            host: host.into(),
            ssh_public_key: ssh_public_key.into(),
            renewal_public_jwk,
        }
    }

    /// Validate stable envelope fields before policy-specific checks.
    pub fn validate(&self) -> Result<()> {
        validate_header(self.version, &self.kind, HOST_REQUEST_KIND)?;
        nonempty("host enrollment request host", &self.host)?;
        validate_public_material(&self.ssh_public_key, &self.renewal_public_jwk)
    }
}

/// Public material prepared by a user client host before CA approval.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserRequest {
    /// Enrollment document schema version.
    pub version: u32,
    /// Stable document discriminator.
    pub kind: String,
    /// Policy user requesting enrollment.
    pub user: String,
    /// Policy client host.
    pub host: String,
    /// OpenSSH public key that the initial certificate must cover.
    pub ssh_public_key: String,
    /// Public half of the client-host-owned JWK used for later issuance.
    pub renewal_public_jwk: Value,
}

impl UserRequest {
    /// Build a user request from locally generated public keys.
    pub fn new(
        user: impl Into<String>,
        host: impl Into<String>,
        ssh_public_key: impl Into<String>,
        renewal_public_jwk: Value,
    ) -> Self {
        Self {
            version: VERSION,
            kind: USER_REQUEST_KIND.to_owned(),
            user: user.into(),
            host: host.into(),
            ssh_public_key: ssh_public_key.into(),
            renewal_public_jwk,
        }
    }

    /// Validate stable envelope fields before policy-specific checks.
    pub fn validate(&self) -> Result<()> {
        validate_header(self.version, &self.kind, USER_REQUEST_KIND)?;
        nonempty("enrollment request user", &self.user)?;
        nonempty("enrollment request host", &self.host)?;
        validate_public_material(&self.ssh_public_key, &self.renewal_public_jwk)
    }
}

fn validate_public_material(ssh_public_key: &str, renewal_public_jwk: &Value) -> Result<()> {
    if !ssh_public_key.starts_with("ssh-") {
        return Err(validation(
            "enrollment request SSH key",
            "expected an OpenSSH public key",
        ));
    }
    let key = renewal_public_jwk.as_object().ok_or_else(|| {
        validation(
            "enrollment request renewal key",
            "public JWK must be an object",
        )
    })?;
    const PRIVATE_JWK_FIELDS: &[&str] = &["d", "k", "p", "q", "dp", "dq", "qi", "oth"];
    if let Some(field) = PRIVATE_JWK_FIELDS
        .iter()
        .find(|field| key.contains_key(**field))
    {
        return Err(validation(
            "enrollment request renewal key",
            format!("request must not contain private JWK material ({field})"),
        ));
    }
    if key.get("kty").and_then(Value::as_str) == Some("oct") {
        return Err(validation(
            "enrollment request renewal key",
            "symmetric JWKs are not valid public renewal keys",
        ));
    }
    Ok(())
}

/// Secret one-time grant returned after a user request is approved.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserGrant {
    /// Enrollment document schema version.
    pub version: u32,
    /// Stable document discriminator.
    pub kind: String,
    /// Policy user authorized by the grant.
    pub user: String,
    /// Policy client host authorized by the grant.
    pub host: String,
    /// OpenSSH public key copied from the approved request.
    pub ssh_public_key: String,
    /// Public renewal JWK copied from the approved request.
    pub renewal_public_jwk: Value,
    /// Public Smallstep CA endpoint.
    pub ca_url: String,
    /// Pinned SHA-256 fingerprint of the root X.509 CA certificate.
    pub root_fingerprint: String,
    /// Short-lived Smallstep SSH signing token.
    pub token: String,
}

impl UserGrant {
    /// Build a grant bound to the public request that was approved.
    pub fn new(
        request: &UserRequest,
        ca_url: impl Into<String>,
        root_fingerprint: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            version: VERSION,
            kind: USER_GRANT_KIND.to_owned(),
            user: request.user.clone(),
            host: request.host.clone(),
            ssh_public_key: request.ssh_public_key.clone(),
            renewal_public_jwk: request.renewal_public_jwk.clone(),
            ca_url: ca_url.into(),
            root_fingerprint: root_fingerprint.into(),
            token: token.into(),
        }
    }

    /// Validate envelope fields before matching the local pending request.
    pub fn validate(&self) -> Result<()> {
        validate_header(self.version, &self.kind, USER_GRANT_KIND)?;
        nonempty("user enrollment grant CA URL", &self.ca_url)?;
        nonempty(
            "user enrollment grant root fingerprint",
            &self.root_fingerprint,
        )?;
        validate_fingerprint(
            "user enrollment grant root fingerprint",
            &self.root_fingerprint,
        )?;
        nonempty("user enrollment grant token", &self.token)
    }
}

/// Secret one-time grant used to enroll an SSH server host.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostGrant {
    /// Enrollment document schema version.
    pub version: u32,
    /// Stable document discriminator.
    pub kind: String,
    /// Policy SSH server host authorized by the grant.
    pub host: String,
    /// OpenSSH host public key copied from the approved request.
    pub ssh_public_key: String,
    /// Public renewal JWK copied from the approved request.
    pub renewal_public_jwk: Value,
    /// Public Smallstep CA endpoint.
    pub ca_url: String,
    /// Pinned SHA-256 fingerprint of the root X.509 CA certificate.
    pub root_fingerprint: String,
    /// Short-lived Smallstep SSH host-signing token.
    pub token: String,
}

impl HostGrant {
    /// Build a host grant from CA-generated enrollment material.
    pub fn new(
        request: &HostRequest,
        ca_url: impl Into<String>,
        root_fingerprint: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            version: VERSION,
            kind: HOST_GRANT_KIND.to_owned(),
            host: request.host.clone(),
            ssh_public_key: request.ssh_public_key.clone(),
            renewal_public_jwk: request.renewal_public_jwk.clone(),
            ca_url: ca_url.into(),
            root_fingerprint: root_fingerprint.into(),
            token: token.into(),
        }
    }

    /// Validate envelope fields before performing privileged host changes.
    pub fn validate(&self) -> Result<()> {
        validate_header(self.version, &self.kind, HOST_GRANT_KIND)?;
        nonempty("host enrollment grant host", &self.host)?;
        nonempty("host enrollment grant CA URL", &self.ca_url)?;
        nonempty(
            "host enrollment grant root fingerprint",
            &self.root_fingerprint,
        )?;
        validate_fingerprint(
            "host enrollment grant root fingerprint",
            &self.root_fingerprint,
        )?;
        nonempty("host enrollment grant token", &self.token)
    }
}

fn validate_header(version: u32, kind: &str, expected_kind: &str) -> Result<()> {
    if version != VERSION {
        return Err(validation(
            "enrollment document version",
            format!("unsupported version {version}"),
        ));
    }
    if kind != expected_kind {
        return Err(validation(
            "enrollment document kind",
            format!("expected {expected_kind}, got {kind}"),
        ));
    }
    Ok(())
}

fn nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(validation(field, "value must not be empty"));
    }
    Ok(())
}

fn validate_fingerprint(field: &str, value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(validation(
            field,
            "expected a 64-character SHA-256 hexadecimal fingerprint",
        ))
    }
}

fn validation(field: impl Into<String>, message: impl Into<String>) -> Error {
    Error::Validation {
        field: field.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        UserGrant, UserRequest, parse_host_provisioner_name, parse_user_provisioner_name,
        user_provisioner_name,
    };

    #[test]
    fn scoped_names_round_trip_without_hyphen_collisions() {
        let first = user_provisioner_name("a-b", "c");
        let second = user_provisioner_name("a", "b-c");

        assert_ne!(first, second);
        assert_eq!(
            parse_user_provisioner_name(&first),
            Some(("a-b".to_owned(), "c".to_owned()))
        );
        assert_eq!(
            parse_host_provisioner_name("grafhome-host-6d6574726f"),
            Some("metro".to_owned())
        );
    }

    #[test]
    fn request_rejects_private_renewal_jwk() {
        let request = UserRequest::new(
            "alice",
            "laptop",
            "ssh-ed25519 AAAA alice@laptop",
            json!({"kty": "OKP", "x": "public", "d": "private"}),
        );

        assert!(
            request
                .validate()
                .unwrap_err()
                .to_string()
                .contains("must not contain private JWK material")
        );
    }

    #[test]
    fn request_rejects_symmetric_renewal_jwk() {
        let request = UserRequest::new(
            "alice",
            "laptop",
            "ssh-ed25519 AAAA alice@laptop",
            json!({"kty": "oct", "k": "shared-secret"}),
        );

        assert!(
            request
                .validate()
                .unwrap_err()
                .to_string()
                .contains("private JWK material (k)")
        );
    }

    #[test]
    fn request_rejects_rsa_private_parameters() {
        let request = UserRequest::new(
            "alice",
            "laptop",
            "ssh-ed25519 AAAA alice@laptop",
            json!({"kty": "RSA", "n": "public", "e": "AQAB", "p": "secret"}),
        );

        assert!(
            request
                .validate()
                .unwrap_err()
                .to_string()
                .contains("private JWK material (p)")
        );
    }

    #[test]
    fn grant_rejects_malformed_root_fingerprint() {
        let request = UserRequest::new(
            "alice",
            "laptop",
            "ssh-ed25519 AAAA alice@laptop",
            json!({"kty": "OKP", "crv": "Ed25519", "x": "public"}),
        );
        let grant = UserGrant::new(&request, "https://ca.example.test", "not-a-hash", "token");

        let error = grant.validate().unwrap_err().to_string();

        assert!(error.contains("64-character SHA-256 hexadecimal fingerprint"));
    }
}
