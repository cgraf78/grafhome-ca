//! X.509-only provisioners, enrollment requests, and on-host key material.
//!
//! `tlshd` accepts any unexpired certificate chaining to the root, so who can
//! obtain a certificate is the entire control. Each provisioner here is bound to
//! one renewal JWK and one enrolled public key, denies SSH, and disables
//! Smallstep's `/renew` and `/rekey`, which would otherwise accept any unexpired
//! certificate without the JWK. Smallstep stays the crypto boundary: this module
//! only produces its configuration and checks a key's fixed-format encoding.
//!
//! Host-side renewal and status also live here. Every fact about a certificate
//! comes from `step certificate inspect`, and each `step` call and lock wait is
//! bounded, because boot units and cron wait on them.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::enrollment::{VERSION, decode_identity, encode_identity, validate_header};
use crate::enrollment_registry::canonical_jwk;
use crate::error::{Error, Result};
use crate::executable::trusted_program;
use crate::policy::{Policy, X509Cert, X509Role, step_duration};
use crate::runtime_provisioners::validate_public_jwk;

const PROVISIONER_PREFIX: &str = "grafhome-x509-";
const REQUEST_KIND: &str = "grafhome-x509-enrollment-request";
const SSH_DENY_TEMPLATE: &str =
    r#"{{ fail "ssh issuance disabled for Grafhome X.509 provisioner" }}"#;
const KEY_MARKER_PREFIX: &str = "{{/* grafhome-ca-x509-key:";
const KEY_MARKER_SUFFIX: &str = " */}}";
const PEM_HEADER: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_FOOTER: &str = "-----END PUBLIC KEY-----";
const PEM_LINE_WIDTH: usize = 64;

/// DER prefix of a P-256 `SubjectPublicKeyInfo` holding an uncompressed point.
///
/// P-256 is the only key type `x509 enroll` creates, and this encoding has a
/// fixed layout, so comparing the prefix is a full check of the key's type
/// without an ASN.1 parser. The coordinates follow at fixed offsets.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
const P256_COORDINATE_LEN: usize = 32;
const P256_SPKI_LEN: usize = P256_SPKI_PREFIX.len() + 2 * P256_COORDINATE_LEN;

/// Mode of a published `cert.pem`, which holds nothing secret.
#[cfg(unix)]
const CERTIFICATE_MODE: u32 = 0o644;
const STEP_TIMEOUT_ENV: &str = "GRAFHOME_CA_X509_STEP_TIMEOUT_SECS";
const LOCK_TIMEOUT_ENV: &str = "GRAFHOME_CA_X509_LOCK_TIMEOUT_SECS";
/// One `step` call or `after_renew` hook. A signature is one CA round trip, so
/// this only has to outlast a slow network, and a boot unit simply retries.
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// Long enough for a holder to finish a normal renewal.
const LOCK_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// How long a timed-out child gets to exit after `SIGTERM`.
const TERMINATE_GRACE: Duration = Duration::from_secs(2);
/// How long to wait for output after a child exits. A daemon the child left
/// behind can hold its pipes open forever, and must not extend the bound.
const DRAIN_GRACE: Duration = Duration::from_secs(1);

/// Return the collision-free provisioner name for one host's certificate.
#[must_use]
pub fn x509_provisioner_name(host: &str, name: &str) -> String {
    format!(
        "{PROVISIONER_PREFIX}{}-{}",
        encode_identity(host),
        encode_identity(name)
    )
}

/// Decode an X.509 provisioner name into its host and policy name.
///
/// Only the exact form [`x509_provisioner_name`] produces parses. This keeps the
/// ACME `grafhome-x509-ca-proxy` out, and a name is what exempts a provisioner
/// from the X.509 deny check, so no spelling variant may qualify.
#[must_use]
pub fn parse_x509_provisioner_name(name: &str) -> Option<(String, String)> {
    let (host, certificate) = name.strip_prefix(PROVISIONER_PREFIX)?.split_once('-')?;
    let host = decode_identity(host)?;
    let certificate = decode_identity(certificate)?;
    let canonical = !host.is_empty()
        && !certificate.is_empty()
        && x509_provisioner_name(&host, &certificate) == name;
    canonical.then_some((host, certificate))
}

/// Human-readable logical identity of one host's certificate.
#[must_use]
pub fn x509_identity(host: &str, name: &str) -> String {
    format!("x509 {name}@{host}")
}

/// Whether a template does nothing but fail, so it can never issue.
#[must_use]
pub fn is_deny_template(template: &str) -> bool {
    let template = template.trim();
    template.starts_with("{{ fail ")
        && template.ends_with("}}")
        && template.matches("{{").count() == 1
}

/// A validated P-256 certificate public key in its canonical encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateKey {
    der: Vec<u8>,
}

impl CertificateKey {
    /// Parse a PEM public key, accepting only P-256.
    pub fn parse(pem: &str) -> Result<Self> {
        let body = pem
            .trim()
            .strip_prefix(PEM_HEADER)
            .and_then(|rest| rest.strip_suffix(PEM_FOOTER))
            .ok_or_else(|| invalid_key("expected a PEM public key"))?;
        let body = body.split_whitespace().collect::<String>();
        let der = STANDARD
            .decode(body)
            .map_err(|_| invalid_key("PEM body is not valid base64"))?;
        Self::from_der(der)
    }

    fn from_der(der: Vec<u8>) -> Result<Self> {
        if der.len() == P256_SPKI_LEN && der.starts_with(&P256_SPKI_PREFIX) {
            Ok(Self { der })
        } else {
            Err(invalid_key("expected a P-256 public key"))
        }
    }

    /// Canonical PEM, the form stored in the registry and sent in requests.
    #[must_use]
    pub fn pem(&self) -> String {
        let encoded = STANDARD.encode(&self.der);
        let mut pem = format!("{PEM_HEADER}\n");
        for line in encoded.as_bytes().chunks(PEM_LINE_WIDTH) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str(PEM_FOOTER);
        pem.push('\n');
        pem
    }

    /// SHA-256 of the DER key, as `SHA256:` plus 43 base64 characters.
    ///
    /// This is the format of an OpenSSH fingerprint and of the policy tombstone.
    /// It hashes the whole `SubjectPublicKeyInfo`, so stock tools can recompute
    /// it from the DER form of the public key.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(&self.der))
        )
    }

    /// Lowercase hex SHA-256 of the DER key, as `step certificate inspect` prints it.
    fn spki_hex(&self) -> String {
        Sha256::digest(&self.der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn coordinate(&self, index: usize) -> String {
        let start = P256_SPKI_PREFIX.len() + index * P256_COORDINATE_LEN;
        let hex = self.der[start..start + P256_COORDINATE_LEN]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        // Must equal Go's `big.Int.Text(16)`, which has no leading zeros.
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_owned()
        } else {
            trimmed.to_owned()
        }
    }

    fn marker(&self) -> String {
        format!(
            "{KEY_MARKER_PREFIX}{}{KEY_MARKER_SUFFIX}",
            STANDARD.encode(&self.der)
        )
    }

    fn from_template(template: &str) -> Option<Self> {
        let encoded = template
            .lines()
            .next()?
            .strip_prefix(KEY_MARKER_PREFIX)?
            .strip_suffix(KEY_MARKER_SUFFIX)?;
        Self::from_der(STANDARD.decode(encoded).ok()?).ok()
    }
}

fn invalid_key(message: &str) -> Error {
    Error::Validation {
        field: "certificate public key".to_owned(),
        message: message.to_owned(),
    }
}

/// Build the Smallstep template that fixes everything a certificate may say.
///
/// Nothing from the CSR or token reaches the output, so a CSR cannot add names,
/// usages, or extensions. The guard compares the coordinates Smallstep parsed
/// from the CSR, whose signature it has already verified, so only the holder of
/// the enrolled private key can be issued. Any other key type has no such fields
/// and fails template execution, which also refuses it.
fn x509_template(cert: &X509Cert, key: &CertificateKey) -> Result<String> {
    let common_name = cert.names.first().ok_or_else(|| Error::Validation {
        field: x509_identity(&cert.host, &cert.name),
        message: "a certificate needs at least one name".to_owned(),
    })?;
    let usage = match cert.role {
        X509Role::Server => "serverAuth",
        X509Role::Client => "clientAuth",
    };
    let sans = cert
        .names
        .iter()
        .map(|name| json!({"type": "dns", "value": name}))
        .collect::<Vec<_>>();
    let body = json!({
        "subject": {"commonName": common_name},
        "sans": sans,
        "keyUsage": ["digitalSignature"],
        "extKeyUsage": [usage],
    });
    let (marker, x, y) = (key.marker(), key.coordinate(0), key.coordinate(1));
    Ok(format!(
        "{marker}\n{{{{- $key := .Insecure.CR.PublicKey }}}}\n{{{{- if or (ne $key.Curve.Params.Name \"P-256\") (ne ($key.X.Text 16) \"{x}\") (ne ($key.Y.Text 16) \"{y}\") }}}}{{{{ fail \"certificate public key does not match enrollment\" }}}}{{{{ end }}}}\n{body}\n"
    ))
}

/// Smallstep claims for one declared certificate.
fn x509_claims(cert: &X509Cert) -> Map<String, Value> {
    Map::from_iter([
        (
            "defaultTLSCertDuration".to_owned(),
            Value::String(cert.ttl.clone()),
        ),
        (
            "maxTLSCertDuration".to_owned(),
            Value::String(cert.ttl.clone()),
        ),
        // Without this, `/renew` and `/rekey` accept any unexpired certificate
        // and key, which would bypass the JWK and survive revocation.
        ("disableRenewal".to_owned(), Value::Bool(true)),
        ("enableSSHCA".to_owned(), Value::Bool(false)),
    ])
}

/// Build the complete X.509-only provisioner for one enrollment.
///
/// Returns a `Result` because `public_key` crosses a trust boundary as text.
pub fn x509_provisioner(key: Value, cert: &X509Cert, public_key: &str) -> Result<Value> {
    let certificate_key = CertificateKey::parse(public_key)?;
    Ok(json!({
        "type": "JWK",
        "name": x509_provisioner_name(&cert.host, &cert.name),
        "key": key,
        "claims": x509_claims(cert),
        "options": {
            "x509": {"template": x509_template(cert, &certificate_key)?},
            "ssh": {"template": SSH_DENY_TEMPLATE},
        },
    }))
}

fn live_name(live: &Value) -> &str {
    live.get("name").and_then(Value::as_str).unwrap_or_default()
}

fn pinned_key(live: &Value) -> Result<CertificateKey> {
    live.pointer("/options/x509/template")
        .and_then(Value::as_str)
        .and_then(CertificateKey::from_template)
        .ok_or_else(|| Error::Validation {
            field: format!("live provisioner {}", live_name(live)),
            message: "X.509 provisioner has no pinned public key".to_owned(),
        })
}

fn live_key(live: &Value) -> Result<&Value> {
    live.get("key").ok_or_else(|| Error::Validation {
        field: format!("live provisioner {}", live_name(live)),
        message: "X.509 provisioner has no public JWK".to_owned(),
    })
}

/// Rebuild a live provisioner from policy, keeping its JWK and pinned key.
///
/// The whole object is replaced, so stale fields cannot widen its authority, and
/// policy stays the one source for its names, usage, and lifetime. A provisioner
/// with no active declaration is refused rather than silently kept, because its
/// host could be issuing a name that policy has since given to another host. The
/// refusal stops the command, not the provisioner: it keeps issuing until revoked.
pub fn reconcile_live(policy: &Policy, live: &Value) -> Result<Value> {
    let name = live_name(live);
    let (host, certificate) =
        parse_x509_provisioner_name(name).ok_or_else(|| Error::Validation {
            field: format!("live provisioner {name}"),
            message: "not an X.509 provisioner name".to_owned(),
        })?;
    let cert = active_cert(policy, &host, &certificate).map_err(|_| Error::Validation {
        field: format!("live provisioner {name}"),
        message: format!(
            "{} has no active policy declaration; restore it or run `grafhome-ca x509 revoke --host {host} {certificate}`",
            x509_identity(&host, &certificate)
        ),
    })?;
    x509_provisioner(live_key(live)?.clone(), cert, &pinned_key(live)?.pem())
}

/// Whether a live provisioner holds a key that policy has tombstoned.
pub fn is_revoked(policy: &Policy, live: &Value) -> Result<bool> {
    let (_, renewal) = canonical_jwk(live_key(live)?)?;
    let certificate = pinned_key(live)?.fingerprint();
    Ok(policy.revoked_x509_keys.iter().any(|entry| {
        entry.renewal_fingerprint == renewal || entry.public_key_fingerprint == certificate
    }))
}

/// Public material prepared by a host before CA approval.
///
/// Unknown fields are rejected, so private material cannot travel in a request
/// even by mistake.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509Request {
    /// Enrollment document schema version.
    pub version: u32,
    /// Stable document discriminator.
    pub kind: String,
    /// Policy host requesting enrollment.
    pub host: String,
    /// Policy certificate name.
    pub name: String,
    /// DNS names the host believes this certificate declares.
    pub names: Vec<String>,
    /// PEM public key of the certificate's private key.
    pub certificate_public_key: String,
    /// Public half of the host-owned JWK that authorizes issuance.
    pub renewal_public_jwk: Value,
}

impl X509Request {
    /// Build a request from locally generated public keys.
    pub fn new(
        host: impl Into<String>,
        name: impl Into<String>,
        names: Vec<String>,
        certificate_public_key: impl Into<String>,
        renewal_public_jwk: Value,
    ) -> Self {
        Self {
            version: VERSION,
            kind: REQUEST_KIND.to_owned(),
            host: host.into(),
            name: name.into(),
            names,
            certificate_public_key: certificate_public_key.into(),
            renewal_public_jwk,
        }
    }

    /// Validate the request's envelope and public keys before policy checks.
    pub fn validate(&self) -> Result<()> {
        validate_header(self.version, &self.kind, REQUEST_KIND)?;
        for (field, value) in [("host", &self.host), ("name", &self.name)] {
            if value.trim().is_empty() {
                return Err(Error::Validation {
                    field: format!("x509 enrollment request {field}"),
                    message: "value must not be empty".to_owned(),
                });
            }
        }
        if self.names.is_empty() {
            return Err(Error::Validation {
                field: "x509 enrollment request names".to_owned(),
                message: "must list at least one name".to_owned(),
            });
        }
        CertificateKey::parse(&self.certificate_public_key)?;
        validate_public_jwk(
            &self.renewal_public_jwk,
            "x509 enrollment request renewal key",
        )?;
        Ok(())
    }
}

/// Find the active declaration a request is approved against.
///
/// Issued names come from this declaration, never from the request. The request's
/// names are compared only so a host working from stale policy fails at approval,
/// not at its first issuance.
pub fn approved_cert<'a>(policy: &'a Policy, request: &X509Request) -> Result<&'a X509Cert> {
    let cert = active_cert(policy, &request.host, &request.name)?;
    if cert.names != request.names {
        return Err(Error::Validation {
            field: "x509 enrollment request names".to_owned(),
            message: format!(
                "{} requests {:?}, but policy declares {:?}",
                x509_identity(&request.host, &request.name),
                request.names,
                cert.names
            ),
        });
    }
    Ok(cert)
}

/// Find the active policy declaration of one host's certificate.
pub fn active_cert<'a>(policy: &'a Policy, host: &str, name: &str) -> Result<&'a X509Cert> {
    let identity = x509_identity(host, name);
    let cert = policy
        .x509_certs_for_host(host)
        .into_iter()
        .find(|cert| cert.name == name)
        .ok_or_else(|| Error::Validation {
            field: "x509 certificate".to_owned(),
            message: format!("{identity} is not declared in policy"),
        })?;
    if !cert.status.is_active() {
        return Err(Error::Validation {
            field: "x509 certificate".to_owned(),
            message: format!("{identity} is not active in policy"),
        });
    }
    Ok(cert)
}

/// Locations of one certificate's local material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X509Paths {
    /// Directory holding the renewal credential.
    pub credential_dir: PathBuf,
    /// Public renewal JWK.
    pub public_jwk: PathBuf,
    /// Encrypted private renewal JWK.
    pub private_jwk: PathBuf,
    /// Password protecting the renewal JWK.
    pub password: PathBuf,
    /// Live certificate: the leaf followed by its intermediate.
    pub cert: PathBuf,
    /// Live certificate private key.
    pub key: PathBuf,
    /// Enrolled replacement key, until a renewal signs it and renames it over `key`.
    pub pending_key: PathBuf,
    /// Serializes changes to this certificate's material. It sits outside the
    /// credential directory, which re-enrollment replaces.
    pub lock: PathBuf,
}

impl X509Paths {
    /// Derive the paths from a host's material directory and the deployment's X.509 directory.
    #[must_use]
    pub fn new(host_material_dir: &Path, x509_dir: &Path, name: &str) -> Self {
        let credentials = host_material_dir.join("x509");
        let credential_dir = credentials.join(name);
        let key_dir = x509_dir.join(name);
        Self {
            public_jwk: credential_dir.join("provisioner.pub.json"),
            private_jwk: credential_dir.join("provisioner.priv.json"),
            password: credential_dir.join("renewal-password"),
            credential_dir,
            cert: key_dir.join("cert.pem"),
            key: key_dir.join("key.pem"),
            pending_key: key_dir.join("key.pem.pending"),
            lock: credentials.join(format!("{name}.lock")),
        }
    }

    /// Whether a renewal credential exists, complete or not. A partial one counts,
    /// so renewal reports it rather than skipping it as not enrolled.
    #[must_use]
    pub fn has_credential(&self) -> bool {
        self.private_jwk.exists() || self.password.exists()
    }

    /// The key an enrollment covers: the pending key if one is staged, else the live key.
    fn enrolled_key(&self) -> Option<&Path> {
        [&self.pending_key, &self.key]
            .into_iter()
            .find(|path| path.exists())
            .map(PathBuf::as_path)
    }
}

/// Create or reuse local material and return the public request.
///
/// Rerunning re-emits the same request. Only a tombstone in the distributed
/// policy replaces material: revoking is what makes re-enrollment possible, and
/// reissuing keys unprompted would just collide with the live provisioner, whose
/// name is reused. A replacement certificate key is staged as `pending_key`, so
/// the live certificate and key stay a matching pair until a renewal signs it.
pub fn prepare_enrollment(
    paths: &X509Paths,
    step_bin: &Path,
    policy: &Policy,
    cert: &X509Cert,
    password: &str,
) -> Result<X509Request> {
    if let Some(parent) = paths.credential_dir.parent() {
        create_private_dir(parent)?;
    }
    if let Some(parent) = paths.key.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::io(parent, source))?;
    }
    // Two racing runs could otherwise each print a request for a key the other
    // replaced, and approval would pin a key this host no longer holds.
    let _lock = lock_material(&paths.lock)?;

    let key = match paths.enrolled_key() {
        None => create_key(step_bin, &paths.key)?,
        Some(path) => {
            require_private_file(path)?;
            let key = public_key_of(step_bin, path)?;
            if key_is_revoked(policy, &key) {
                create_key(step_bin, &paths.pending_key)?
            } else {
                key
            }
        }
    };
    let renewal_public_jwk = match read_renewal_jwk(paths)? {
        Some(jwk) if !renewal_is_revoked(policy, &jwk)? => jwk,
        _ => create_renewal_jwk(step_bin, paths, password)?,
    };

    let request = X509Request::new(
        &cert.host,
        &cert.name,
        cert.names.clone(),
        key.pem(),
        renewal_public_jwk,
    );
    request.validate()?;
    Ok(request)
}

/// Take the material lock if it is free. `None` means another run holds it.
fn try_lock_material(path: &Path) -> Result<Option<File>> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .map_err(|source| Error::io(path, source))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(source) => Err(Error::io(path, source)),
    }
}

/// Wait for the material lock, for no longer than the lock timeout.
///
/// `flock` has no timeout of its own, so this polls: a holder stuck in a kernel
/// wait must not be able to hold a boot unit here with it.
fn lock_material(path: &Path) -> Result<File> {
    let timeout = timeout_from(LOCK_TIMEOUT_ENV, LOCK_TIMEOUT)?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(file) = try_lock_material(path)? {
            return Ok(file);
        }
        if Instant::now() >= deadline {
            return Err(Error::Validation {
                field: path.display().to_string(),
                message: format!("timed out after {timeout:?} waiting for the lock"),
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Read a timeout override, refusing a value that would not be a bound.
fn timeout_from(variable: &str, default: Duration) -> Result<Duration> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(default);
    };
    value
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| Error::Validation {
            field: variable.to_owned(),
            message: "must be a positive whole number of seconds".to_owned(),
        })
}

fn key_is_revoked(policy: &Policy, key: &CertificateKey) -> bool {
    let fingerprint = key.fingerprint();
    policy
        .revoked_x509_keys
        .iter()
        .any(|entry| entry.public_key_fingerprint == fingerprint)
}

fn renewal_is_revoked(policy: &Policy, jwk: &Value) -> Result<bool> {
    let (_, fingerprint) = canonical_jwk(jwk)?;
    Ok(policy
        .revoked_x509_keys
        .iter()
        .any(|entry| entry.renewal_fingerprint == fingerprint))
}

/// Read the existing renewal JWK, refusing a partial credential.
fn read_renewal_jwk(paths: &X509Paths) -> Result<Option<Value>> {
    let parts = [&paths.private_jwk, &paths.public_jwk, &paths.password];
    let present = parts.iter().filter(|path| path.exists()).count();
    if present == 0 {
        return Ok(None);
    }
    if present != parts.len() {
        return Err(Error::Validation {
            field: paths.credential_dir.display().to_string(),
            message: "incomplete renewal credential; remove this directory and enroll again"
                .to_owned(),
        });
    }
    require_private_file(&paths.private_jwk)?;
    require_private_file(&paths.password)?;
    let text = std::fs::read_to_string(&paths.public_jwk)
        .map_err(|source| Error::io(&paths.public_jwk, source))?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|source| Error::Json {
            path: paths.public_jwk.clone(),
            source,
        })
}

/// Generate a renewal JWK, then swap it in as a complete directory.
///
/// A crash can therefore leave the old credential or the new one, never a
/// password that does not open its key. Removing the old one first is safe
/// because this only runs when it is absent or revoked, so it grants nothing.
fn create_renewal_jwk(step_bin: &Path, paths: &X509Paths, password: &str) -> Result<Value> {
    let parent = paths
        .credential_dir
        .parent()
        .ok_or_else(|| Error::Validation {
            field: paths.credential_dir.display().to_string(),
            message: "credential directory must have a parent".to_owned(),
        })?;
    let staged = staging_dir(".grafhome-ca-x509-credential-")
        .tempdir_in(parent)
        .map_err(|source| Error::io(parent, source))?;
    let file_name = |path: &Path| {
        staged
            .path()
            .join(path.file_name().expect("credential path has a file name"))
    };
    let (public, private, password_file) = (
        file_name(&paths.public_jwk),
        file_name(&paths.private_jwk),
        file_name(&paths.password),
    );
    write_private_file(&password_file, password.as_bytes())?;
    run_step(
        Command::new(step_bin)
            .args(["crypto", "jwk", "create"])
            .arg(&public)
            .arg(&private)
            .arg("--password-file")
            .arg(&password_file),
    )?;
    set_private_mode(&private)?;
    let text = std::fs::read_to_string(&public).map_err(|source| Error::io(&public, source))?;
    let jwk = serde_json::from_str(&text).map_err(|source| Error::Json {
        path: public.clone(),
        source,
    })?;
    if paths.credential_dir.exists() {
        std::fs::remove_dir_all(&paths.credential_dir)
            .map_err(|source| Error::io(&paths.credential_dir, source))?;
    }
    std::fs::rename(staged.path(), &paths.credential_dir)
        .map_err(|source| Error::io(&paths.credential_dir, source))?;
    Ok(jwk)
}

/// Generate a P-256 key and rename it into place, never exposing it.
///
/// `tlshd` and Apache read this key unattended, so it cannot be encrypted; its
/// `0600` mode and root-owned directory are the protection. It is generated in a
/// private directory on the destination filesystem, which also keeps the rename
/// atomic.
fn create_key(step_bin: &Path, destination: &Path) -> Result<CertificateKey> {
    let parent = destination.parent().ok_or_else(|| Error::Validation {
        field: destination.display().to_string(),
        message: "key path must have a parent directory".to_owned(),
    })?;
    let staged = staging_dir(".grafhome-ca-x509-key-")
        .tempdir_in(parent)
        .map_err(|source| Error::io(parent, source))?;
    let public = staged.path().join("key.pub.pem");
    let private = staged.path().join("key.pem");
    run_step(
        Command::new(step_bin)
            .args(["crypto", "keypair"])
            .arg(&public)
            .arg(&private)
            .args([
                "--kty",
                "EC",
                "--crv",
                "P-256",
                "--no-password",
                "--insecure",
            ]),
    )?;
    set_private_mode(&private)?;
    let text = std::fs::read_to_string(&public).map_err(|source| Error::io(&public, source))?;
    let key = CertificateKey::parse(&text)?;
    std::fs::rename(&private, destination).map_err(|source| Error::io(destination, source))?;
    Ok(key)
}

/// A builder for a private staging directory.
///
/// `tempfile` leaves a directory's mode to the umask, and these hold secrets, one
/// of which becomes the credential directory by rename.
fn staging_dir(prefix: &str) -> tempfile::Builder<'_, 'static> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    builder.permissions(std::fs::Permissions::from_mode(0o700));
    builder
}

fn public_key_of(step_bin: &Path, private_key: &Path) -> Result<CertificateKey> {
    let output = run_step(
        Command::new(step_bin)
            .args(["crypto", "key", "public"])
            .arg(private_key),
    )?;
    CertificateKey::parse(&String::from_utf8_lossy(&output))
}

/// Run `step`, keeping its output out of ours except for a failure's stderr.
fn run_step(command: &mut Command) -> Result<Vec<u8>> {
    run_step_redacted(command, None)
}

/// [`run_step`], removing a secret from any failure text.
fn run_step_redacted(command: &mut Command, secret: Option<&str>) -> Result<Vec<u8>> {
    let output = run_bounded(command, timeout_from(STEP_TIMEOUT_ENV, STEP_TIMEOUT)?)?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = match secret {
        Some(secret) => stderr.replace(secret, "[redacted]"),
        None => stderr.into_owned(),
    };
    Err(Error::Validation {
        field: "step".to_owned(),
        message: format!("{:?} failed: {}", leading_args(command), stderr.trim()),
    })
}

/// The arguments that name a `step` subcommand. Later ones can hold a token.
fn leading_args(command: &Command) -> Vec<&std::ffi::OsStr> {
    command.get_args().take(3).collect()
}

/// A child that exited within its bound.
struct Finished {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run a command for at most `timeout`, in its own process group.
///
/// The group lets a timeout reach whatever the command started, which would
/// otherwise keep running and hold the output pipes open. Only a timeout signals
/// it: a daemon a hook started on purpose must outlive a successful hook.
fn run_bounded(command: &mut Command, timeout: Duration) -> Result<Finished> {
    #[cfg(unix)]
    command.process_group(0);
    let program = OsString::from(command.get_program());
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| Error::io(Path::new(&program), source))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    loop {
        let finished = child
            .try_wait()
            .map_err(|source| Error::io(Path::new(&program), source));
        match finished {
            Ok(Some(status)) => {
                return Ok(Finished {
                    status,
                    stdout: stdout.recv_timeout(DRAIN_GRACE).unwrap_or_default(),
                    stderr: stderr.recv_timeout(DRAIN_GRACE).unwrap_or_default(),
                });
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                terminate(&mut child);
                return Err(Error::Validation {
                    field: "step".to_owned(),
                    message: format!("{:?} timed out after {timeout:?}", leading_args(command)),
                });
            }
            Err(error) => {
                terminate(&mut child);
                return Err(error);
            }
        }
    }
}

/// Collect a pipe on its own thread, so a full pipe cannot stall the child.
fn drain(source: Option<impl Read + Send + 'static>) -> Receiver<Vec<u8>> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        if let Some(mut source) = source {
            source.read_to_end(&mut output).ok();
        }
        sender.send(output).ok();
    });
    receiver
}

/// Stop a timed-out child and everything it started, then reap it.
#[cfg(unix)]
fn terminate(child: &mut Child) {
    use rustix::process::{Pid, Signal, kill_process_group};

    let group = Pid::from_child(child);
    kill_process_group(group, Signal::TERM).ok();
    let deadline = Instant::now() + TERMINATE_GRACE;
    while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
        std::thread::sleep(POLL_INTERVAL);
    }
    // Descendants may ignore `SIGTERM`, and they keep the group alive even once
    // the leader is gone.
    kill_process_group(group, Signal::KILL).ok();
    child.wait().ok();
}

#[cfg(not(unix))]
fn terminate(child: &mut Child) {
    child.kill().ok();
    child.wait().ok();
}

fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| Error::io(path, source))?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|source| Error::io(path, source))?;
    Ok(())
}

fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|source| Error::io(path, source))?;
    file.write_all(content)
        .map_err(|source| Error::io(path, source))
}

fn set_private_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|source| Error::io(path, source))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Confirm an existing secret is a regular file, and repair its mode.
fn require_private_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| Error::io(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(Error::Validation {
            field: path.display().to_string(),
            message: "private material must be a regular file".to_owned(),
        });
    }
    set_private_mode(path)
}

/// `step certificate inspect --format json`, reduced to the facts used here.
#[derive(Debug, Deserialize)]
struct InspectedCertificate {
    #[serde(default)]
    names: Vec<String>,
    validity: InspectedValidity,
    subject_key_info: InspectedKey,
    #[serde(default)]
    extensions: InspectedExtensions,
}

#[derive(Debug, Deserialize)]
struct InspectedValidity {
    end: String,
}

#[derive(Debug, Deserialize)]
struct InspectedKey {
    fingerprint_sha256: String,
}

#[derive(Debug, Default, Deserialize)]
struct InspectedExtensions {
    #[serde(default)]
    extended_key_usage: BTreeMap<String, Value>,
}

/// With `--bundle`, `step` prints an array, or a bare object for one certificate.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InspectedBundle {
    Chain(Vec<InspectedCertificate>),
    Single(Box<InspectedCertificate>),
}

/// The leaf of a certificate file, and how many certificates came with it.
#[derive(Debug)]
struct Chain {
    leaf: InspectedCertificate,
    not_after: OffsetDateTime,
    length: usize,
}

impl Chain {
    /// Whether the file carries the intermediate. Truststores pin only the root,
    /// so a leaf alone is refused in both directions.
    fn is_complete(&self) -> bool {
        self.length > 1
    }
}

/// Whether a certificate is due for renewal: a third of its lifetime has elapsed.
#[must_use]
pub fn renewal_due(not_after: OffsetDateTime, ttl: time::Duration, now: OffsetDateTime) -> bool {
    (not_after - now) * 3 <= ttl * 2
}

/// Whether a certificate needs a person: under one-third of its lifetime remains.
#[must_use]
pub fn alert_due(not_after: OffsetDateTime, ttl: time::Duration, now: OffsetDateTime) -> bool {
    (not_after - now) * 3 < ttl
}

/// The state of a live certificate, as a TLS peer would find it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Condition {
    /// Present, complete, unexpired, and matching the live key.
    Valid,
    /// No `cert.pem`.
    Missing,
    /// `step` cannot read `cert.pem`.
    Unreadable,
    /// `cert.pem` lacks its intermediate.
    NoIntermediate,
    /// `cert.pem` does not match `key.pem`.
    KeyMismatch,
    /// `cert.pem` has expired.
    Expired,
}

/// What a certificate looks like now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Assessment {
    /// The live certificate's state.
    pub condition: Condition,
    /// When it expires, if it can be read.
    pub not_after: Option<OffsetDateTime>,
    /// Whether an enrolled replacement key is waiting to be signed.
    pub pending_key: bool,
}

impl Assessment {
    /// Whether this host can complete a handshake with what it has.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.condition == Condition::Valid
    }

    fn renewal_needed(&self, ttl: time::Duration, now: OffsetDateTime) -> bool {
        !self.usable()
            || self.pending_key
            || self.not_after.is_none_or(|end| renewal_due(end, ttl, now))
    }

    /// Whether `x509 status` must alert.
    #[must_use]
    pub fn alert(&self, ttl: time::Duration, now: OffsetDateTime) -> bool {
        !self.usable() || self.not_after.is_none_or(|end| alert_due(end, ttl, now))
    }
}

/// What a renewal run did, when it did not fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Renewal {
    /// The live certificate needs nothing.
    Current,
    /// Another run holds the lock, and the live certificate still works.
    Busy,
    /// A new certificate is live.
    Published {
        /// When the new certificate expires.
        not_after: OffsetDateTime,
    },
}

/// Why a renewal failed, which decides who hears about it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    /// The CA could not be used, or a concurrent run could not be waited out.
    /// A TCP probe cannot see past a proxy, and `step`'s prose is not a contract,
    /// so a failed token or signature counts as this too.
    Unavailable,
    /// Anything an outage cannot explain, such as a refused candidate.
    Refused,
    /// The certificate is published, but its `after_renew` hook failed.
    AfterRenew,
}

/// A failed renewal.
#[derive(Debug)]
pub struct RenewalFailure {
    /// What went wrong.
    pub error: Error,
    /// Which kind of failure this is.
    pub kind: FailureKind,
    /// Whether the live certificate still works.
    pub usable: bool,
}

impl RenewalFailure {
    /// Whether `--if-reachable` lets the run succeed anyway: only while the live
    /// certificate works, so a boot unit never releases `nfs-server` or a mount
    /// without one. A failed hook is about a certificate already published, and
    /// its service still needs a person whatever the CA is doing.
    #[must_use]
    pub fn tolerated(&self) -> bool {
        self.usable && self.kind != FailureKind::AfterRenew
    }

    /// Whether `--if-reachable --quiet` hides this. Only an outage is hidden: cron
    /// runs every 5 minutes, and `x509 status` reports what the outage costs.
    #[must_use]
    pub fn hidden(&self) -> bool {
        self.kind == FailureKind::Unavailable
    }
}

/// One declared certificate on this host, and what it takes to reach its CA.
#[derive(Clone, Debug)]
pub struct LocalCertificate<'a> {
    /// The policy declaration.
    pub cert: &'a X509Cert,
    /// Where its local material lives.
    pub paths: X509Paths,
    /// Trusted `step` executable.
    pub step_bin: PathBuf,
    /// `STEPPATH` for `step`.
    pub steppath: PathBuf,
    /// The pinned root certificate.
    pub root: PathBuf,
    /// URL of the certificate's own CA endpoint.
    pub ca_url: String,
}

impl LocalCertificate<'_> {
    /// The declared lifetime.
    pub fn ttl(&self) -> Result<time::Duration> {
        step_duration(&self.cert.ttl).ok_or_else(|| Error::Validation {
            field: x509_identity(&self.cert.host, &self.cert.name),
            message: format!("invalid ttl {}", self.cert.ttl),
        })
    }

    fn step(&self) -> Command {
        let mut command = Command::new(&self.step_bin);
        command.env("STEPPATH", &self.steppath);
        command
    }

    /// Read a certificate file. `None` means `step` cannot make sense of it.
    fn read_chain(&self, file: &Path) -> Result<Option<Chain>> {
        let output = run_bounded(
            self.step()
                .args(["certificate", "inspect", "--format", "json", "--bundle"])
                .arg(file),
            timeout_from(STEP_TIMEOUT_ENV, STEP_TIMEOUT)?,
        )?;
        if !output.status.success() {
            return Ok(None);
        }
        let (leaf, length) = match serde_json::from_slice(&output.stdout) {
            Ok(InspectedBundle::Single(leaf)) => (*leaf, 1),
            Ok(InspectedBundle::Chain(mut chain)) if !chain.is_empty() => {
                let length = chain.len();
                (chain.remove(0), length)
            }
            _ => return Ok(None),
        };
        let Ok(not_after) = OffsetDateTime::parse(&leaf.validity.end, &Rfc3339) else {
            return Ok(None);
        };
        Ok(Some(Chain {
            leaf,
            not_after,
            length,
        }))
    }

    /// Assess the live certificate. This stays offline, so `x509 status` still
    /// reports with the CA down.
    pub fn assess(&self, now: OffsetDateTime) -> Result<Assessment> {
        let pending_key = self.paths.pending_key.exists();
        let assessment = |condition, not_after| Assessment {
            condition,
            not_after,
            pending_key,
        };
        if !self.paths.cert.exists() {
            return Ok(assessment(Condition::Missing, None));
        }
        let Some(chain) = self.read_chain(&self.paths.cert)? else {
            return Ok(assessment(Condition::Unreadable, None));
        };
        let matches_key = self.paths.key.exists()
            && public_key_of(&self.step_bin, &self.paths.key)?.spki_hex()
                == chain.leaf.subject_key_info.fingerprint_sha256;
        let condition = if !matches_key {
            Condition::KeyMismatch
        } else if !chain.is_complete() {
            Condition::NoIntermediate
        } else if chain.not_after <= now {
            Condition::Expired
        } else {
            Condition::Valid
        };
        Ok(assessment(condition, Some(chain.not_after)))
    }

    /// Bring the live certificate up to date.
    ///
    /// `reachable`, set by `--if-reachable`, probes the CA before any attempt. Runs
    /// on one certificate are serialized. A contended run skips while the live
    /// certificate works and waits otherwise, because a boot needs the result, and
    /// it assesses again once it holds the lock, because the holder may have just
    /// done this work.
    pub fn renew(
        &self,
        reachable: Option<&dyn Fn() -> Result<bool>>,
    ) -> std::result::Result<Renewal, RenewalFailure> {
        let ttl = self.ttl().map_err(refused(false))?;
        let first = self
            .assess(OffsetDateTime::now_utc())
            .map_err(refused(false))?;
        if !first.renewal_needed(ttl, OffsetDateTime::now_utc()) {
            return Ok(Renewal::Current);
        }
        let held = try_lock_material(&self.paths.lock).map_err(refused(first.usable()))?;
        let _lock = match held {
            Some(lock) => lock,
            None if first.usable() => return Ok(Renewal::Busy),
            None => lock_material(&self.paths.lock).map_err(unavailable(false))?,
        };

        let current = self
            .assess(OffsetDateTime::now_utc())
            .map_err(refused(first.usable()))?;
        if !current.renewal_needed(ttl, OffsetDateTime::now_utc()) {
            return Ok(Renewal::Current);
        }
        let usable = current.usable();
        if let Some(reachable) = reachable {
            // A probe that errors has not shown the CA is up.
            if !reachable().unwrap_or(false) {
                return Err(unavailable(usable)(Error::Validation {
                    field: x509_identity(&self.cert.host, &self.cert.name),
                    message: format!("CA endpoint {} is unreachable", self.ca_url),
                }));
            }
        }
        let not_after = self.issue(usable)?;
        self.run_after_renew().map_err(|error| RenewalFailure {
            error,
            kind: FailureKind::AfterRenew,
            usable,
        })?;
        Ok(Renewal::Published { not_after })
    }

    /// Issue and publish, signing a pending key if one is staged.
    ///
    /// The candidate is built beside the live files, so publishing is a rename, and
    /// `tlshd`, which reads them on each handshake, sees the old pair or the new
    /// one. Signing and validation finish before any rename. With a pending key
    /// the key moves first: a crash between the two renames leaves a pair that
    /// [`Self::assess`] reports as mismatched, which the next run repairs.
    fn issue(&self, usable: bool) -> std::result::Result<OffsetDateTime, RenewalFailure> {
        let key = self.paths.enrolled_key().ok_or_else(|| {
            refused(usable)(Error::Validation {
                field: x509_identity(&self.cert.host, &self.cert.name),
                message: "no certificate key; run `grafhome-ca x509 enroll`".to_owned(),
            })
        })?;
        for secret in [key, &self.paths.private_jwk, &self.paths.password] {
            require_private_file(secret).map_err(refused(usable))?;
        }
        let public_key = public_key_of(&self.step_bin, key).map_err(refused(usable))?;
        let directory = self.paths.cert.parent().ok_or_else(|| {
            refused(usable)(Error::Validation {
                field: self.paths.cert.display().to_string(),
                message: "certificate path must have a parent directory".to_owned(),
            })
        })?;
        let staged = staging_dir(".grafhome-ca-x509-cert-")
            .tempdir_in(directory)
            .map_err(|source| refused(usable)(Error::io(directory, source)))?;
        let csr = staged.path().join("request.csr");
        let candidate = staged.path().join("cert.pem");

        self.create_csr(key, &csr).map_err(refused(usable))?;
        self.sign(&csr, &candidate).map_err(unavailable(usable))?;
        let not_after = self
            .validate(&candidate, &public_key)
            .map_err(refused(usable))?;
        // A failure here can land between the renames, so nothing vouches for the
        // live pair any more.
        self.publish(&candidate).map_err(refused(false))?;
        Ok(not_after)
    }

    /// Create a CSR for `key`. `step-ca` refuses one whose common name is not the
    /// first name, or whose names differ from the token's.
    fn create_csr(&self, key: &Path, csr: &Path) -> Result<()> {
        let mut command = self.step();
        command
            .args(["certificate", "create"])
            .arg(self.common_name()?)
            .arg(csr)
            .arg("--csr")
            .arg("--key")
            .arg(key)
            .args(["--no-password", "--insecure"]);
        for name in &self.cert.names {
            command.arg("--san").arg(name);
        }
        run_step(&mut command).map(drop)
    }

    /// Sign a CSR on the certificate's own CA endpoint. The renewal JWK is the
    /// authority here, so this works just the same on an expired certificate.
    fn sign(&self, csr: &Path, candidate: &Path) -> Result<()> {
        let mut command = self.step();
        command.args(["ca", "token"]).arg(self.common_name()?);
        for name in &self.cert.names {
            command.arg("--san").arg(name);
        }
        let token = run_step(
            command
                .arg("--issuer")
                .arg(x509_provisioner_name(&self.cert.host, &self.cert.name))
                .arg("--key")
                .arg(&self.paths.private_jwk)
                .arg("--password-file")
                .arg(&self.paths.password)
                .arg("--ca-url")
                .arg(&self.ca_url)
                .arg("--root")
                .arg(&self.root),
        )?;
        let token = String::from_utf8_lossy(&token);
        let token = token.trim();
        run_step_redacted(
            self.step()
                .args(["ca", "sign"])
                .arg(csr)
                .arg(candidate)
                .arg("--token")
                .arg(token)
                .arg("--ca-url")
                .arg(&self.ca_url)
                .arg("--root")
                .arg(&self.root),
            Some(token),
        )
        .map(drop)
    }

    /// Check a candidate against the declaration before it can replace anything.
    ///
    /// The CA template pins all of this already. Checking again here means a CA
    /// that drifted costs a failed renewal rather than a broken live certificate.
    fn validate(&self, candidate: &Path, key: &CertificateKey) -> Result<OffsetDateTime> {
        let refuse = |message: String| Error::Validation {
            field: x509_identity(&self.cert.host, &self.cert.name),
            message,
        };
        let chain = self
            .read_chain(candidate)?
            .ok_or_else(|| refuse("step cannot read the certificate the CA returned".to_owned()))?;
        if !chain.is_complete() {
            return Err(refuse("the CA returned no intermediate".to_owned()));
        }
        let mut names = chain.leaf.names.clone();
        names.sort();
        let mut declared = self.cert.names.clone();
        declared.sort();
        if names != declared {
            return Err(refuse(format!(
                "the CA issued names {names:?}, but policy declares {declared:?}"
            )));
        }
        let usages = chain
            .leaf
            .extensions
            .extended_key_usage
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let declared_usage = match self.cert.role {
            X509Role::Server => "server_auth",
            X509Role::Client => "client_auth",
        };
        if usages != [declared_usage] {
            return Err(refuse(format!(
                "the CA issued extended key usage {usages:?}, but policy declares {declared_usage}"
            )));
        }
        if chain.leaf.subject_key_info.fingerprint_sha256 != key.spki_hex() {
            return Err(refuse(
                "the issued certificate does not match the signing key".to_owned(),
            ));
        }
        if chain.not_after <= OffsetDateTime::now_utc() {
            return Err(refuse("the CA returned an expired certificate".to_owned()));
        }
        // Against the root alone, as a peer's truststore is, so this also proves
        // the file carries a working intermediate.
        run_step(
            self.step()
                .args(["certificate", "verify"])
                .arg(candidate)
                .arg("--roots")
                .arg(&self.root)
                .arg("--host")
                .arg(self.common_name()?),
        )?;
        Ok(chain.not_after)
    }

    /// Replace the live files with a validated candidate.
    fn publish(&self, candidate: &Path) -> Result<()> {
        #[cfg(unix)]
        std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(CERTIFICATE_MODE))
            .map_err(|source| Error::io(candidate, source))?;
        if self.paths.pending_key.exists() {
            std::fs::rename(&self.paths.pending_key, &self.paths.key)
                .map_err(|source| Error::io(&self.paths.key, source))?;
        }
        std::fs::rename(candidate, &self.paths.cert)
            .map_err(|source| Error::io(&self.paths.cert, source))
    }

    /// Run the declared hook, checking its program's provenance just before use.
    ///
    /// Publishing comes first: a host with a bad hook is better off with a fresh
    /// certificate and a reported failure than an expiring one. It is not retried,
    /// and the next renewal reruns it while the certificate it missed is still valid.
    fn run_after_renew(&self) -> Result<()> {
        let Some((program, arguments)) = self.cert.after_renew.split_first() else {
            return Ok(());
        };
        let refuse = |message: String| Error::Validation {
            field: format!(
                "after_renew of {}",
                x509_identity(&self.cert.host, &self.cert.name)
            ),
            message,
        };
        let program =
            trusted_program(Path::new(program)).map_err(|error| refuse(error.to_string()))?;
        let output = run_bounded(
            Command::new(program).args(arguments),
            timeout_from(STEP_TIMEOUT_ENV, STEP_TIMEOUT)?,
        )
        .map_err(|error| refuse(error.to_string()))?;
        if output.status.success() {
            return Ok(());
        }
        Err(refuse(format!(
            "exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    fn common_name(&self) -> Result<&str> {
        self.cert
            .names
            .first()
            .map(String::as_str)
            .ok_or_else(|| Error::Validation {
                field: x509_identity(&self.cert.host, &self.cert.name),
                message: "a certificate needs at least one name".to_owned(),
            })
    }
}

fn refused(usable: bool) -> impl Fn(Error) -> RenewalFailure {
    failure(FailureKind::Refused, usable)
}

fn unavailable(usable: bool) -> impl Fn(Error) -> RenewalFailure {
    failure(FailureKind::Unavailable, usable)
}

fn failure(kind: FailureKind, usable: bool) -> impl Fn(Error) -> RenewalFailure {
    move |error| RenewalFailure {
        error,
        kind,
        usable,
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use serde_json::{Value, json};

    use super::{
        CertificateKey, FailureKind, RenewalFailure, X509Request, alert_due, approved_cert,
        is_deny_template, parse_x509_provisioner_name, reconcile_live, renewal_due,
        x509_provisioner, x509_provisioner_name,
    };
    use crate::policy::{Status, X509Cert, X509Role};

    const KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpLa4TQ2I6fGxrpsTXIjkONnFqp7+
aVXF2GUB0FzWyZNJBGBdIwsLJSjUsFMF+216+CkBLucOD2YTRAkWruHHcQ==
-----END PUBLIC KEY-----
";

    fn cert(role: X509Role) -> X509Cert {
        X509Cert {
            host: "edge-host".to_owned(),
            name: "nfs-client".to_owned(),
            role,
            names: vec![
                "edge.example.test".to_owned(),
                "edge2.example.test".to_owned(),
            ],
            ttl: "24h".to_owned(),
            ca_endpoint: "ca_api".to_owned(),
            after_renew: Vec::new(),
            status: Status::Active,
        }
    }

    fn jwk() -> Value {
        json!({"kid": "renewal-kid", "kty": "EC", "crv": "P-256", "x": "x", "y": "y"})
    }

    /// The JSON document after the template's guard lines.
    fn template_body(provisioner: &Value) -> Value {
        let template = provisioner["options"]["x509"]["template"].as_str().unwrap();
        serde_json::from_str(template.lines().last().unwrap()).unwrap()
    }

    fn at(seconds: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds)
    }

    #[test]
    fn renewal_due_boundaries() {
        const HOUR: i64 = 3600;
        for (ttl_hours, remaining_hours) in [(24, 16), (720, 480)] {
            let ttl = time::Duration::hours(ttl_hours);
            let not_after = at(remaining_hours * HOUR);
            assert!(!renewal_due(not_after, ttl, at(-1)), "{ttl_hours}h early");
            assert!(renewal_due(not_after, ttl, at(0)), "{ttl_hours}h exact");
            assert!(renewal_due(not_after, ttl, at(1)), "{ttl_hours}h late");
            // Long past expiry is still due.
            assert!(renewal_due(not_after, ttl, at(remaining_hours * 2 * HOUR)));
        }
    }

    #[test]
    fn alert_due_boundaries() {
        const HOUR: i64 = 3600;
        for (ttl_hours, remaining_hours) in [(24, 8), (720, 240)] {
            let ttl = time::Duration::hours(ttl_hours);
            let not_after = at(remaining_hours * HOUR);
            assert!(!alert_due(not_after, ttl, at(-1)), "{ttl_hours}h early");
            assert!(!alert_due(not_after, ttl, at(0)), "{ttl_hours}h exact");
            assert!(alert_due(not_after, ttl, at(1)), "{ttl_hours}h late");
            assert!(alert_due(not_after, ttl, at(remaining_hours * 2 * HOUR)));
        }
    }

    #[test]
    fn a_failure_is_tolerated_only_while_the_certificate_works() {
        let failure = |kind, usable| RenewalFailure {
            error: crate::error::Error::Validation {
                field: "test".to_owned(),
                message: "test".to_owned(),
            },
            kind,
            usable,
        };
        assert!(failure(FailureKind::Unavailable, true).tolerated());
        assert!(failure(FailureKind::Refused, true).tolerated());
        assert!(!failure(FailureKind::Unavailable, false).tolerated());
        assert!(!failure(FailureKind::Refused, false).tolerated());
        assert!(!failure(FailureKind::AfterRenew, true).tolerated());
        assert!(failure(FailureKind::Unavailable, false).hidden());
        assert!(!failure(FailureKind::Refused, true).hidden());
        assert!(!failure(FailureKind::AfterRenew, true).hidden());
    }

    #[test]
    fn provisioner_name_round_trips_and_rejects_noncanonical_forms() {
        let name = x509_provisioner_name("edge-host", "nfs-client");
        assert_eq!(
            name,
            "grafhome-x509-656467652d686f7374-6e66732d636c69656e74"
        );
        assert_eq!(
            parse_x509_provisioner_name(&name),
            Some(("edge-host".to_owned(), "nfs-client".to_owned()))
        );
        for other in [
            "grafhome-x509-ca-proxy",
            "grafhome-x509--",
            "grafhome-x509-6e-",
            "grafhome-x509-6E-6e",
            "grafhome-host-6e",
        ] {
            assert_eq!(parse_x509_provisioner_name(other), None, "{other}");
        }
    }

    #[test]
    fn x509_provisioner_pins_sans_and_single_eku() {
        for (role, eku) in [
            (X509Role::Server, "serverAuth"),
            (X509Role::Client, "clientAuth"),
        ] {
            let provisioner = x509_provisioner(jwk(), &cert(role), KEY).unwrap();
            assert_eq!(provisioner["type"], "JWK");
            assert_eq!(
                provisioner["name"],
                x509_provisioner_name("edge-host", "nfs-client")
            );
            assert_eq!(
                template_body(&provisioner),
                json!({
                    "subject": {"commonName": "edge.example.test"},
                    "sans": [
                        {"type": "dns", "value": "edge.example.test"},
                        {"type": "dns", "value": "edge2.example.test"},
                    ],
                    "keyUsage": ["digitalSignature"],
                    "extKeyUsage": [eku],
                })
            );
        }
    }

    #[test]
    fn x509_provisioner_pins_public_key() {
        let provisioner = x509_provisioner(jwk(), &cert(X509Role::Client), KEY).unwrap();
        let template = provisioner["options"]["x509"]["template"].as_str().unwrap();
        assert!(template.contains(r#"(ne $key.Curve.Params.Name "P-256")"#));
        assert!(template.contains(
            r#"(ne ($key.X.Text 16) "a4b6b84d0d88e9f1b1ae9b135c88e438d9c5aa9efe6955c5d86501d05cd6c993")"#
        ));
        assert!(template.contains(
            r#"(ne ($key.Y.Text 16) "4904605d230b0b2528d4b05305fb6d7af829012ee70e0f6613440916aee1c771")"#
        ));
        assert!(!template.contains(".Subject"));
        assert!(!template.contains(".SANs"));
        assert!(!template.contains("Extensions"));
    }

    #[test]
    fn x509_provisioner_denies_ssh() {
        let provisioner = x509_provisioner(jwk(), &cert(X509Role::Client), KEY).unwrap();
        assert_eq!(provisioner["claims"]["enableSSHCA"], false);
        assert!(is_deny_template(
            provisioner["options"]["ssh"]["template"].as_str().unwrap()
        ));
    }

    #[test]
    fn x509_provisioner_disables_renewal() {
        let provisioner = x509_provisioner(jwk(), &cert(X509Role::Client), KEY).unwrap();
        assert_eq!(provisioner["claims"]["disableRenewal"], true);
        assert_eq!(provisioner["claims"]["defaultTLSCertDuration"], "24h");
        assert_eq!(provisioner["claims"]["maxTLSCertDuration"], "24h");
    }

    #[test]
    fn x509_provisioner_refuses_a_certificate_with_no_names() {
        let mut declared = cert(X509Role::Client);
        declared.names.clear();
        assert!(x509_provisioner(jwk(), &declared, KEY).is_err());
    }

    #[test]
    fn certificate_key_fingerprint_fits_the_tombstone_format() {
        let key = CertificateKey::parse(KEY).unwrap();
        let fingerprint = key.fingerprint();
        let encoded = fingerprint.strip_prefix("SHA256:").unwrap();
        assert_eq!(encoded.len(), 43);
        assert!(!encoded.contains(['=', '-', '_']));
    }

    #[test]
    fn certificate_key_normalizes_armor_and_line_endings() {
        let messy = format!("\r\n{}\r\n", KEY.replace('\n', "\r\n"));
        assert_eq!(CertificateKey::parse(&messy).unwrap().pem(), KEY);
    }

    #[test]
    fn certificate_key_rejects_everything_but_p256_public_keys() {
        let body = |bytes: &[u8]| {
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            )
        };
        for value in [
            String::new(),
            "not a key".to_owned(),
            // A valid body, so only the label check can refuse this one.
            KEY.replace("PUBLIC KEY", "CERTIFICATE"),
            body(&[0; 91]),
            body(&[0; 90]),
            "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----\n".to_owned(),
        ] {
            assert!(CertificateKey::parse(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn template_coordinates_match_big_int_text_for_leading_zeros() {
        // `big.Int.Text` drops leading zeros, so a pin keeping them would refuse
        // the enrolled key itself about once in every 256 enrollments.
        let mut der = base64::engine::general_purpose::STANDARD
            .decode(
                KEY.lines()
                    .filter(|line| !line.starts_with('-'))
                    .collect::<String>(),
            )
            .unwrap();
        der[27] = 0;
        der[28] = 0x0a;
        der[59..91].fill(0);
        der[90] = 1;
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        let provisioner = x509_provisioner(jwk(), &cert(X509Role::Client), &pem).unwrap();
        let template = provisioner["options"]["x509"]["template"].as_str().unwrap();
        assert!(template.contains(r#"($key.X.Text 16) "ab84d0d8"#));
        assert!(template.contains(r#"($key.Y.Text 16) "1")"#));
    }

    #[test]
    fn deny_template_recognizes_only_a_lone_fail() {
        assert!(is_deny_template(r#"{{ fail "x509 disabled" }}"#));
        assert!(is_deny_template(" {{ fail \"x509 disabled\" }}\n"));
        for template in [
            "",
            "{}",
            r#"{"subject": {{ toJson .Subject }}}"#,
            r#"{{ if .Token.admin }}{{ fail "no" }}{{ end }}"#,
            r#"{{ fail "no" }}{"sans": {{ toJson .SANs }}}"#,
        ] {
            assert!(!is_deny_template(template), "{template}");
        }
    }

    #[test]
    fn request_rejects_private_jwk_and_unknown_fields() {
        let mut request = X509Request::new(
            "edge-host",
            "nfs-client",
            vec!["edge.example.test".to_owned()],
            KEY,
            jwk(),
        );
        request.validate().unwrap();
        request.renewal_public_jwk["d"] = json!("private");
        assert!(
            request
                .validate()
                .unwrap_err()
                .to_string()
                .contains("private key material")
        );

        let mut document = serde_json::to_value(X509Request::new(
            "edge-host",
            "nfs-client",
            vec!["edge.example.test".to_owned()],
            KEY,
            jwk(),
        ))
        .unwrap();
        document["private_key"] = json!("secret");
        assert!(serde_json::from_value::<X509Request>(document).is_err());
    }

    #[test]
    fn request_requires_the_x509_kind_and_a_name() {
        let mut request = X509Request::new("edge-host", "nfs-client", Vec::new(), KEY, jwk());
        assert!(request.validate().is_err());
        request.names = vec!["edge.example.test".to_owned()];
        request.kind = "grafhome-host-enrollment-request".to_owned();
        assert!(request.validate().is_err());
    }

    #[test]
    fn approved_cert_requires_an_active_exact_declaration() {
        let root = crate::example_config_root();
        let mut policy = crate::policy::Policy::load(&root).unwrap();
        let declared = policy.x509_certs[0].clone();
        let request = |names: Vec<String>| {
            X509Request::new(&declared.host, &declared.name, names, KEY, jwk())
        };

        assert_eq!(
            approved_cert(&policy, &request(declared.names.clone())).unwrap(),
            &declared
        );
        let mut wider = declared.names.clone();
        wider.push("extra.example.test".to_owned());
        assert!(approved_cert(&policy, &request(wider)).is_err());
        policy.x509_certs[0].status = Status::Disabled;
        assert!(approved_cert(&policy, &request(declared.names.clone())).is_err());
        policy.x509_certs.clear();
        assert!(approved_cert(&policy, &request(declared.names.clone())).is_err());
    }

    #[test]
    fn reconcile_live_rebuilds_from_policy_and_keeps_the_pin() {
        let root = crate::example_config_root();
        let mut policy = crate::policy::Policy::load(&root).unwrap();
        let declared = policy.x509_certs[0].clone();
        let mut live = x509_provisioner(jwk(), &declared, KEY).unwrap();
        assert_eq!(reconcile_live(&policy, &live).unwrap(), live);

        policy.x509_certs[0].ttl = "48h".to_owned();
        live["encryptedKey"] = json!("stale");
        live["options"]["x509"]["templateFile"] = json!("stale");
        let reconciled = reconcile_live(&policy, &live).unwrap();
        assert_eq!(reconciled["claims"]["maxTLSCertDuration"], "48h");
        assert_eq!(reconciled["key"], live["key"]);
        assert!(reconciled.get("encryptedKey").is_none());
        assert!(reconciled["options"]["x509"].get("templateFile").is_none());
        assert!(
            reconciled["options"]["x509"]["template"]
                .as_str()
                .unwrap()
                .contains("a4b6b84d0d88")
        );
    }

    #[test]
    fn reconcile_live_refuses_undeclared_or_unpinned_provisioners() {
        let root = crate::example_config_root();
        let mut policy = crate::policy::Policy::load(&root).unwrap();
        let declared = policy.x509_certs[0].clone();
        let live = x509_provisioner(jwk(), &declared, KEY).unwrap();

        let mut unpinned = live.clone();
        unpinned["options"]["x509"]["template"] = json!("{}");
        assert!(
            reconcile_live(&policy, &unpinned)
                .unwrap_err()
                .to_string()
                .contains("pinned")
        );

        policy.x509_certs.clear();
        assert!(
            reconcile_live(&policy, &live)
                .unwrap_err()
                .to_string()
                .contains("x509 revoke")
        );
    }
}
