//! X.509-only provisioners, enrollment requests, and on-host key material.
//!
//! `tlshd` accepts any unexpired certificate chaining to the root, so who can
//! obtain a certificate is the entire control. Each provisioner here is bound to
//! one renewal JWK and one enrolled public key, denies SSH, and disables
//! Smallstep's `/renew` and `/rekey`, which would otherwise accept any unexpired
//! certificate without the JWK. Smallstep stays the crypto boundary: this module
//! only produces its configuration and checks a key's fixed-format encoding.

use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::enrollment::{VERSION, decode_identity, encode_identity, validate_header};
use crate::enrollment_registry::canonical_jwk;
use crate::error::{Error, Result};
use crate::policy::{Policy, X509Cert, X509Role};
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
            key: key_dir.join("key.pem"),
            pending_key: key_dir.join("key.pem.pending"),
            lock: credentials.join(format!("{name}.lock")),
        }
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

fn lock_material(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .map_err(|source| Error::io(path, source))?;
    file.lock_exclusive()
        .map_err(|source| Error::io(path, source))?;
    Ok(file)
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
    let program = command.get_program().to_owned();
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|source| Error::io(Path::new(&program), source))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    Err(Error::Validation {
        field: "step".to_owned(),
        message: format!(
            "{:?} failed: {}",
            command.get_args().take(3).collect::<Vec<_>>(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    })
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

#[cfg(test)]
mod tests {
    use base64::Engine;
    use serde_json::{Value, json};

    use super::{
        CertificateKey, X509Request, approved_cert, is_deny_template, parse_x509_provisioner_name,
        reconcile_live, x509_provisioner, x509_provisioner_name,
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
