//! Public CA material export.
//!
//! These helpers are intentionally read-only with respect to CA state. They
//! collect public trust anchors produced by `step ca init` so rollout does not
//! rely on ad hoc copying from live state directories.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::executable::root_step_bin;
use crate::model::SiteModel;
use crate::policy::Host;
use crate::render::RenderedFile;

const ROOT_CERT: &str = "root_ca.crt";
const ROOT_FINGERPRINT: &str = "root_fingerprint";
const SSH_HOST_CA_KEY: &str = "ssh_host_ca_key.pub";
const SSH_USER_CA_KEY: &str = "ssh_user_ca_key.pub";
const USER_CA_KEYS: &str = "user_ca_keys.pem";
const SSH_KNOWN_HOSTS: &str = "ssh_known_hosts";
const MANIFEST: &str = "manifest.json";

/// Manifest describing an exported public-material bundle.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct PublicMaterialManifest {
    /// Client-facing CA URL used for bootstrap commands.
    pub ca_url: String,
    /// SHA-256 fingerprint of the root X.509 CA certificate.
    pub root_fingerprint: String,
    /// Files written in the export bundle.
    pub files: PublicMaterialFiles,
    /// Host certificate principals covered by the OpenSSH known-hosts CA line.
    pub host_principals: Vec<String>,
}

/// Stable relative file names in a public-material export bundle.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct PublicMaterialFiles {
    /// PEM-encoded root X.509 certificate.
    pub root_cert: String,
    /// Text file containing only the root fingerprint.
    pub root_fingerprint: String,
    /// OpenSSH public key for signing host certificates.
    pub ssh_host_ca_key: String,
    /// OpenSSH public key for signing user certificates.
    pub ssh_user_ca_key: String,
    /// Copy of the user CA public key suitable for `TrustedUserCAKeys`.
    pub user_ca_keys: String,
    /// OpenSSH known-hosts CA trust file for client hosts.
    pub ssh_known_hosts: String,
}

/// Collect public CA material from the configured CA state tree.
pub fn collect(model: &SiteModel) -> Result<Vec<RenderedFile>> {
    let ca_url = model
        .policy
        .endpoint("ca_api")
        .ok_or_else(|| Error::Validation {
            field: "policy/endpoints.toml:ca_api".to_owned(),
            message: "missing required endpoint".to_owned(),
        })?
        .url();
    let root_cert_path = ca_cert_path(model, ROOT_CERT);
    let host_ca_key = read_public_key(&ca_cert_path(model, SSH_HOST_CA_KEY))?;
    let user_ca_key = read_public_key(&ca_cert_path(model, SSH_USER_CA_KEY))?;
    let root_cert = read_public_text(&root_cert_path)?;
    let root_fingerprint = root_fingerprint(model, &root_cert_path)?;
    let host_principals = host_principals(&model.policy.hosts);
    let known_hosts = known_hosts_line(&host_principals, &host_ca_key)?;
    let manifest = PublicMaterialManifest {
        ca_url,
        root_fingerprint: root_fingerprint.clone(),
        files: PublicMaterialFiles {
            root_cert: ROOT_CERT.to_owned(),
            root_fingerprint: ROOT_FINGERPRINT.to_owned(),
            ssh_host_ca_key: SSH_HOST_CA_KEY.to_owned(),
            ssh_user_ca_key: SSH_USER_CA_KEY.to_owned(),
            user_ca_keys: USER_CA_KEYS.to_owned(),
            ssh_known_hosts: SSH_KNOWN_HOSTS.to_owned(),
        },
        host_principals,
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|source| Error::Json {
        path: PathBuf::from(MANIFEST),
        source,
    })?;

    Ok(vec![
        file(ROOT_CERT, root_cert),
        file(ROOT_FINGERPRINT, format!("{root_fingerprint}\n")),
        file(SSH_HOST_CA_KEY, host_ca_key.clone()),
        file(SSH_USER_CA_KEY, user_ca_key.clone()),
        file(USER_CA_KEYS, user_ca_key),
        file(SSH_KNOWN_HOSTS, known_hosts),
        file(MANIFEST, format!("{manifest_json}\n")),
    ])
}

/// Return the stable output paths for a public-material export.
#[must_use]
pub fn planned_files() -> Vec<RenderedFile> {
    vec![
        file(ROOT_CERT, String::new()),
        file(ROOT_FINGERPRINT, String::new()),
        file(SSH_HOST_CA_KEY, String::new()),
        file(SSH_USER_CA_KEY, String::new()),
        file(USER_CA_KEYS, String::new()),
        file(SSH_KNOWN_HOSTS, String::new()),
        file(MANIFEST, String::new()),
    ]
}

/// Write collected public CA material to an export directory.
pub fn write(files: &[RenderedFile], out_dir: impl AsRef<Path>) -> Result<()> {
    crate::render::write(files, out_dir)
}

fn ca_cert_path(model: &SiteModel, file_name: &str) -> PathBuf {
    Path::new(&model.deployment.ca_steppath())
        .join("certs")
        .join(file_name)
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|source| Error::io(path, source))
}

fn read_public_key(path: &Path) -> Result<String> {
    let mut text = read_public_text(path)?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

fn read_public_text(path: &Path) -> Result<String> {
    let text = read_text(path)?;
    if text.contains("PRIVATE KEY") || text.contains("OPENSSH PRIVATE KEY") {
        return Err(Error::Validation {
            field: path.display().to_string(),
            message: "refusing to export private key material".to_owned(),
        });
    }
    Ok(text)
}

fn root_fingerprint(model: &SiteModel, root_cert_path: &Path) -> Result<String> {
    let step_bin = root_step_bin(model)?;
    let output = Command::new(&step_bin)
        .arg("certificate")
        .arg("fingerprint")
        .arg(root_cert_path)
        .output()
        .map_err(|source| Error::io(&step_bin, source))?;
    if !output.status.success() {
        return Err(Error::Validation {
            field: "step certificate fingerprint".to_owned(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    let fingerprint = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if fingerprint.is_empty() {
        return Err(Error::Validation {
            field: "step certificate fingerprint".to_owned(),
            message: "step returned an empty root fingerprint".to_owned(),
        });
    }
    Ok(fingerprint)
}

fn host_principals(hosts: &[Host]) -> Vec<String> {
    let mut principals = hosts
        .iter()
        .filter(|host| host.ssh_server)
        .flat_map(|host| host.principals.iter().map(String::as_str))
        .map(str::trim)
        .filter(|principal| !principal.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    principals.sort();
    principals.dedup();
    principals
}

fn known_hosts_line(principals: &[String], host_ca_key: &str) -> Result<String> {
    if principals.is_empty() {
        return Err(Error::Validation {
            field: "policy/hosts.toml:principals".to_owned(),
            message: "at least one SSH server host principal is required".to_owned(),
        });
    }
    Ok(format!(
        "@cert-authority {} {}\n",
        principals.join(","),
        host_ca_key.trim()
    ))
}

fn file(path: &str, content: String) -> RenderedFile {
    RenderedFile {
        path: PathBuf::from(path),
        mode: 0o644,
        content,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::collect;

    #[cfg(unix)]
    #[test]
    fn exports_only_public_trust_material() {
        use std::os::unix::fs::PermissionsExt;

        let mut model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let temp = tempdir().unwrap();
        let ca_state = temp.path().join("state");
        let step_bin = temp.path().join("fake-step");
        fs::create_dir_all(ca_state.join("step/certs")).unwrap();
        fs::write(
            ca_state.join("step/certs/root_ca.crt"),
            "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            ca_state.join("step/certs/ssh_host_ca_key.pub"),
            "ssh-ed25519 AAAAhost grafhome-host-ca\n",
        )
        .unwrap();
        fs::write(
            ca_state.join("step/certs/ssh_user_ca_key.pub"),
            "ssh-ed25519 AAAAuser grafhome-user-ca\n",
        )
        .unwrap();
        fs::write(
            &step_bin,
            "#!/bin/sh\nprintf '%s\\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        fs::set_permissions(&step_bin, fs::Permissions::from_mode(0o755)).unwrap();
        model.deployment.values.insert(
            "GRAFHOME_CA_STATE_DIR".to_owned(),
            ca_state.display().to_string(),
        );
        model.deployment.values.insert(
            "GRAFHOME_CA_ROOT_STEP_BIN".to_owned(),
            step_bin.display().to_string(),
        );

        let files = collect(&model).unwrap();
        let combined = files
            .iter()
            .map(|file| file.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let paths = files
            .iter()
            .map(|file| file.path.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                "root_ca.crt",
                "root_fingerprint",
                "ssh_host_ca_key.pub",
                "ssh_user_ca_key.pub",
                "user_ca_keys.pem",
                "ssh_known_hosts",
                "manifest.json"
            ]
        );
        assert!(combined.contains("@cert-authority"));
        assert!(combined.contains("ca-origin.example.test"));
        assert!(combined.contains("ssh-ed25519 AAAAhost"));
        assert!(combined.contains("ssh-ed25519 AAAAuser"));
        assert!(!combined.contains("PRIVATE KEY"));
        assert!(!combined.contains("OPENSSH PRIVATE KEY"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_private_material_in_public_key_inputs() {
        use std::os::unix::fs::PermissionsExt;

        let mut model = crate::model::SiteModel::load(crate::example_config_root()).unwrap();
        let temp = tempdir().unwrap();
        let ca_state = temp.path().join("state");
        let step_bin = temp.path().join("fake-step");
        fs::create_dir_all(ca_state.join("step/certs")).unwrap();
        fs::write(
            ca_state.join("step/certs/root_ca.crt"),
            "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            ca_state.join("step/certs/ssh_host_ca_key.pub"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(
            ca_state.join("step/certs/ssh_user_ca_key.pub"),
            "ssh-ed25519 AAAAuser grafhome-user-ca\n",
        )
        .unwrap();
        fs::write(
            &step_bin,
            "#!/bin/sh\nprintf '%s\\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        fs::set_permissions(&step_bin, fs::Permissions::from_mode(0o755)).unwrap();
        model.deployment.values.insert(
            "GRAFHOME_CA_STATE_DIR".to_owned(),
            ca_state.display().to_string(),
        );
        model.deployment.values.insert(
            "GRAFHOME_CA_ROOT_STEP_BIN".to_owned(),
            step_bin.display().to_string(),
        );

        let error = collect(&model).unwrap_err().to_string();

        assert!(error.contains("refusing to export private key material"));
    }
}
