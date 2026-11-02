//! Deployment configuration parsing.
//!
//! This module owns the non-secret `config/deployment.env` contract. It keeps
//! derived paths out of the checked-in file so future renderers have one
//! authoritative place to compute them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};

const REQUIRED_KEYS: &[&str] = &[
    "GRAFHOME_CA_STATE_DIR",
    "GRAFHOME_CA_SERVER_STEPPATH",
    "GRAFHOME_CA_USER_STEPPATH",
    "GRAFHOME_CA_SSH_TRUST_DIR",
    "GRAFHOME_CA_AUTH_PRINCIPALS_DIR",
    "GRAFHOME_CA_STEP_CA_BIN",
    "GRAFHOME_CA_ROOT_STEP_BIN",
    "GRAFHOME_CA_HOST_KEY_PATH",
    "GRAFHOME_CA_PASSWORD_FILE",
    "GRAFHOME_CA_SERVICE_USER",
];

/// Keys a deployment may omit. Binaries that predate a key reject it as
/// unknown, so a site sets one only once every host runs a binary that knows it.
const OPTIONAL_KEYS: &[&str] = &["GRAFHOME_CA_X509_DIR"];

/// Keys that no longer configure anything. Releases before each retirement
/// require them, so they stay accepted until every host runs a newer binary;
/// a site then deletes them. They are dropped at load so no consumer can come
/// to depend on one again.
///
/// - `GRAFHOME_CA_PROXY_ACME_WEBROOT`: retired with ACME.
/// - `GRAFHOME_CA_PROXY_TLS_DIR` and `GRAFHOME_CA_APACHE_CONF_AVAILABLE`: only
///   placed and filled in a rendered Apache proxy fragment that `render` no
///   longer produces; the reverse proxy's site owns that configuration.
/// - `GRAFHOME_CA_HELPER_BIN`: named the helper for root-run rollout plans,
///   which were removed; nothing executes it.
const RETIRED_KEYS: &[&str] = &[
    "GRAFHOME_CA_PROXY_ACME_WEBROOT",
    "GRAFHOME_CA_PROXY_TLS_DIR",
    "GRAFHOME_CA_APACHE_CONF_AVAILABLE",
    "GRAFHOME_CA_HELPER_BIN",
];

/// Default root for host-held X.509 certificates and keys.
const DEFAULT_X509_DIR: &str = "/etc/grafhome-ca/x509";

/// Parsed deployment environment.
#[derive(Debug, Clone, Serialize)]
pub struct Deployment {
    /// Source path.
    #[serde(skip)]
    pub path: PathBuf,
    /// Key-value map from `config/deployment.env`.
    #[serde(flatten)]
    pub values: BTreeMap<String, String>,
}

impl Deployment {
    /// Load and validate `config/deployment.env`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
        let mut values = BTreeMap::new();

        for (idx, raw) in text.lines().enumerate() {
            let line = idx + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                return Err(Error::Parse {
                    path: path.to_path_buf(),
                    line,
                    message: "expected KEY=value".to_owned(),
                });
            };
            if key.is_empty() || value.is_empty() {
                return Err(Error::Parse {
                    path: path.to_path_buf(),
                    line,
                    message: "key and value must both be non-empty".to_owned(),
                });
            }
            if value.contains('"') || value.contains('\'') {
                return Err(Error::Parse {
                    path: path.to_path_buf(),
                    line,
                    message: "deployment.env values are literal and must not be shell-quoted"
                        .to_owned(),
                });
            }
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(Error::Parse {
                    path: path.to_path_buf(),
                    line,
                    message: format!("duplicate key {key}"),
                });
            }
        }
        // Drop retired keys only after the parse checks above, so this binary
        // still rejects a file that older binaries sharing it would reject.
        values.retain(|key, _| !RETIRED_KEYS.contains(&key.as_str()));

        let deployment = Self {
            path: path.to_path_buf(),
            values,
        };
        deployment.validate()?;
        Ok(deployment)
    }

    /// Derived CA daemon `STEPPATH`.
    #[must_use]
    pub fn ca_steppath(&self) -> String {
        format!(
            "{}/step",
            self.values["GRAFHOME_CA_STATE_DIR"].trim_end_matches('/')
        )
    }

    /// Directory holding `<name>/{cert.pem,key.pem}` for declared X.509 certificates.
    ///
    /// Reads the optional key without indexing so an absent override never panics.
    #[must_use]
    pub fn x509_dir(&self) -> PathBuf {
        self.values
            .get("GRAFHOME_CA_X509_DIR")
            .map_or_else(|| PathBuf::from(DEFAULT_X509_DIR), PathBuf::from)
    }

    fn validate(&self) -> Result<()> {
        let expected = REQUIRED_KEYS.iter().copied().collect::<BTreeSet<_>>();
        let actual = self
            .values
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();

        if let Some(key) = expected.difference(&actual).next() {
            return Err(Error::Validation {
                field: format!("{}:{key}", self.path.display()),
                message: "missing required deployment key".to_owned(),
            });
        }
        if let Some(key) = actual
            .difference(&expected)
            .find(|key| !OPTIONAL_KEYS.contains(key))
        {
            return Err(Error::Validation {
                field: format!("{}:{key}", self.path.display()),
                message: "unknown deployment key".to_owned(),
            });
        }
        if self.values.contains_key("GRAFHOME_CA_STEPPATH") {
            return Err(Error::Validation {
                field: format!("{}:GRAFHOME_CA_STEPPATH", self.path.display()),
                message: "derived values must not be stored independently".to_owned(),
            });
        }
        for (key, value) in &self.values {
            if key == "GRAFHOME_CA_USER_STEPPATH" {
                if value.starts_with('/') {
                    return Err(Error::Validation {
                        field: format!("{}:{key}", self.path.display()),
                        message: "user STEPPATH must be relative to the user home".to_owned(),
                    });
                }
            } else if (key.ends_with("_DIR")
                || key.ends_with("_BIN")
                || key.ends_with("_FILE")
                || key.ends_with("_PATH")
                || key == "GRAFHOME_CA_STATE_DIR"
                || key == "GRAFHOME_CA_SERVER_STEPPATH")
                && !value.starts_with('/')
            {
                return Err(Error::Validation {
                    field: format!("{}:{key}", self.path.display()),
                    message: "system path must be absolute".to_owned(),
                });
            }
        }
        self.validate_password_file_location()?;

        Ok(())
    }

    fn validate_password_file_location(&self) -> Result<()> {
        let state_dir = Path::new(&self.values["GRAFHOME_CA_STATE_DIR"]);
        let password_file = Path::new(&self.values["GRAFHOME_CA_PASSWORD_FILE"]);
        if state_dir.parent().is_none() {
            return Err(Error::Validation {
                field: format!("{}:GRAFHOME_CA_STATE_DIR", self.path.display()),
                message: "state directory must not be the filesystem root".to_owned(),
            });
        }
        if state_dir
            .components()
            .any(|component| component == Component::ParentDir)
            || password_file
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(Error::Validation {
                field: format!("{}:GRAFHOME_CA_PASSWORD_FILE", self.path.display()),
                message: "state and password paths must not contain parent directory components"
                    .to_owned(),
            });
        }
        if password_file == state_dir || !password_file.starts_with(state_dir) {
            return Err(Error::Validation {
                field: format!("{}:GRAFHOME_CA_PASSWORD_FILE", self.path.display()),
                message: "password file must be inside GRAFHOME_CA_STATE_DIR".to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{Deployment, REQUIRED_KEYS, RETIRED_KEYS};

    #[test]
    fn rejects_derived_steppath_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deployment.env");
        let mut text = String::new();
        for key in REQUIRED_KEYS {
            let value = if *key == "GRAFHOME_CA_USER_STEPPATH" {
                ".config/grafhome/step"
            } else if key.ends_with("_USER") || key.ends_with("_GROUP") {
                "grafhome-ca"
            } else {
                "/tmp/grafhome-ca"
            };
            text.push_str(&format!("{key}={value}\n"));
        }
        text.push_str("GRAFHOME_CA_STEPPATH=/tmp/grafhome-ca/step\n");
        fs::write(&path, text).unwrap();

        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("GRAFHOME_CA_STEPPATH"));
    }

    #[test]
    fn rejects_shell_quoted_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deployment.env");
        let mut text = String::new();
        for key in REQUIRED_KEYS {
            let value = if *key == "GRAFHOME_CA_USER_STEPPATH" {
                ".config/grafhome/step"
            } else if *key == "GRAFHOME_CA_SERVICE_USER" {
                "\"step-ca\""
            } else {
                "/tmp/grafhome-ca"
            };
            text.push_str(&format!("{key}={value}\n"));
        }
        fs::write(&path, text).unwrap();

        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("must not be shell-quoted"));
    }

    #[test]
    fn rejects_password_file_outside_state_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deployment.env");
        let mut text = String::new();
        for key in REQUIRED_KEYS {
            let value = if *key == "GRAFHOME_CA_STATE_DIR" {
                "/srv/example-ca"
            } else if *key == "GRAFHOME_CA_PASSWORD_FILE" {
                "/srv/secrets/intermediate_ca_password"
            } else if *key == "GRAFHOME_CA_USER_STEPPATH" {
                ".config/grafhome/step"
            } else if *key == "GRAFHOME_CA_SERVICE_USER" {
                "step-ca"
            } else {
                "/tmp/grafhome-ca"
            };
            text.push_str(&format!("{key}={value}\n"));
        }
        fs::write(&path, text).unwrap();

        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("password file must be inside GRAFHOME_CA_STATE_DIR"));
    }

    #[test]
    fn rejects_parent_components_in_password_location() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deployment.env");
        let mut text = String::new();
        for key in REQUIRED_KEYS {
            let value = if *key == "GRAFHOME_CA_STATE_DIR" {
                "/srv/example-ca"
            } else if *key == "GRAFHOME_CA_PASSWORD_FILE" {
                "/srv/example-ca/../secrets/intermediate_ca_password"
            } else if *key == "GRAFHOME_CA_USER_STEPPATH" {
                ".config/grafhome/step"
            } else if *key == "GRAFHOME_CA_SERVICE_USER" {
                "step-ca"
            } else {
                "/tmp/grafhome-ca"
            };
            text.push_str(&format!("{key}={value}\n"));
        }
        fs::write(&path, text).unwrap();

        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("must not contain parent directory components"));
    }

    #[test]
    fn rejects_root_state_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deployment.env");
        let mut text = String::new();
        for key in REQUIRED_KEYS {
            let value = if *key == "GRAFHOME_CA_STATE_DIR" {
                "/"
            } else if *key == "GRAFHOME_CA_PASSWORD_FILE" {
                "/srv/example-ca/secrets/intermediate_ca_password"
            } else if *key == "GRAFHOME_CA_USER_STEPPATH" {
                ".config/grafhome/step"
            } else if *key == "GRAFHOME_CA_SERVICE_USER" {
                "step-ca"
            } else {
                "/tmp/grafhome-ca"
            };
            text.push_str(&format!("{key}={value}\n"));
        }
        fs::write(&path, text).unwrap();

        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("state directory must not be the filesystem root"));
    }

    fn minimal_env(extra: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deployment.env");
        let mut text = String::new();
        for key in REQUIRED_KEYS {
            let value = if *key == "GRAFHOME_CA_STATE_DIR" {
                "/srv/example-ca"
            } else if *key == "GRAFHOME_CA_PASSWORD_FILE" {
                "/srv/example-ca/secrets/intermediate_ca_password"
            } else if *key == "GRAFHOME_CA_USER_STEPPATH" {
                ".config/grafhome/step"
            } else if *key == "GRAFHOME_CA_SERVICE_USER" {
                "step-ca"
            } else {
                "/tmp/grafhome-ca"
            };
            text.push_str(&format!("{key}={value}\n"));
        }
        text.push_str(extra);
        fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn deployment_accepts_optional_x509_dir() {
        let (_dir, path) = minimal_env("GRAFHOME_CA_X509_DIR=/srv/example-x509\n");
        let deployment = Deployment::load(&path).unwrap();
        assert_eq!(
            deployment.x509_dir(),
            std::path::PathBuf::from("/srv/example-x509")
        );
    }

    #[test]
    fn deployment_rejects_relative_x509_dir() {
        let (_dir, path) = minimal_env("GRAFHOME_CA_X509_DIR=relative/x509\n");
        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("system path must be absolute"));
    }

    /// Lines an older site file carries for each retired key.
    const RETIRED_LINES: &str = "GRAFHOME_CA_PROXY_ACME_WEBROOT=/var/www/html\n\
        GRAFHOME_CA_PROXY_TLS_DIR=/etc/ssl/example-ca\n\
        GRAFHOME_CA_APACHE_CONF_AVAILABLE=/etc/apache2/conf-available\n\
        GRAFHOME_CA_HELPER_BIN=/root/.local/bin/grafhome-ca\n";

    #[test]
    fn deployment_accepts_and_drops_retired_keys() {
        let (_dir, path) = minimal_env(RETIRED_LINES);
        let deployment = Deployment::load(&path).unwrap();
        for key in RETIRED_KEYS {
            assert!(!deployment.values.contains_key(*key), "{key} kept");
        }
    }

    #[test]
    fn deployment_ignores_retired_key_values() {
        // A retired key configures nothing, so even a value the live keys
        // would reject must not block loading an older site file.
        let (_dir, path) = minimal_env("GRAFHOME_CA_HELPER_BIN=relative/grafhome-ca\n");
        Deployment::load(&path).unwrap();
    }

    #[test]
    fn deployment_rejects_duplicate_retired_key() {
        // Older binaries reject the duplicate, so a shared file must fail here
        // too rather than load on one host and break another.
        let (_dir, path) = minimal_env(
            "GRAFHOME_CA_HELPER_BIN=/root/.local/bin/grafhome-ca\n\
             GRAFHOME_CA_HELPER_BIN=/root/.local/bin/grafhome-ca\n",
        );
        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("duplicate key GRAFHOME_CA_HELPER_BIN"));
    }

    #[test]
    fn deployment_rejects_unknown_key() {
        let (_dir, path) = minimal_env("GRAFHOME_CA_NOT_A_KEY=/srv/example\n");
        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("unknown deployment key"));
    }

    #[test]
    fn deployment_rejects_missing_required_key() {
        let (_dir, path) = minimal_env("");
        let text = fs::read_to_string(&path).unwrap();
        let without = text
            .lines()
            .filter(|line| !line.starts_with("GRAFHOME_CA_STEP_CA_BIN="))
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        fs::write(&path, without).unwrap();
        let error = Deployment::load(&path).unwrap_err().to_string();
        assert!(error.contains("missing required deployment key"));
    }

    #[test]
    fn deployment_defaults_x509_dir() {
        let (_dir, path) = minimal_env("");
        let deployment = Deployment::load(&path).unwrap();
        assert_eq!(
            deployment.x509_dir(),
            std::path::PathBuf::from("/etc/grafhome-ca/x509")
        );
    }
}
