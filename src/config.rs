//! Deployment configuration parsing.
//!
//! This module owns the non-secret `config/deployment.env` contract. It keeps
//! derived paths out of the checked-in file so future renderers have one
//! authoritative place to compute them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};

const REQUIRED_KEYS: &[&str] = &[
    "GRAFHOME_CA_STATE_DIR",
    "GRAFHOME_CA_SERVER_STEPPATH",
    "GRAFHOME_CA_USER_STEPPATH",
    "GRAFHOME_CA_SSH_TRUST_DIR",
    "GRAFHOME_CA_AUTH_PRINCIPALS_DIR",
    "GRAFHOME_CA_PROXY_TLS_DIR",
    "GRAFHOME_CA_PROXY_ACME_WEBROOT",
    "GRAFHOME_CA_STEP_CA_BIN",
    "GRAFHOME_CA_ROOT_STEP_BIN",
    "GRAFHOME_CA_HELPER_BIN",
    "GRAFHOME_CA_HOST_KEY_PATH",
    "GRAFHOME_CA_PASSWORD_FILE",
    "GRAFHOME_CA_SERVICE_USER",
    "GRAFHOME_CA_APACHE_CONF_AVAILABLE",
];

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
        if let Some(key) = actual.difference(&expected).next() {
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
                || key.ends_with("_AVAILABLE")
                || key == "GRAFHOME_CA_STATE_DIR"
                || key == "GRAFHOME_CA_SERVER_STEPPATH"
                || key == "GRAFHOME_CA_PROXY_ACME_WEBROOT")
                && !value.starts_with('/')
            {
                return Err(Error::Validation {
                    field: format!("{}:{key}", self.path.display()),
                    message: "system path must be absolute".to_owned(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{Deployment, REQUIRED_KEYS};

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
}
