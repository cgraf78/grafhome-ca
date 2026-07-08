//! Site configuration model loading.
//!
//! Runtime CA policy is private site configuration, not source-repository data.
//! The default location follows the XDG config convention:
//! `${XDG_CONFIG_HOME:-$HOME/.config}/grafhome-ca`.

use std::path::{Path, PathBuf};

use crate::config::Deployment;
use crate::error::{Error, Result};
use crate::policy::Policy;

/// Fully loaded site configuration model.
#[derive(Debug, Clone)]
pub struct SiteModel {
    /// Root directory containing `config/` and `policy/`.
    pub config_root: PathBuf,
    /// Deployment constants.
    pub deployment: Deployment,
    /// Policy files.
    pub policy: Policy,
}

impl SiteModel {
    /// Return the default XDG config root.
    pub fn default_config_root() -> Result<PathBuf> {
        if let Some(xdg_config_home) = std::env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(xdg_config_home).join("grafhome-ca"));
        }
        let Some(home) = std::env::var_os("HOME") else {
            return Err(Error::Validation {
                field: "config-root".to_owned(),
                message: "HOME is not set and XDG_CONFIG_HOME was not provided".to_owned(),
            });
        };
        Ok(PathBuf::from(home).join(".config/grafhome-ca"))
    }

    /// Load config and policy from a site config root.
    pub fn load(config_root: impl AsRef<Path>) -> Result<Self> {
        let config_root = config_root.as_ref();
        let deployment = Deployment::load(config_root.join("config/deployment.env"))?;
        let policy = Policy::load(config_root)?;
        Ok(Self {
            config_root: config_root.to_path_buf(),
            deployment,
            policy,
        })
    }
}
