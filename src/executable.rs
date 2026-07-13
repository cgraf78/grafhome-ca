//! Trusted external executable discovery.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::model::SiteModel;
use crate::{Error, Result};

const STEP_BIN: &str = "step";
const USER_STEP_BINS: &[&str] = &[STEP_BIN, "step-cli"];
const ANDROID_USER_STEP_BINS: &[&str] = &["step-cli", STEP_BIN];

/// Resolve the Smallstep CLI used by unprivileged client operations.
///
/// Smallstep installs `step` on its supported desktop platforms. Termux's
/// official package intentionally uses `step-cli` to avoid colliding with the
/// KDE Step package, so Android builds prefer that unambiguous name.
pub fn user_step_bin() -> Result<String> {
    let names = if cfg!(target_os = "android") {
        ANDROID_USER_STEP_BINS
    } else {
        USER_STEP_BINS
    };
    user_step_bin_in(std::env::var_os("PATH").as_deref(), names)
}

fn user_step_bin_in(path: Option<&OsStr>, names: &[&str]) -> Result<String> {
    if let Some(path) = path {
        for directory in std::env::split_paths(path) {
            for name in names {
                let candidate = directory.join(name);
                if !candidate.is_file() {
                    continue;
                }
                if let Some(path) = trusted_executable(&candidate)? {
                    return Ok(path.to_string_lossy().into_owned());
                }
            }
        }
    }
    Err(Error::Validation {
        field: "step executable".to_owned(),
        message:
            "no Smallstep CLI is available on PATH; install `step` or Termux's `step-cli` package"
                .to_owned(),
    })
}

/// Resolve the Smallstep CLI used by privileged operations.
///
/// The configured path remains authoritative when it is usable. Standard
/// system locations and `PATH` provide cross-platform fallback, but a root
/// process never executes a binary or parent path writable by another user.
pub fn root_step_bin(model: &SiteModel) -> Result<String> {
    let configured = PathBuf::from(&model.deployment.values["GRAFHOME_CA_ROOT_STEP_BIN"]);
    let mut candidates = vec![configured.clone()];
    candidates.extend([
        PathBuf::from("/usr/local/bin/step"),
        PathBuf::from("/usr/bin/step"),
    ]);
    candidates.extend(path_candidates(STEP_BIN));
    for candidate in candidates {
        if let Some(path) = trusted_executable(&candidate)? {
            return Ok(path.to_string_lossy().into_owned());
        }
    }
    Err(Error::Validation {
        field: "step executable".to_owned(),
        message: format!(
            "no trusted step executable is available; configured path {} is missing or unsafe. Install a root-owned copy at /usr/local/bin/step",
            configured.display()
        ),
    })
}

fn path_candidates(name: &str) -> Vec<PathBuf> {
    let path = std::env::var_os("PATH");
    path_candidates_in(name, path.as_deref())
}

fn path_candidates_in(name: &str, path: Option<&OsStr>) -> Vec<PathBuf> {
    let Some(path) = path else {
        return Vec::new();
    };
    std::env::split_paths(path)
        .map(|directory| directory.join(name))
        .filter(|candidate| candidate.is_file())
        .collect()
}

#[cfg(unix)]
fn trusted_executable(path: &Path) -> Result<Option<PathBuf>> {
    trusted_executable_for_uid(path, rustix::process::geteuid().as_raw())
}

#[cfg(not(unix))]
fn trusted_executable(path: &Path) -> Result<Option<PathBuf>> {
    trusted_executable_for_uid(path, 0)
}

fn trusted_executable_for_uid(path: &Path, trusted_uid: u32) -> Result<Option<PathBuf>> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let path = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(Error::io(path, source)),
    };
    let metadata = std::fs::metadata(&path).map_err(|source| Error::io(&path, source))?;
    if !metadata.is_file() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if !owner_is_trusted(metadata.uid(), trusted_uid) || mode & 0o022 != 0 || mode & 0o100 == 0
        {
            return Ok(None);
        }
        if trusted_uid == 0 {
            let mut parent = path.parent();
            while let Some(directory) = parent {
                let metadata =
                    std::fs::metadata(directory).map_err(|source| Error::io(directory, source))?;
                if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
                    return Ok(None);
                }
                parent = directory.parent();
            }
        }
    }
    Ok(Some(path))
}

fn owner_is_trusted(owner: u32, invoking_uid: u32) -> bool {
    owner == invoking_uid || (invoking_uid != 0 && owner == 0)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::{
        ANDROID_USER_STEP_BINS, USER_STEP_BINS, owner_is_trusted, trusted_executable,
        user_step_bin_in,
    };

    fn executable(path: &std::path::Path) {
        std::fs::write(path, "fake").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn resolves_termux_step_cli_fallback() {
        let temp = tempdir().unwrap();
        let step_cli = temp.path().join("step-cli");
        executable(&step_cli);

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), USER_STEP_BINS).unwrap(),
            step_cli.to_string_lossy()
        );
    }

    #[test]
    fn prefers_standard_step_name() {
        let temp = tempdir().unwrap();
        let step = temp.path().join("step");
        executable(&step);
        executable(&temp.path().join("step-cli"));

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), USER_STEP_BINS).unwrap(),
            step.to_string_lossy()
        );
    }

    #[test]
    fn android_prefers_unambiguous_step_cli_name() {
        let temp = tempdir().unwrap();
        executable(&temp.path().join("step"));
        let step_cli = temp.path().join("step-cli");
        executable(&step_cli);

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), ANDROID_USER_STEP_BINS).unwrap(),
            step_cli.to_string_lossy()
        );
    }

    #[test]
    fn respects_path_directory_order() {
        let temp = tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let step_cli = first.join("step-cli");
        executable(&step_cli);
        executable(&second.join("step"));
        let path = std::env::join_paths([&first, &second]).unwrap();

        assert_eq!(
            user_step_bin_in(Some(&path), USER_STEP_BINS).unwrap(),
            step_cli.to_string_lossy()
        );
    }

    #[test]
    fn skips_unsafe_step_and_uses_step_cli() {
        let temp = tempdir().unwrap();
        let unsafe_step = temp.path().join("step");
        executable(&unsafe_step);
        std::fs::set_permissions(&unsafe_step, std::fs::Permissions::from_mode(0o777)).unwrap();
        let step_cli = temp.path().join("step-cli");
        executable(&step_cli);

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), USER_STEP_BINS).unwrap(),
            step_cli.to_string_lossy()
        );
    }

    #[test]
    fn missing_path_reports_install_guidance() {
        let error = user_step_bin_in(None, USER_STEP_BINS)
            .unwrap_err()
            .to_string();

        assert!(error.contains("install `step` or Termux's `step-cli` package"));
    }

    #[test]
    fn rejects_group_or_world_writable_executable() {
        let temp = tempdir().unwrap();
        let executable = temp.path().join("step");
        std::fs::write(&executable, "fake").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o777)).unwrap();

        assert_eq!(trusted_executable(&executable).unwrap(), None);
    }

    #[test]
    fn rejects_file_without_owner_execute_permission() {
        let temp = tempdir().unwrap();
        let executable = temp.path().join("step");
        std::fs::write(&executable, "fake").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(trusted_executable(&executable).unwrap(), None);
    }

    #[test]
    fn ownership_allows_root_or_the_invoking_user_without_privilege_inversion() {
        assert!(owner_is_trusted(501, 501));
        assert!(owner_is_trusted(0, 501));
        assert!(!owner_is_trusted(502, 501));
        assert!(owner_is_trusted(0, 0));
        assert!(!owner_is_trusted(501, 0));
    }
}
