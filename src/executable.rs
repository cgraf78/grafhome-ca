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

/// Resolve the Smallstep CLI used by system or host-owner operations.
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
    let guidance = if std::env::var("TERMUX_VERSION").is_ok() && cfg!(target_os = "android") {
        "Install Termux's `step-cli` package"
    } else {
        "Install a root-owned copy at /usr/local/bin/step"
    };
    Err(Error::Validation {
        field: "step executable".to_owned(),
        message: format!(
            "no trusted step executable is available; configured path {} is missing or unsafe. {guidance}",
            configured.display(),
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
    let boundary = android_executable_boundary();
    trusted_executable_for_uid_beneath(
        path,
        rustix::process::geteuid().as_raw(),
        boundary.as_deref(),
    )
}

#[cfg(not(unix))]
fn trusted_executable(path: &Path) -> Result<Option<PathBuf>> {
    trusted_executable_for_uid_beneath(path, 0, None)
}

fn trusted_executable_for_uid_beneath(
    path: &Path,
    trusted_uid: u32,
    boundary: Option<&Path>,
) -> Result<Option<PathBuf>> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    #[cfg(not(unix))]
    let _ = trusted_uid;

    let path = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(Error::io(path, source)),
    };
    let boundary = match boundary {
        Some(boundary) => {
            let boundary = match std::fs::canonicalize(boundary) {
                Ok(boundary) => boundary,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(source) => return Err(Error::io(boundary, source)),
            };
            let metadata =
                std::fs::metadata(&boundary).map_err(|source| Error::io(&boundary, source))?;
            if !metadata.is_dir() || path == boundary || !path.starts_with(&boundary) {
                return Ok(None);
            }
            Some(boundary)
        }
        None => None,
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

        for directory in path.ancestors().skip(1).take_while(|directory| {
            boundary
                .as_ref()
                .is_none_or(|root| directory.starts_with(root))
        }) {
            let metadata =
                std::fs::metadata(directory).map_err(|source| Error::io(directory, source))?;
            let mode = metadata.permissions().mode();
            if !directory_is_trusted(metadata.uid(), mode, trusted_uid) {
                return Ok(None);
            }
        }
    }
    Ok(Some(path))
}

#[cfg(target_os = "android")]
fn android_executable_boundary() -> Option<PathBuf> {
    // PREFIX and its descendants are checked below; Android's app sandbox is
    // the trust boundary for the system-owned ancestors outside PREFIX.
    let prefix = PathBuf::from(std::env::var_os("PREFIX").filter(|value| !value.is_empty())?);
    prefix.is_absolute().then_some(prefix)
}

#[cfg(all(unix, not(target_os = "android")))]
fn android_executable_boundary() -> Option<PathBuf> {
    None
}

#[cfg(unix)]
fn directory_is_trusted(owner: u32, mode: u32, invoking_uid: u32) -> bool {
    owner_is_trusted(owner, invoking_uid) && (mode & 0o022 == 0 || owner == 0 && mode & 0o1000 != 0)
}

#[cfg(unix)]
fn owner_is_trusted(owner: u32, invoking_uid: u32) -> bool {
    owner == invoking_uid || (invoking_uid != 0 && owner == 0)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::{TempDir, tempdir};

    use super::{
        ANDROID_USER_STEP_BINS, USER_STEP_BINS, directory_is_trusted, owner_is_trusted,
        trusted_executable, trusted_executable_for_uid_beneath, user_step_bin_in,
    };

    fn executable(path: &std::path::Path) {
        std::fs::write(path, "fake").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn trusted_tempdir() -> TempDir {
        if rustix::process::geteuid().is_root() {
            tempfile::Builder::new()
                .prefix(".grafhome-ca-executable-test-")
                .tempdir_in("/root")
                .unwrap()
        } else {
            tempdir().unwrap()
        }
    }

    fn canonical(path: &std::path::Path) -> String {
        std::fs::canonicalize(path)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn resolves_termux_step_cli_fallback() {
        let temp = trusted_tempdir();
        let step_cli = temp.path().join("step-cli");
        executable(&step_cli);

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), USER_STEP_BINS).unwrap(),
            canonical(&step_cli)
        );
    }

    #[test]
    fn prefers_standard_step_name() {
        let temp = trusted_tempdir();
        let step = temp.path().join("step");
        executable(&step);
        executable(&temp.path().join("step-cli"));

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), USER_STEP_BINS).unwrap(),
            canonical(&step)
        );
    }

    #[test]
    fn android_prefers_unambiguous_step_cli_name() {
        let temp = trusted_tempdir();
        executable(&temp.path().join("step"));
        let step_cli = temp.path().join("step-cli");
        executable(&step_cli);

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), ANDROID_USER_STEP_BINS).unwrap(),
            canonical(&step_cli)
        );
    }

    #[test]
    fn respects_path_directory_order() {
        let temp = trusted_tempdir();
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
            canonical(&step_cli)
        );
    }

    #[test]
    fn skips_unsafe_step_and_uses_step_cli() {
        let temp = trusted_tempdir();
        let unsafe_step = temp.path().join("step");
        executable(&unsafe_step);
        std::fs::set_permissions(&unsafe_step, std::fs::Permissions::from_mode(0o777)).unwrap();
        let step_cli = temp.path().join("step-cli");
        executable(&step_cli);

        assert_eq!(
            user_step_bin_in(Some(temp.path().as_os_str()), USER_STEP_BINS).unwrap(),
            canonical(&step_cli)
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
    fn rejects_group_or_world_writable_ancestor() {
        for mode in [0o770, 0o707] {
            let temp = trusted_tempdir();
            let bin = temp.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(mode)).unwrap();
            let executable_path = bin.join("step");
            executable(&executable_path);

            assert_eq!(trusted_executable(&executable_path).unwrap(), None);
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn accepts_root_owned_sticky_ancestor() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let executable_path = temp.path().join("step");
        executable(&executable_path);

        assert_eq!(
            trusted_executable(&executable_path).unwrap(),
            Some(std::fs::canonicalize(executable_path).unwrap())
        );
    }

    #[test]
    fn sticky_exception_requires_root_ownership() {
        assert!(directory_is_trusted(0, 0o1777, 501));
        assert!(!directory_is_trusted(501, 0o1777, 501));
    }

    #[test]
    fn explicit_sandbox_boundary_ignores_system_ancestors() {
        let temp = trusted_tempdir();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let sandbox = temp.path().join("sandbox");
        let bin = sandbox.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let executable_path = bin.join("step-cli");
        executable(&executable_path);
        let uid = rustix::process::geteuid().as_raw();

        assert_eq!(trusted_executable(&executable_path).unwrap(), None);
        assert_eq!(
            trusted_executable_for_uid_beneath(&executable_path, uid, Some(&sandbox)).unwrap(),
            Some(std::fs::canonicalize(executable_path).unwrap())
        );
    }

    #[test]
    fn explicit_sandbox_boundary_rejects_paths_outside_or_equal_to_it() {
        let temp = trusted_tempdir();
        let sandbox = temp.path().join("sandbox");
        std::fs::create_dir(&sandbox).unwrap();
        let executable_path = temp.path().join("step-cli");
        executable(&executable_path);

        assert_eq!(
            trusted_executable_for_uid_beneath(
                &executable_path,
                rustix::process::geteuid().as_raw(),
                Some(&sandbox),
            )
            .unwrap(),
            None
        );

        let alias = temp.path().join("file-boundary-alias");
        std::os::unix::fs::symlink(&executable_path, &alias).unwrap();
        for boundary in [&executable_path, &alias] {
            assert_eq!(
                trusted_executable_for_uid_beneath(
                    &executable_path,
                    rustix::process::geteuid().as_raw(),
                    Some(boundary),
                )
                .unwrap(),
                None
            );
        }
    }

    #[test]
    fn resolves_symlinks_before_validating_ancestors() {
        let temp = trusted_tempdir();
        let real_bin = temp.path().join("real/bin");
        std::fs::create_dir_all(&real_bin).unwrap();
        let executable_path = real_bin.join("step");
        executable(&executable_path);
        let alias = temp.path().join("step-alias");
        std::os::unix::fs::symlink(&executable_path, &alias).unwrap();

        assert_eq!(
            trusted_executable(&alias).unwrap(),
            Some(std::fs::canonicalize(executable_path).unwrap())
        );

        std::fs::set_permissions(&real_bin, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(trusted_executable(&alias).unwrap(), None);
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
