//! Filesystem provenance checks for privileged policy consumers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Validate that privileged config inputs cannot be changed by another local user.
///
/// Every lexical path component, symlink, resolved target component, and input
/// file must be owned by root or `trusted_uid`. Group/world-writable objects are
/// rejected, except for root-owned sticky directories such as `/tmp` where Unix
/// rename rules still protect entries owned by the trusted account.
#[cfg(unix)]
pub fn validate_config_root(config_root: impl AsRef<Path>, trusted_uid: u32) -> Result<()> {
    validate_config_root_with_boundary(config_root.as_ref(), trusted_uid, None)
}

/// Validate config provenance beneath an already trusted filesystem boundary.
///
/// This is intended for application sandboxes whose system-owned ancestors do
/// not use ordinary root ownership. Lexical paths and resolved symlink targets
/// must remain beneath `boundary`. The returned canonical path must be used for
/// subsequent reads so a validated config-root alias cannot be swapped.
#[cfg(unix)]
pub fn validate_config_root_beneath(
    config_root: impl AsRef<Path>,
    trusted_uid: u32,
    boundary: impl AsRef<Path>,
) -> Result<PathBuf> {
    let config_root = absolute(config_root.as_ref())?;
    let lexical_boundary = absolute(boundary.as_ref())?;
    if config_root
        .components()
        .any(|part| part == std::path::Component::ParentDir)
        || lexical_boundary
            .components()
            .any(|part| part == std::path::Component::ParentDir)
        || !config_root.starts_with(&lexical_boundary)
    {
        return Err(provenance_error(
            &config_root,
            &format!("path must remain beneath {}", lexical_boundary.display()),
        ));
    }

    let boundary = std::fs::canonicalize(&lexical_boundary)
        .map_err(|source| Error::io(&lexical_boundary, source))?;
    let resolved_config_root =
        std::fs::canonicalize(&config_root).map_err(|source| Error::io(&config_root, source))?;
    if !resolved_config_root.starts_with(&boundary) {
        return Err(provenance_error(
            &resolved_config_root,
            &format!("path must remain beneath {}", boundary.display()),
        ));
    }

    let mut checked = BTreeSet::new();
    check_chain(
        &config_root,
        trusted_uid,
        Some(&lexical_boundary),
        &mut checked,
    )?;
    validate_config_root_with_boundary(&resolved_config_root, trusted_uid, Some(&boundary))?;
    Ok(resolved_config_root)
}

#[cfg(unix)]
fn validate_config_root_with_boundary(
    config_root: &Path,
    trusted_uid: u32,
    boundary: Option<&Path>,
) -> Result<()> {
    let config_root = absolute(config_root)?;
    let mut checked = BTreeSet::new();
    check_chain(&config_root, trusted_uid, boundary, &mut checked)?;

    // Canonical policy discovers per-host files dynamically. Protect both the
    // lexical and resolved directory before trusting its directory entries.
    if config_root.join(crate::policy::CA_POLICY_PATH).exists() {
        let hosts = config_root.join(crate::policy::HOST_POLICY_DIR);
        check_chain(&hosts, trusted_uid, boundary, &mut checked)?;
        let resolved = std::fs::canonicalize(&hosts).map_err(|source| Error::io(&hosts, source))?;
        check_chain(&resolved, trusted_uid, boundary, &mut checked)?;
        if !std::fs::metadata(&resolved)
            .map_err(|source| Error::io(&resolved, source))?
            .is_dir()
        {
            return Err(provenance_error(
                &resolved,
                "host policy input is not a directory",
            ));
        }
    }

    for relative in crate::schema::config_input_paths(&config_root)? {
        let input = config_root.join(relative);
        check_chain(&input, trusted_uid, boundary, &mut checked)?;
        let resolved = std::fs::canonicalize(&input).map_err(|source| Error::io(&input, source))?;
        check_chain(&resolved, trusted_uid, boundary, &mut checked)?;
        let metadata =
            std::fs::metadata(&resolved).map_err(|source| Error::io(&resolved, source))?;
        if !metadata.is_file() {
            return Err(provenance_error(&resolved, "input is not a regular file"));
        }
    }
    Ok(())
}

/// Report that privileged filesystem provenance is unsupported on this platform.
#[cfg(not(unix))]
pub fn validate_config_root(_config_root: impl AsRef<Path>, _trusted_uid: u32) -> Result<()> {
    Err(Error::Validation {
        field: "config provenance".to_owned(),
        message: "privileged policy commands require Unix ownership semantics".to_owned(),
    })
}

/// Report that bounded filesystem provenance is unsupported on this platform.
#[cfg(not(unix))]
pub fn validate_config_root_beneath(
    _config_root: impl AsRef<Path>,
    _trusted_uid: u32,
    _boundary: impl AsRef<Path>,
) -> Result<PathBuf> {
    Err(Error::Validation {
        field: "config provenance".to_owned(),
        message: "privileged policy commands require Unix ownership semantics".to_owned(),
    })
}

#[cfg(unix)]
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .map_err(|source| Error::io(path, source))
}

#[cfg(unix)]
fn check_chain(
    path: &Path,
    trusted_uid: u32,
    boundary: Option<&Path>,
    checked: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if let Some(boundary) = boundary {
        if path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
            || !path.starts_with(boundary)
        {
            return Err(provenance_error(
                path,
                &format!("path must remain beneath {}", boundary.display()),
            ));
        }
    }
    let components = path
        .ancestors()
        .take_while(|component| boundary.is_none_or(|root| component.starts_with(root)))
        .collect::<Vec<_>>();
    for component in components.into_iter().rev() {
        if component.as_os_str().is_empty() || !checked.insert(component.to_path_buf()) {
            continue;
        }
        let metadata =
            std::fs::symlink_metadata(component).map_err(|source| Error::io(component, source))?;
        let owner = metadata.uid();
        if owner != 0 && owner != trusted_uid {
            return Err(provenance_error(
                component,
                &format!("owner uid {owner} is neither root nor trusted uid {trusted_uid}"),
            ));
        }

        // Symlink mode bits are not access-control bits on Unix. Ownership of
        // the link and the full canonical target chain are checked separately.
        if metadata.file_type().is_symlink() {
            continue;
        }
        let mode = metadata.mode() & 0o7777;
        let sticky_root_directory = metadata.is_dir() && owner == 0 && mode & 0o1000 != 0;
        if mode & 0o022 != 0 && !sticky_root_directory {
            return Err(provenance_error(
                component,
                &format!("mode {mode:04o} permits group or world writes"),
            ));
        }
    }
    Ok(())
}

fn provenance_error(path: &Path, message: &str) -> Error {
    Error::Validation {
        field: format!("config provenance: {}", path.display()),
        message: message.to_owned(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use tempfile::tempdir;

    use super::{validate_config_root, validate_config_root_beneath};

    fn fixture() -> tempfile::TempDir {
        let dir = tempdir().expect("temporary config root");
        let root = dir.path().join("grafhome-ca");
        copy_dir(&crate::example_config_root(), &root);
        dir
    }

    fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let source = entry.path();
            let target = to.join(entry.file_name());
            if source.is_dir() {
                copy_dir(&source, &target);
            } else {
                fs::copy(&source, &target).unwrap();
            }
        }
    }

    #[test]
    fn accepts_inputs_owned_by_the_invoking_user() {
        let dir = fixture();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        validate_config_root(dir.path().join("grafhome-ca"), uid).unwrap();
    }

    #[test]
    fn bounded_validation_accepts_inputs_beneath_the_trusted_boundary() {
        let dir = fixture();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        validate_config_root_beneath(dir.path().join("grafhome-ca"), uid, dir.path()).unwrap();
    }

    #[test]
    fn bounded_validation_accepts_a_canonical_alias_of_the_boundary() {
        let dir = fixture();
        let boundary = dir.path().join("sandbox");
        let alias = dir.path().join("sandbox-alias");
        fs::create_dir(&boundary).unwrap();
        fs::rename(dir.path().join("grafhome-ca"), boundary.join("grafhome-ca")).unwrap();
        std::os::unix::fs::symlink(&boundary, &alias).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let validated =
            validate_config_root_beneath(alias.join("grafhome-ca"), uid, &alias).unwrap();

        assert_eq!(
            validated,
            fs::canonicalize(boundary.join("grafhome-ca")).unwrap()
        );
    }

    #[test]
    fn bounded_validation_rejects_a_config_root_outside_the_boundary() {
        let dir = fixture();
        let boundary = dir.path().join("sandbox");
        fs::create_dir(&boundary).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root_beneath(dir.path().join("grafhome-ca"), uid, &boundary)
            .unwrap_err()
            .to_string();

        assert!(error.contains("must remain beneath"));
    }

    #[test]
    fn bounded_validation_rejects_a_resolved_input_outside_the_boundary() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let boundary = dir.path().join("sandbox");
        fs::create_dir(&boundary).unwrap();
        fs::rename(&root, boundary.join("grafhome-ca")).unwrap();
        let root = boundary.join("grafhome-ca");
        let input = root.join("policy/hosts/ca-host.toml");
        let outside = dir.path().join("outside-host.toml");
        fs::rename(&input, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &input).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root_beneath(&root, uid, &boundary)
            .unwrap_err()
            .to_string();

        assert!(error.contains("must remain beneath"));
    }

    #[test]
    fn rejects_group_writable_policy_file() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let input = root.join("policy/hosts/ca-host.toml");
        fs::set_permissions(&input, fs::Permissions::from_mode(0o664)).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("ca-host.toml"));
        assert!(error.contains("permits group or world writes"));
    }

    #[test]
    fn rejects_world_writable_policy_directory() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let policy = root.join("policy");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o777)).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("policy"));
        assert!(error.contains("permits group or world writes"));
    }

    #[test]
    fn rejects_world_writable_host_inventory_directory() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let hosts = root.join("policy/hosts");
        fs::set_permissions(&hosts, fs::Permissions::from_mode(0o777)).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("policy/hosts"));
        assert!(error.contains("permits group or world writes"));
    }

    #[test]
    fn accepts_protected_symlinked_host_inventory_directory() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let hosts = root.join("policy/hosts");
        let target = dir.path().join("external-hosts");
        fs::rename(&hosts, &target).unwrap();
        std::os::unix::fs::symlink(&target, &hosts).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        validate_config_root(&root, uid).unwrap();
    }

    #[test]
    fn rejects_writable_symlinked_host_inventory_directory() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let hosts = root.join("policy/hosts");
        let target = dir.path().join("external-hosts");
        fs::rename(&hosts, &target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&target, &hosts).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("external-hosts"));
        assert!(error.contains("permits group or world writes"));
    }

    #[test]
    fn rejects_host_inventory_that_resolves_to_a_regular_file() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let hosts = root.join("policy/hosts");
        fs::remove_dir_all(&hosts).unwrap();
        fs::write(&hosts, "not a directory\n").unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("host policy input is not a directory"));
    }

    #[test]
    fn rejects_untrusted_owner() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let untrusted_uid = if uid == 0 {
            let input = root.join("policy/hosts/ca-host.toml");
            rustix::fs::chown(&input, Some(rustix::fs::Uid::from_raw(1)), None).unwrap();
            2
        } else {
            uid.checked_add(1).expect("test uid has a successor")
        };

        let error = validate_config_root(&root, untrusted_uid)
            .unwrap_err()
            .to_string();

        assert!(error.contains("neither root nor trusted uid"));
    }

    #[test]
    fn rejects_writable_symlink_target() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let original = root.join("policy/hosts/ca-host.toml");
        let target = dir.path().join("ca-host.toml");
        fs::rename(&original, &target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).unwrap();
        std::os::unix::fs::symlink(&target, &original).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("ca-host.toml"));
        assert!(error.contains("permits group or world writes"));
    }

    #[test]
    fn accepts_protected_symlink_target() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let original = root.join("policy/hosts/ca-host.toml");
        let target = dir.path().join("ca-host.toml");
        fs::rename(&original, &target).unwrap();
        std::os::unix::fs::symlink(&target, &original).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        validate_config_root(&root, uid).unwrap();
    }
}
