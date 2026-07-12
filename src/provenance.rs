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
    let config_root = absolute(config_root.as_ref())?;
    let mut checked = BTreeSet::new();
    check_chain(&config_root, trusted_uid, &mut checked)?;

    for relative in crate::schema::config_input_paths() {
        let input = config_root.join(relative);
        check_chain(&input, trusted_uid, &mut checked)?;
        let resolved = std::fs::canonicalize(&input).map_err(|source| Error::io(&input, source))?;
        check_chain(&resolved, trusted_uid, &mut checked)?;
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
fn check_chain(path: &Path, trusted_uid: u32, checked: &mut BTreeSet<PathBuf>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
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

    use super::validate_config_root;

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
    fn rejects_group_writable_policy_file() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let input = root.join("policy/user-hosts.tsv");
        fs::set_permissions(&input, fs::Permissions::from_mode(0o664)).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("user-hosts.tsv"));
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
    fn rejects_untrusted_owner() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let untrusted_uid = uid.checked_add(1).expect("test uid has a successor");

        let error = validate_config_root(&root, untrusted_uid)
            .unwrap_err()
            .to_string();

        assert!(error.contains("neither root nor trusted uid"));
    }

    #[test]
    fn rejects_writable_symlink_target() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let original = root.join("policy/user-hosts.tsv");
        let target = dir.path().join("user-hosts.tsv");
        fs::rename(&original, &target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).unwrap();
        std::os::unix::fs::symlink(&target, &original).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        let error = validate_config_root(&root, uid).unwrap_err().to_string();

        assert!(error.contains("user-hosts.tsv"));
        assert!(error.contains("permits group or world writes"));
    }

    #[test]
    fn accepts_protected_symlink_target() {
        let dir = fixture();
        let root = dir.path().join("grafhome-ca");
        let original = root.join("policy/user-hosts.tsv");
        let target = dir.path().join("user-hosts.tsv");
        fs::rename(&original, &target).unwrap();
        std::os::unix::fs::symlink(&target, &original).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();

        validate_config_root(&root, uid).unwrap();
    }
}
