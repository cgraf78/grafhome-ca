//! Build-version reporting.

/// Git commit embedded into the binary at build time.
pub const COMMIT: &str = env!("GRAFHOME_CA_BUILD_COMMIT");

/// Public generated version embedded into the binary at build time.
///
/// The format is `YYYYMMDD-HHMMSS-<8hex>`.
pub const VERSION: &str = env!("GRAFHOME_CA_BUILD_VERSION");

/// Full CLI version payload without the leading binary name.
pub const CLI_VERSION: &str = env!("GRAFHOME_CA_CLI_VERSION");

/// Returns the embedded git commit hash.
#[must_use]
pub const fn commit() -> &'static str {
    COMMIT
}

/// Returns the generated public version.
#[must_use]
pub const fn version() -> &'static str {
    VERSION
}

/// Returns the full CLI version payload without the leading binary name.
#[must_use]
pub const fn cli() -> &'static str {
    CLI_VERSION
}

#[cfg(test)]
mod tests {
    use super::{cli, commit, version};

    #[test]
    fn embedded_commit_is_concrete_hex() {
        let commit = commit();

        assert!(commit.len() >= 8);
        assert!(commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(commit, "unknown");
    }

    #[test]
    fn public_version_is_readable_and_traceable() {
        let version = version();
        let parts = version.split('-').collect::<Vec<_>>();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 6);
        assert_eq!(parts[2].len(), 8);
        assert!(parts[0].bytes().all(|byte| byte.is_ascii_digit()));
        assert!(parts[1].bytes().all(|byte| byte.is_ascii_digit()));
        assert!(parts[2].bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(parts[2], &commit()[..8]);
        assert_ne!(version, "unknown");
    }

    #[test]
    fn cli_version_starts_with_public_version() {
        assert!(cli().starts_with(version()));
    }
}
