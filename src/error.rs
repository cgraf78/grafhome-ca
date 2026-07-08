//! Error types shared by the library and CLIs.

use std::path::PathBuf;

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by Grafhome CA tooling.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Filesystem I/O failed.
    #[error("{path}: {source}")]
    Io {
        /// Path being read or written.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A config or policy file is malformed.
    #[error("{path}:{line}: {message}")]
    Parse {
        /// Path being parsed.
        path: PathBuf,
        /// One-indexed line number.
        line: usize,
        /// Human-readable parse failure.
        message: String,
    },

    /// A policy/config field failed validation.
    #[error("{field}: {message}")]
    Validation {
        /// Owning field, such as `policy/endpoints.tsv:ca_origin.port`.
        field: String,
        /// Human-readable validation failure.
        message: String,
    },

    /// JSON parsing failed.
    #[error("{path}: {source}")]
    Json {
        /// Path being parsed.
        path: PathBuf,
        /// Underlying JSON error.
        source: serde_json::Error,
    },

    /// CSV/TSV parsing failed.
    #[error("{path}: {source}")]
    Csv {
        /// Path being parsed.
        path: PathBuf,
        /// Underlying CSV error.
        source: csv::Error,
    },
}

impl Error {
    /// Wrap an I/O error with its path.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
