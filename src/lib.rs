//! Core library for Grafhome CA tooling.
//!
//! This crate owns local policy parsing, schema validation, render inputs, and
//! command orchestration. It intentionally does not implement CA signing or the
//! Smallstep protocol; `step-ca` and `step` remain the cryptographic boundary.

pub mod config;
pub mod error;
pub mod lifecycle;
pub mod model;
pub mod policy;
pub mod public_material;
pub mod render;
pub mod runtime_provisioners;
pub mod schema;
pub mod smallstep;
pub mod version;

pub use error::{Error, Result};

#[cfg(test)]
pub(crate) fn example_config_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/site-config")
}
