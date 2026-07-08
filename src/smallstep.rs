//! Smallstep command boundary.
//!
//! The crate intentionally shells out to `step` and `step-ca` instead of
//! reimplementing Smallstep protocols. This module will own argument/env
//! construction and structured output parsing as live workflows are added.

use std::path::PathBuf;

/// A prepared Smallstep command.
#[derive(Debug, Clone)]
pub struct StepCommand {
    /// Program path.
    pub program: PathBuf,
    /// Command arguments.
    pub args: Vec<String>,
    /// Optional `STEPPATH`.
    pub steppath: Option<PathBuf>,
}
