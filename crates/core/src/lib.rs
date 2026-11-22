//! Shared infrastructure for the PHP2Shell-RS workspace.
//!
//! This crate contains no network or exploit logic.

pub mod error;
pub mod sha256;
pub mod types;
pub mod versions;

pub use error::{Error, Result};
pub use types::{Architecture, Confidence, Sapi, Version};
pub use versions::{Classification, VersionStatus};

pub const TOOL_NAME: &str = "php2shell-rs";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
