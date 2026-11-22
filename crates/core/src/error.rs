//! Shared error type. Every crate maps its failures into this enum so the CLI
//! can render one consistent diagnostic and choose a meaningful exit code.

use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("invalid TOML in {path}: {message}")]
    Toml { path: PathBuf, message: String },

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("invalid profile `{id}`: {message}")]
    Profile { id: String, message: String },

    #[error("profile not found: {0}")]
    ProfileNotFound(String),

    #[error("address `{0}` is not allowed by the current configuration")]
    HostNotAllowed(String),

    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("operation requires lab mode and an explicitly configured local target")]
    LabOnly,

    #[error("operation cancelled: {0}")]
    Cancelled(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    pub fn json(path: impl AsRef<Path>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    /// Stable exit-code class used by the CLI.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::HostNotAllowed(_) | Self::LabOnly => 4,
            Self::Config(_) | Self::Toml { .. } => 3,
            Self::Io { .. } | Self::Json { .. } => 5,
            Self::Profile { .. } | Self::ProfileNotFound(_) => 2,
            Self::Http(_) | Self::Cancelled(_) | Self::Other(_) => 6,
        }
    }
}
