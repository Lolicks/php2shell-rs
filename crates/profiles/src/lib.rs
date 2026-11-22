//! Profile registry: import, validate and export the upstream JSON profiles
//! without changing their contents.

mod manifest;
mod model;
mod registry;
mod validation;

pub use manifest::{Manifest, ManifestEntry};
pub use model::{Profile, ProfileKind};
pub use registry::{ProfileQuery, Registry};
pub use validation::{Issue, Severity, validate_profile, validate_registry};
