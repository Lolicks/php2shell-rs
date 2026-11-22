//! Safe calibration support: reproducible metadata and artifact hashes.
//!
//! The exploit-driven calibration stages of the original Python toolkit are
//! intentionally absent. This crate records observations and checks their
//! metadata; it never applies a payload and never marks a result as verified
//! without an operator-supplied artifact hash.

mod metadata;
mod pad;
mod record;

pub use metadata::{
    ContainerMetadata, collect_container_metadata, parse_memory_limit, symbol_offsets,
};
pub use pad::{bookworm_pads, lab_pads, pads_to_spec, parse_pads, stage3_profile_json};
pub use record::{CalibrationRecord, CalibrationResult};
