//! Passive fingerprinting of HTTP responses.
//!
//! Every conclusion carries an explicit confidence. HTTP headers are
//! operator-supplied observations, not proofs of the target configuration.

mod fingerprint;
mod probe;

pub use fingerprint::{
    Evidence, EvidenceKind, Fingerprint, Fingerprinter, detect_distro, detect_sapi,
    normalize_distro,
};
pub use probe::{ProbeInfo, parse_probe_response};
