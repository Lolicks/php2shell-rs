//! Combines passive observations with the profile registry into a diagnostic
//! result. It never attempts to exploit or validate a target actively.

mod preconditions;
mod report;

pub use preconditions::{Check, PreconditionReport, probe};
pub use report::{DiagnosticReport, ProfileMatch, ProfileMismatch, Verdict, analyze};
