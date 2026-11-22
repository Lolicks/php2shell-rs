//! Combines passive observations with the profile registry into a diagnostic
//! result. It never attempts to exploit or validate a target actively.

mod report;

pub use report::{DiagnosticReport, ProfileMatch, ProfileMismatch, Verdict, analyze};
