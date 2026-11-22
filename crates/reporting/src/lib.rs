//! Versioned report export with redaction of operator-supplied URLs.

mod report;

pub use report::{Report, redact_url, render_table, write_report};
