use std::path::Path;

use php2shell_calibration::CalibrationRecord;
use php2shell_config::Config;
use php2shell_core::{Error, Result, sha256};
use php2shell_diagnostics::DiagnosticReport;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const REPORT_SCHEMA: &str = "php2shell-rs/report/1.0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub generated_at: String,
    pub tool_name: &'static str,
    pub tool_version: &'static str,
    pub mode: &'static str,
    pub target: String,
    pub diagnostics: DiagnosticReport,
    pub calibration: Vec<CalibrationRecord>,
}

impl Report {
    pub fn new(
        config: &Config,
        diagnostics: DiagnosticReport,
        calibration: Vec<CalibrationRecord>,
    ) -> Self {
        let target = if config.report.redact {
            redact_url(&diagnostics.target)
        } else {
            diagnostics.target.clone()
        };
        Self {
            schema: REPORT_SCHEMA,
            generated_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
            tool_name: php2shell_core::TOOL_NAME,
            tool_version: php2shell_core::TOOL_VERSION,
            mode: config.mode.as_str(),
            target,
            diagnostics,
            calibration,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|err| Error::other(format!("serialising report: {err}")))
    }

    pub fn sha256(&self) -> Result<String> {
        Ok(sha256::hash_bytes(self.to_json()?.as_bytes()))
    }
}

/// Removes user info, query parameters and fragments from a URL. Used by
/// default so reports never leak credentials embedded in an operator URL.
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path = &rest[authority_end..];
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    format!("{scheme}{authority}{path}")
}

pub fn write_report(report: &Report, path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
    }
    let json = report.to_json()?;
    std::fs::write(path, &json).map_err(|err| Error::io(path, err))?;
    report.sha256()
}

pub fn render_table(report: &Report) -> String {
    let d = &report.diagnostics;
    let mut out = String::new();
    out.push_str(&format!("target            : {}\n", report.target));
    out.push_str(&format!("verdict           : {}\n", verdict_str(d.verdict)));
    out.push_str(&format!(
        "php version       : {}\n",
        d.fingerprint.php_version.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "server software   : {}\n",
        d.fingerprint
            .server_software
            .as_deref()
            .unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "sapi (inferred)   : {}\n",
        d.fingerprint.sapi.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "completeness      : {}%\n",
        d.fingerprint.completeness
    ));
    out.push_str(&format!(
        "compatible        : {}\n",
        d.compatible_profiles.len()
    ));
    out.push_str(&format!(
        "incompatible      : {}\n",
        d.incompatible_profiles.len()
    ));
    out.push_str(&format!(
        "uncertainty       : {} item(s)\n",
        d.uncertainty.len()
    ));
    out.push_str(&format!(
        "recommendations   : {} item(s)\n",
        d.recommendations.len()
    ));
    out.push_str(&format!("mode              : {}\n", report.mode));
    out
}

fn verdict_str(verdict: php2shell_diagnostics::Verdict) -> &'static str {
    use php2shell_diagnostics::Verdict;
    match verdict {
        Verdict::SufficientEvidence => "sufficient evidence",
        Verdict::InsufficientEvidence => "insufficient evidence",
        Verdict::PatchedVersion => "patched version",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_url_parts() {
        assert_eq!(
            redact_url("https://user:pass@example.org/path?token=secret#frag"),
            "https://example.org/path"
        );
        assert_eq!(
            redact_url("http://127.0.0.1:8105/index.php"),
            "http://127.0.0.1:8105/index.php"
        );
    }

    #[test]
    fn report_is_deterministic_enough_to_hash() {
        let _config = Config::default();
        // Reports contain a timestamp; hashing the same value twice is stable.
        let report = Report {
            schema: REPORT_SCHEMA,
            generated_at: "2026-01-01T00:00:00Z".into(),
            tool_name: "php2shell-rs",
            tool_version: "1.0.0",
            mode: "safe",
            target: "http://127.0.0.1/index.php".into(),
            diagnostics: serde_json::from_value(serde_json::json!({
                "target": "http://127.0.0.1/index.php",
                "fingerprint": {
                    "target": "http://127.0.0.1/index.php", "http_status": 200,
                    "server_software": null, "php_version": null, "sapi": null,
                    "os_hint": null, "version_status": null, "evidence": [],
                    "uncertainty": [], "completeness": 0
                },
                "confirmed": [], "assumptions": [], "compatible_profiles": [],
                "incompatible_profiles": [], "uncertainty": [], "recommendations": [],
                "verdict": "insufficient_evidence"
            }))
            .unwrap(),
            calibration: vec![],
        };
        assert_eq!(report.sha256().unwrap(), report.sha256().unwrap());
        assert!(render_table(&report).contains("insufficient evidence"));
    }
}
