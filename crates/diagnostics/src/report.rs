use php2shell_core::{Architecture, VersionStatus};
use php2shell_fingerprint::{Evidence, Fingerprint};
use php2shell_profiles::Registry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    SufficientEvidence,
    InsufficientEvidence,
    PatchedVersion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMatch {
    pub id: String,
    pub php_version: String,
    pub sapi: String,
    pub arch: String,
    pub status: String,
    pub exact: bool,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMismatch {
    pub id: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub target: String,
    pub fingerprint: Fingerprint,
    pub confirmed: Vec<Evidence>,
    pub assumptions: Vec<Evidence>,
    pub compatible_profiles: Vec<ProfileMatch>,
    pub incompatible_profiles: Vec<ProfileMismatch>,
    pub uncertainty: Vec<String>,
    pub recommendations: Vec<String>,
    pub verdict: Verdict,
}

pub fn analyze(
    fingerprint: &Fingerprint,
    registry: &Registry,
    requested_arch: Option<&Architecture>,
    probe: Option<php2shell_fingerprint::ProbeInfo>,
) -> DiagnosticReport {
    let mut uncertainty = fingerprint.uncertainty.clone();
    let mut compatible = Vec::new();
    let mut incompatible = Vec::new();

    let version = fingerprint.version();
    let sapi = fingerprint.sapi_enum();
    let arch = requested_arch.filter(|value| value.is_known());

    if version.is_none() {
        uncertainty.push("No exact PHP version: profiles cannot be matched to this target.".into());
    }
    if arch.is_none() {
        uncertainty.push("CPU architecture is not observable over HTTP; no build-specific profile can be confirmed.".into());
    }

    for profile in &registry.profiles {
        let profile_version = profile.version();
        let mut reasons = Vec::new();

        let exact = match (&version, &profile_version) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        };
        let branch_match = match (&version, &profile_version) {
            (Some(a), Some(b)) => a.branch() == b.branch(),
            _ => false,
        };
        if !exact && !branch_match {
            reasons.push(if version.is_none() {
                "target version unknown".to_owned()
            } else {
                format!(
                    "profile version {} does not match observed {}",
                    profile.string("php_version").unwrap_or_default(),
                    version
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "unknown".into())
                )
            });
        }
        if let Some(wanted) = arch {
            let observed = profile.arch();
            if observed.is_known() && wanted != &observed {
                reasons.push(format!(
                    "architecture {} does not match {}",
                    observed, wanted
                ));
            }
        }
        if let Some(wanted) = sapi.as_ref() {
            let observed = profile.sapi();
            if !observed.as_str().is_empty() && wanted != &observed {
                reasons.push(format!("SAPI {} does not match {}", observed, wanted));
            }
        }
        if !profile.verified() || !profile.rce() {
            reasons.push("no verified calibration recorded for this build".to_owned());
        }

        if reasons.is_empty() {
            compatible.push(ProfileMatch {
                id: profile.id().to_owned(),
                php_version: profile.string("php_version").unwrap_or_default().to_owned(),
                sapi: profile.sapi().as_str().to_owned(),
                arch: profile.arch().as_str().to_owned(),
                status: profile.status().to_owned(),
                exact,
                reason: if exact {
                    "exact version, SAPI and architecture match".to_owned()
                } else {
                    "branch match only; exact build not confirmed".to_owned()
                },
            });
        } else {
            incompatible.push(ProfileMismatch {
                id: profile.id().to_owned(),
                reason: reasons.join("; "),
            });
        }
    }

    if let Some(probe) = probe {
        if probe.rejected {
            uncertainty.push("The observed response rejected a large body (413); configuration details are unavailable.".into());
        }
        if let Some(limit) = probe.memory_limit_mb {
            uncertainty.push(format!("Observed memory_limit={limit}M from a diagnostic message; this is not a configuration proof."));
        }
        if let Some(bytes) = probe.post_max_size_bytes {
            uncertainty.push(format!(
                "Observed post_max_size={bytes} bytes from a diagnostic message."
            ));
        }
        if !probe.diagnostics && !probe.rejected {
            uncertainty.push(
                "No request-startup diagnostics were observable in the supplied response.".into(),
            );
        }
    }

    let recommendations = recommendations(fingerprint, probe);

    let verdict = match fingerprint.version_status {
        Some(VersionStatus::Patched) => Verdict::PatchedVersion,
        // An exact version match alone is not enough: CPU architecture is not
        // observable over HTTP, so a build-specific profile stays unconfirmed
        // until the operator supplies --arch explicitly.
        Some(_) if arch.is_some() && compatible.iter().any(|m| m.exact) => {
            Verdict::SufficientEvidence
        }
        _ => Verdict::InsufficientEvidence,
    };

    DiagnosticReport {
        target: fingerprint.target.clone(),
        fingerprint: fingerprint.clone(),
        confirmed: fingerprint.confident_facts().into_iter().cloned().collect(),
        assumptions: fingerprint.assumptions().into_iter().cloned().collect(),
        compatible_profiles: compatible,
        incompatible_profiles: incompatible,
        uncertainty,
        recommendations,
        verdict,
    }
}

fn recommendations(
    fingerprint: &Fingerprint,
    probe: Option<php2shell_fingerprint::ProbeInfo>,
) -> Vec<String> {
    let mut out = Vec::new();
    match fingerprint.version_status {
        Some(VersionStatus::Patched) => out.push(
            "The observed version is at or above the first fixed release of its branch; keep patch levels current."
                .to_owned(),
        ),
        Some(VersionStatus::Vulnerable | VersionStatus::VulnerableEol) => {
            if let Some(version) = fingerprint.version() {
                if let Some(fixed) = php2shell_core::versions::fixed_in(&version) {
                    out.push(format!("Upgrade PHP to {fixed} or newer."));
                } else {
                    out.push("The observed branch is end-of-life and has no official fix; plan a supported upgrade.".to_owned());
                }
            }
            out.push("Disable session.upload_progress where it is not required.".to_owned());
            out.push("Set display_errors=Off in production; startup diagnostics are a disclosure channel.".to_owned());
            out.push("Rate-limit large multipart request bodies at the edge and alert on repeated OOM/500 responses.".to_owned());
            out.push("Run PHP as an unprivileged user with a read-only document root.".to_owned());
            if probe.is_some_and(|p| p.diagnostics) {
                out.push("Observed diagnostics in a response: verify display_errors=Off in the production configuration.".to_owned());
            }
        }
        Some(VersionStatus::OutsideMatrix | VersionStatus::Unknown) | None => {
            out.push("Version or branch is outside the known matrix; confirm the build from an authoritative source.".to_owned());
        }
    }
    if fingerprint.version_status.is_none() {
        out.push("Supply a captured HTTP response with an explicit X-Powered-By header for offline fingerprinting.".to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use php2shell_fingerprint::Fingerprinter;
    use php2shell_http_client::HttpResponse;

    fn report() -> DiagnosticReport {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("8.4.26-bookworm-amd64.json"),
            r#"{"name":"php-8.4.26-bookworm-amd64","php_version":"8.4.26","branch":"8.4","sapi":"apache2handler","arch":"amd64","rce":true,"verified":true,"status":"verified","libphp":{"zif_system":"0x1","zval_ptr_dtor":"0x2","htdata":"0x3"},"stages":{},"config":{},"oom_mb":12}"#,
        )
        .unwrap();
        let registry = Registry::load_with_manifest(dir.path(), None).unwrap();
        let response = HttpResponse {
            url: "http://127.0.0.1:8105/index.php".into(),
            status: 200,
            headers: vec![
                ("server".into(), "Apache/2.4.69 (Debian)".into()),
                ("x-powered-by".into(), "PHP/8.4.26".into()),
            ],
            body: Bytes::from_static(b"OK"),
        };
        let fingerprint = Fingerprinter::analyze(&response);
        analyze(&fingerprint, &registry, Some(&Architecture::Amd64), None)
    }

    #[test]
    fn finds_exact_profile_and_keeps_sapi_as_probable() {
        let report = report();
        assert_eq!(report.verdict, Verdict::SufficientEvidence);
        assert_eq!(report.compatible_profiles.len(), 1);
        assert!(report.compatible_profiles[0].exact);
        assert!(
            report
                .assumptions
                .iter()
                .any(|e| e.kind == php2shell_fingerprint::EvidenceKind::Sapi)
        );
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn unknown_version_is_not_a_confirmed_match() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::load_with_manifest(dir.path(), None).unwrap();
        let response = HttpResponse {
            url: "http://127.0.0.1/index.php".into(),
            status: 200,
            headers: vec![],
            body: Bytes::from_static(b"nothing here"),
        };
        let fingerprint = Fingerprinter::analyze(&response);
        let report = analyze(&fingerprint, &registry, None, None);
        assert_eq!(report.verdict, Verdict::InsufficientEvidence);
        assert!(report.compatible_profiles.is_empty());
        assert!(report.uncertainty.len() >= 4);
    }
}
