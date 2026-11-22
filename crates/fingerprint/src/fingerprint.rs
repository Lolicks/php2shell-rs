use php2shell_core::{Confidence, Sapi, Version, VersionStatus, versions};
use php2shell_http_client::HttpResponse;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ServerSoftware,
    PhpVersion,
    Sapi,
    OsHint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub value: String,
    pub source: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub target: String,
    pub http_status: u16,
    pub server_software: Option<String>,
    pub php_version: Option<String>,
    pub sapi: Option<String>,
    pub os_hint: Option<String>,
    pub version_status: Option<VersionStatus>,
    pub evidence: Vec<Evidence>,
    pub uncertainty: Vec<String>,
    /// 0-100 estimate of how complete the observable information is.
    pub completeness: u8,
}

impl Fingerprint {
    pub fn sapi_enum(&self) -> Option<Sapi> {
        self.sapi.as_deref().map(|value| match value {
            "apache2handler" => Sapi::Apache2Handler,
            "fpm" => Sapi::Fpm,
            other => Sapi::Unknown(other.to_owned()),
        })
    }

    pub fn version(&self) -> Option<Version> {
        self.php_version.as_deref().and_then(Version::parse)
    }

    pub fn confident_facts(&self) -> Vec<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| e.confidence == Confidence::Confirmed)
            .collect()
    }

    pub fn assumptions(&self) -> Vec<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| e.confidence != Confidence::Confirmed)
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Fingerprinter;

impl Fingerprinter {
    pub fn analyze(response: &HttpResponse) -> Fingerprint {
        let mut evidence = Vec::new();
        let mut uncertainty = Vec::new();

        let server = response
            .header("server")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let powered = response
            .header("x-powered-by")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let body = response.body_text();

        let server_software = server.map(ToOwned::to_owned);
        if let Some(value) = &server_software {
            evidence.push(Evidence {
                kind: EvidenceKind::ServerSoftware,
                value: value.clone(),
                source: "header:server".into(),
                confidence: Confidence::Confirmed,
            });
        } else {
            uncertainty
                .push("The Server header was not supplied; server software is unknown.".into());
        }

        let header_version = powered
            .and_then(find_php_version)
            .or_else(|| server.and_then(find_php_version));
        let body_version = find_php_version(&body);
        let body_version_present = body_version.is_some();
        let php_version = if let Some(version) = header_version {
            if let Some(other) = body_version
                && other != version
            {
                uncertainty.push(format!(
                        "Header version {version} disagrees with body version {other}; header value kept."
                    ));
            }
            Some(version.to_string())
        } else {
            body_version.map(|version| {
                uncertainty.push(format!(
                    "PHP {version} was inferred from response body text; this is not a confirmed header value."
                ));
                version.to_string()
            })
        };
        let version_confidence = if powered.is_some() || server.and_then(find_php_version).is_some()
        {
            Confidence::Confirmed
        } else if body_version_present {
            Confidence::Probable
        } else {
            Confidence::Unknown
        };
        if version_confidence != Confidence::Unknown {
            evidence.push(Evidence {
                kind: EvidenceKind::PhpVersion,
                value: php_version.clone().unwrap_or_default(),
                source: if version_confidence == Confidence::Confirmed {
                    "header:x-powered-by".into()
                } else {
                    "body".into()
                },
                confidence: version_confidence,
            });
        }
        if php_version.is_none() {
            uncertainty.push("No PHP version was observable; version remains unknown.".into());
        }

        let sapi_text = server.unwrap_or_default().to_ascii_lowercase();
        let sapi = if sapi_text.contains("apache") {
            Some(Sapi::Apache2Handler.as_str().to_owned())
        } else if sapi_text.contains("nginx") {
            Some(Sapi::Fpm.as_str().to_owned())
        } else {
            None
        };
        if let Some(value) = &sapi {
            let confidence = if sapi_text.contains("apache") {
                Confidence::Probable
            } else {
                Confidence::Possible
            };
            evidence.push(Evidence {
                kind: EvidenceKind::Sapi,
                value: value.clone(),
                source: "header:server".into(),
                confidence,
            });
            uncertainty.push(
                "The SAPI is inferred from a web-server banner only; Apache does not prove mod_php and nginx does not prove PHP-FPM."
                    .into(),
            );
        } else {
            uncertainty.push("The SAPI is unknown from the available response headers.".into());
        }

        let banner = server.unwrap_or_default();
        let os_hint = detect_distro(banner).map(ToOwned::to_owned).or_else(|| {
            let lower = format!("{} {}", banner, powered.unwrap_or_default()).to_ascii_lowercase();
            if lower.contains("win32") || lower.contains("win64") || lower.contains("windows") {
                Some("windows".to_owned())
            } else {
                None
            }
        });
        if let Some(value) = &os_hint {
            evidence.push(Evidence {
                kind: EvidenceKind::OsHint,
                value: value.clone(),
                source: "header:server".into(),
                confidence: Confidence::Possible,
            });
            uncertainty
                .push("Operating system hints from banners are not proof of the host OS.".into());
        } else {
            uncertainty.push("No reliable OS indicator was present in the response.".into());
        }

        if response.status >= 400 {
            uncertainty.push(format!(
                "HTTP status {} may describe an error page rather than the application's normal response.",
                response.status
            ));
        }

        let fields = [
            php_version.is_some(),
            server_software.is_some(),
            sapi.is_some(),
            os_hint.is_some(),
        ];
        let completeness = (fields.iter().filter(|present| **present).count() * 25) as u8;
        let version_status = php_version
            .as_deref()
            .and_then(Version::parse)
            .and_then(|version| versions::classify(&version.to_string()))
            .map(|classification| classification.status);

        Fingerprint {
            target: response.url.clone(),
            http_status: response.status,
            server_software,
            php_version,
            sapi,
            os_hint,
            version_status,
            evidence,
            uncertainty,
            completeness,
        }
    }
}

fn find_php_version(text: &str) -> Option<Version> {
    let bytes = text.as_bytes();
    let marker = b"PHP/";
    let mut offset = 0usize;
    while offset + marker.len() <= bytes.len() {
        let window = &bytes[offset..];
        let relative = window
            .windows(marker.len())
            .position(|part| part == marker)?;
        let start = offset + relative + marker.len();
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
            end += 1;
        }
        if let Some(version) = std::str::from_utf8(&bytes[start..end])
            .ok()
            .and_then(Version::parse)
        {
            return Some(version);
        }
        offset = start;
    }
    None
}

/// Upstream `detect_distro`: first keyword wins, order is significant.
pub fn detect_distro(server: &str) -> Option<&'static str> {
    let lower = server.to_ascii_lowercase();
    [
        "fedora",
        "debian",
        "ubuntu",
        "alpine",
        "centos",
        "red hat",
        "rhel",
        "amazon linux",
        "suse",
        "arch linux",
    ]
    .into_iter()
    .find(|needle| lower.contains(needle))
}

/// Upstream `normalize_distro`: Debian-family banners collapse to `debian`.
pub fn normalize_distro(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if ["debian", "bookworm", "bullseye", "buster", "trixie"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return Some("debian");
    }
    [
        "ubuntu",
        "fedora",
        "alpine",
        "centos",
        "rhel",
        "red hat",
        "amazon linux",
        "suse",
        "arch linux",
    ]
    .into_iter()
    .find(|needle| lower.contains(needle))
}

/// Reports what a server banner suggests about the SAPI without claiming it.
pub fn detect_sapi(server: &str) -> Option<Sapi> {
    let lower = server.to_ascii_lowercase();
    if lower.contains("apache") {
        Some(Sapi::Apache2Handler)
    } else if lower.contains("nginx") {
        Some(Sapi::Fpm)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn response(server: Option<&str>, powered: Option<&str>, body: &str) -> HttpResponse {
        let mut headers = Vec::new();
        if let Some(value) = server {
            headers.push(("server".into(), value.into()));
        }
        if let Some(value) = powered {
            headers.push(("x-powered-by".into(), value.into()));
        }
        HttpResponse {
            url: "http://127.0.0.1:8105/index.php".into(),
            status: 200,
            headers,
            body: Bytes::from(body.to_owned()),
        }
    }

    #[test]
    fn confirms_version_from_header_but_not_sapi() {
        let result = Fingerprinter::analyze(&response(
            Some("Apache/2.4.69 (Debian)"),
            Some("PHP/8.4.26"),
            "OK",
        ));
        assert_eq!(result.php_version.as_deref(), Some("8.4.26"));
        assert_eq!(
            result.server_software.as_deref(),
            Some("Apache/2.4.69 (Debian)")
        );
        assert_eq!(result.sapi.as_deref(), Some("apache2handler"));
        assert_eq!(result.os_hint.as_deref(), Some("debian"));
        assert_eq!(result.version_status, Some(VersionStatus::Vulnerable));
        assert!(
            result
                .confident_facts()
                .iter()
                .any(|e| e.kind == EvidenceKind::PhpVersion)
        );
        assert!(
            result
                .assumptions()
                .iter()
                .any(|e| e.kind == EvidenceKind::Sapi)
        );
    }

    #[test]
    fn keeps_uncertainty_when_nothing_is_observable() {
        let result = Fingerprinter::analyze(&response(None, None, "static page"));
        assert_eq!(result.completeness, 0);
        assert!(result.php_version.is_none());
        assert!(result.version_status.is_none());
        assert!(!result.uncertainty.is_empty());
    }

    #[test]
    fn body_version_is_only_probable() {
        let result =
            Fingerprinter::analyze(&response(Some("nginx"), None, "powered by PHP/8.4.26"));
        assert_eq!(result.php_version.as_deref(), Some("8.4.26"));
        assert_eq!(result.sapi.as_deref(), Some("fpm"));
        assert!(result.uncertainty.iter().any(|u| u.contains("body text")));
    }

    #[test]
    fn distro_helpers_follow_upstream_order() {
        assert_eq!(detect_distro("Apache/2 (Debian)"), Some("debian"));
        assert_eq!(detect_distro("Apache/2 (Red Hat)"), Some("red hat"));
        assert_eq!(normalize_distro("bookworm"), Some("debian"));
        assert_eq!(normalize_distro("ubuntu"), Some("ubuntu"));
        assert_eq!(normalize_distro("plan9"), None);
    }
}
