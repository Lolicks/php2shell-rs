//! Safe precondition diagnostics mirroring steps 1-4 of the upstream FPM
//! `probe`. The OOM/arm step is deliberately NOT implemented.

use php2shell_core::{VersionStatus, versions};
use php2shell_fingerprint::Fingerprinter;
use php2shell_http_client::{HttpResponse, SafeClient};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub label: &'static str,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PreconditionReport {
    pub base: String,
    pub checks: Vec<Check>,
    pub all_ok: bool,
    pub skipped: Vec<String>,
}

fn join(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn status(status: &str) -> &'static str {
    match status {
        "ok" => "+",
        "failed" => "-",
        _ => "!",
    }
}

pub async fn probe(
    client: &SafeClient,
    base: &str,
    app_path: &str,
    ref_path: &str,
    session: &str,
    php_version: Option<&str>,
    diagnostic_version: Option<&str>,
) -> PreconditionReport {
    let mut checks = Vec::new();

    // Step 1: version classification from an explicitly supplied value or a
    // passive fingerprint of the base URL.
    let version = if let Some(value) = php_version {
        Some(value.to_owned())
    } else {
        client
            .fetch(base)
            .await
            .ok()
            .and_then(|response| Fingerprinter::analyze(&response).php_version)
    };
    match version.as_deref().and_then(versions::classify) {
        Some(classification) if classification.status == VersionStatus::Patched => {
            checks.push(Check {
                label: "version",
                status: status("failed"),
                detail: format!(
                    "PHP {} is patched ({})",
                    classification.version,
                    classification
                        .fixed
                        .map(|v| v.to_string())
                        .unwrap_or_default()
                ),
            })
        }
        Some(classification) => checks.push(Check {
            label: "version",
            status: status("ok"),
            detail: format!(
                "PHP {} - {}",
                classification.version,
                classification.status.as_str()
            ),
        }),
        None => checks.push(Check {
            label: "version",
            status: status("unknown"),
            detail: "no PHP version available; supply one explicitly".to_owned(),
        }),
    }

    let sid = "p2s-probe-locally-scoped";
    let cookie = format!("{session}={sid}");

    // Step 2: small, bounded reflection probe. No oversized bodies.
    let app_url = join(base, app_path);
    let post_body = b"k=PRBMARK&v=P2SREFLECT".to_vec();
    let post = client
        .fetch_with(
            &app_url,
            reqwest::Method::POST,
            vec![
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("cookie".into(), cookie.clone()),
            ],
            post_body,
        )
        .await;
    let reflected = match post {
        Ok(_) => client
            .fetch_with(
                &app_url,
                reqwest::Method::GET,
                vec![("cookie".into(), cookie.clone())],
                Vec::new(),
            )
            .await
            .ok()
            .is_some_and(|response: HttpResponse| {
                let text = response.body_text();
                text.contains("PRBMARK") && text.contains("P2SREFLECT")
            }),
        Err(_) => false,
    };
    checks.push(Check {
        label: "reflection",
        status: status(if reflected { "ok" } else { "failed" }),
        detail: format!(
            "GET {app_path} with a small session write {}",
            if reflected {
                "reflected the marker"
            } else {
                "did not reflect the marker"
            }
        ),
    });

    // Step 3: reference endpoint. A tiny `x=1` post, never an exploit payload.
    let ref_url = join(base, ref_path);
    let reference_ok = client
        .fetch_with(
            &ref_url,
            reqwest::Method::POST,
            vec![
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("cookie".into(), cookie.clone()),
            ],
            b"x=1".to_vec(),
        )
        .await
        .is_ok()
        && client
            .fetch_with(
                &app_url,
                reqwest::Method::GET,
                vec![("cookie".into(), cookie)],
                Vec::new(),
            )
            .await
            .ok()
            .is_some_and(|response| response.body_text().contains("r\tx"));
    checks.push(Check {
        label: "reference",
        status: status(if reference_ok { "ok" } else { "failed" }),
        detail: format!(
            "POST {ref_path} + GET {app_path} {}",
            if reference_ok {
                "exposed the reference"
            } else {
                "did not expose the reference"
            }
        ),
    });

    if let Some(diagnostic) = diagnostic_version {
        checks.push(Check {
            label: "diagnostics",
            status: status("ok"),
            detail: format!("observed request-startup diagnostic: {diagnostic}"),
        });
    }

    let all_ok = checks.iter().all(|check| check.status == "+");
    PreconditionReport {
        base: base.to_owned(),
        checks,
        all_ok,
        skipped: vec![
            "OOM/arm step intentionally not implemented (disruptive)".to_owned(),
            "worker count is not measurable over HTTP in safe mode".to_owned(),
        ],
    }
}
