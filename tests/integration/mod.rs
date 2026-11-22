//! End-to-end CLI and library integration tests. All network operations use
//! the local mock laboratory or saved response fixtures.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use php2shell_config::Config;
use php2shell_fingerprint::Fingerprinter;
use php2shell_http_client::SafeClient;
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    root().join("tests/fixtures").join(name)
}

fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_php2shell-rs"));
    command.current_dir(root());
    command
}

fn output(args: &[&str]) -> (i32, String, String) {
    let result = cli().args(args).output().expect("binary should run");
    (
        result.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&result.stdout).into_owned(),
        String::from_utf8_lossy(&result.stderr).into_owned(),
    )
}

#[test]
fn help_and_version_are_available() {
    let (code, stdout, _) = output(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("profile"));
    assert!(stdout.contains("tui"));

    let (code, stdout, _) = output(&["version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("php2shell-rs"));
    assert!(stdout.contains("TLS verification: true"));
}

#[test]
fn real_profiles_validate_without_errors() {
    let (code, stdout, stderr) = output(&["profile", "validate"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("56 profiles: 0 error(s), 0 warning(s)"));
}

#[test]
fn profile_list_and_inventory_read_the_upstream_json() {
    let (code, stdout, _) = output(&["profile", "list", "--json"]);
    assert_eq!(code, 0);
    let profiles: Vec<Value> = serde_json::from_str(&stdout).expect("JSON profile list");
    assert_eq!(profiles.len(), 56);

    let (code, stdout, _) = output(&["inventory", "--json", "--sapi", "fpm"]);
    assert_eq!(code, 0);
    let fpm: Vec<Value> = serde_json::from_str(&stdout).expect("JSON inventory");
    assert_eq!(fpm.len(), 8);
}

#[test]
fn profile_show_returns_the_original_document() {
    let (code, stdout, _) = output(&["profile", "show", "php-8.4.26-bookworm-amd64"]);
    assert_eq!(code, 0);
    let value: Value = serde_json::from_str(&stdout).expect("profile JSON");
    assert_eq!(value["php_version"], "8.4.26");
    assert_eq!(value["sapi"], "apache2handler");
}

#[test]
fn diagnostics_without_architecture_remains_unconfirmed() {
    let path = fixture("http_response.txt").to_string_lossy().into_owned();
    let (code, stdout, _) = output(&["diagnostics", "--fixture", &path, "--json"]);
    assert_eq!(code, 1);
    let report: Value = serde_json::from_str(&stdout).expect("diagnostics JSON");
    assert_eq!(report["verdict"], "insufficient_evidence");
    assert_eq!(report["fingerprint"]["php_version"], "8.4.26");
    assert!(report["uncertainty"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.as_str().is_some_and(|s| s.contains("architecture")))
    }));
}

#[test]
fn diagnostics_with_explicit_architecture_matches_a_profile() {
    let path = fixture("http_response.txt").to_string_lossy().into_owned();
    let (code, stdout, _) = output(&[
        "diagnostics",
        "--fixture",
        &path,
        "--arch",
        "amd64",
        "--json",
    ]);
    assert_eq!(code, 0);
    let report: Value = serde_json::from_str(&stdout).expect("diagnostics JSON");
    assert_eq!(report["verdict"], "sufficient_evidence");
    assert!(
        report["compatible_profiles"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    assert!(
        report["fingerprint"]["sapi"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    // The SAPI is still only an assumption even when a profile matches.
    assert!(
        report["assumptions"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
}

#[test]
fn unknown_response_does_not_produce_a_false_positive() {
    let path = fixture("http_response_unknown.txt")
        .to_string_lossy()
        .into_owned();
    let (code, stdout, _) = output(&[
        "diagnostics",
        "--fixture",
        &path,
        "--arch",
        "amd64",
        "--json",
    ]);
    assert_eq!(code, 1);
    let report: Value = serde_json::from_str(&stdout).expect("diagnostics JSON");
    assert_eq!(report["fingerprint"]["php_version"], Value::Null);
    assert!(
        report["compatible_profiles"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
}

#[test]
fn report_export_writes_a_checksummed_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture("http_response.txt").to_string_lossy().into_owned();
    let out = dir.path().join("report.json");
    let out_arg = out.to_string_lossy().into_owned();
    let (code, stdout, stderr) = output(&[
        "report",
        "export",
        "--fixture",
        &path,
        "--arch",
        "amd64",
        "--output",
        &out_arg,
    ]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("sha256"));
    let text = std::fs::read_to_string(&out).expect("report file");
    let value: Value = serde_json::from_str(&text).expect("report JSON");
    assert_eq!(value["schema"], "php2shell-rs/report/1.0");
    assert_eq!(value["diagnostics"]["verdict"], "sufficient_evidence");
}

#[test]
fn laboratory_controls_are_read_only_in_safe_mode() {
    let (code, stdout, _) = output(&["lab", "list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("docker-compose.yml"));

    let (code, _, stderr) = output(&["lab", "up", "docker-compose.yml"]);
    assert_eq!(code, 4);
    assert!(stderr.contains("lab mode") || stderr.contains("explicitly configured"));
}

#[test]
fn non_allowed_targets_are_refused() {
    let (code, _, stderr) = output(&["fingerprint", "--url", "https://example.org/index.php"]);
    assert_eq!(code, 4);
    assert!(stderr.contains("not allowed"));
}

#[tokio::test]
async fn local_mock_lab_supports_fingerprinting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let server = tokio::spawn(async move {
        let _ = php2shell_lab_manager::serve_mock_lab(&address.to_string()).await;
    });
    let client = SafeClient::new(Arc::new(Config::default())).unwrap();
    let mut response = None;
    for _ in 0..50 {
        if let Ok(result) = client.fetch(&format!("http://{address}/index.php")).await {
            response = Some(result);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let response = response.expect("mock lab started");
    let fingerprint = Fingerprinter::analyze(&response);
    assert_eq!(fingerprint.php_version.as_deref(), Some("8.4.26"));
    assert_eq!(fingerprint.sapi.as_deref(), Some("apache2handler"));
    assert!(
        fingerprint
            .uncertainty
            .iter()
            .any(|item| item.contains("Apache does not prove"))
    );
    server.abort();
}

#[test]
fn pad_spec_and_offset_inventory_commands_work() {
    let (code, stdout, stderr) = output(&["calibrate", "pads", "--spec", "4:4x2,31:31x3"]);
    assert_eq!(code, 0, "stderr={stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["stage3_pads"].as_array().unwrap().len(), 5);

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("offsets.md");
    let out_arg = out.to_string_lossy().into_owned();
    let (code, stdout, _) = output(&["offsets", "--dir", "profiles/offsets", "--output", &out_arg]);
    assert_eq!(code, 0, "{stdout}");
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("| PHP | arch | zif_system"));
    assert!(text.contains("8.4.26"));
}

#[test]
fn preconditions_requires_lab_mode() {
    let (code, _, stderr) = output(&[
        "preconditions",
        "--base",
        "http://127.0.0.1:8110",
        "--php-version",
        "8.4.26",
    ]);
    assert_eq!(code, 4);
    assert!(stderr.contains("lab mode") || stderr.contains("explicitly configured"));
}

#[test]
fn fixtures_are_present() {
    assert!(Path::new(&fixture("http_response.txt")).is_file());
    assert!(Path::new(&fixture("http_response_unknown.txt")).is_file());
}
