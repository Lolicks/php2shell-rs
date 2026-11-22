use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use php2shell_calibration::{CalibrationRecord, collect_container_metadata};
use php2shell_config::{Config, Mode};
use php2shell_core::{Architecture, Error, Result};
use php2shell_diagnostics::{DiagnosticReport, Verdict, analyze};
use php2shell_fingerprint::{Fingerprint, Fingerprinter, parse_probe_response};
use php2shell_http_client::{HttpResponse, SafeClient};
use php2shell_inventory::{
    render_json as render_inventory_json, render_table as render_inventory_table,
    rows as inventory_rows,
};
use php2shell_lab_manager::{LabManager, serve_mock_lab};
use php2shell_profiles::{Manifest, ProfileQuery, Registry, validate_profile};
use php2shell_reporting::{Report, render_table as render_report_table, write_report};

use crate::cli::{
    CalibrateAction, Command, Filters, LabAction, OutputFormat, ProfileAction, ReportAction,
};
use crate::{cli, fixture, output};

pub async fn execute(cli: &cli::Cli, config: Config) -> Result<i32> {
    let color = output::color_enabled(config.log.color);
    let quiet = config.log.quiet;

    match &cli.command {
        Command::Version => {
            println!(
                "{} {}",
                output::heading(color, php2shell_core::TOOL_NAME),
                php2shell_core::TOOL_VERSION
            );
            println!("mode: {}", config.mode.as_str());
            println!("TLS verification: {}", config.http.tls_verify);
            println!(
                "allowed targets: loopback plus {} configured entr{}",
                config.allowed_addresses.len(),
                if config.allowed_addresses.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            );
            println!(
                "{}",
                output::muted(
                    color,
                    "standalone Rust tool: no Python runtime and no exploitation features"
                )
            );
            Ok(0)
        }
        Command::Profile { action } => profile_command(action, &config, cli, color, quiet),
        Command::Inventory { filters } => inventory_command(filters, &config, cli),
        Command::Fingerprint { url, fixture: path } => {
            let response = obtain_response(url.as_deref(), path.as_ref(), &config).await?;
            let fingerprint = Fingerprinter::analyze(&response);
            if cli.json || config.log.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fingerprint).map_err(serde_error)?
                );
            } else {
                print!("{}", format_fingerprint(&fingerprint, color));
            }
            Ok(0)
        }
        Command::Diagnostics {
            url,
            fixture: path,
            arch,
        } => {
            let response = obtain_response(url.as_deref(), path.as_ref(), &config).await?;
            let report = build_diagnostics(&response, arch.clone(), &config)?;
            if cli.json || config.log.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(serde_error)?
                );
            } else {
                print!("{}", format_diagnostics(&report, color));
            }
            Ok(exit_for_verdict(report.verdict))
        }
        Command::Lab { action } => lab_command(action, &config, color).await,
        Command::Report { action } => report_command(action, &config, cli, color).await,
        Command::Calibrate { action } => calibrate_command(action, &config, color),
        Command::Elf { file } => {
            let offsets = php2shell_calibration::symbol_offsets(file)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&offsets).map_err(serde_error)?
            );
            Ok(0)
        }
        Command::Tui => {
            let registry = load_registry(&config)?;
            php2shell_tui::run(config, registry)?;
            Ok(0)
        }
    }
}

fn serde_error(error: serde_json::Error) -> Error {
    Error::other(format!("JSON serialisation failed: {error}"))
}

fn load_registry(config: &Config) -> Result<Registry> {
    let manifest = match &config.profiles.manifest {
        Some(path) if path.is_file() => Some(Manifest::load(path)?),
        Some(path) => {
            tracing::warn!("checksum manifest not found: {}", path.display());
            None
        }
        None => None,
    };
    Registry::load_with_manifest(&config.profiles.directory, manifest)
}

fn client(config: &Config) -> Result<SafeClient> {
    SafeClient::new(Arc::new(config.clone()))
}

async fn obtain_response(
    url: Option<&str>,
    fixture: Option<&PathBuf>,
    config: &Config,
) -> Result<HttpResponse> {
    match (url, fixture) {
        (Some(url), None) => client(config)?.fetch(url).await,
        (None, Some(path)) => {
            let text = std::fs::read_to_string(path).map_err(|err| Error::io(path, err))?;
            fixture::parse_fixture(&text)
        }
        (None, None) => Err(Error::Config(
            "provide --url or --fixture for this command".into(),
        )),
        (Some(_), Some(_)) => Err(Error::Config(
            "--url and --fixture are mutually exclusive".into(),
        )),
    }
}

fn build_diagnostics(
    response: &HttpResponse,
    arch: Option<Architecture>,
    config: &Config,
) -> Result<DiagnosticReport> {
    let registry = load_registry(config)?;
    let fingerprint = Fingerprinter::analyze(response);
    Ok(analyze(
        &fingerprint,
        &registry,
        arch.as_ref(),
        Some(parse_probe_response(&response.body)),
    ))
}

fn exit_for_verdict(verdict: Verdict) -> i32 {
    match verdict {
        Verdict::InsufficientEvidence => 1,
        _ => 0,
    }
}

fn query(filters: &Filters) -> ProfileQuery {
    ProfileQuery {
        search: filters.search.clone(),
        php_version: filters.php_version.clone(),
        branch: filters.branch.clone(),
        sapi: filters.sapi.clone(),
        arch: filters.arch.clone(),
        status: filters.status.clone(),
        rce: filters.rce,
        verified: filters.rce,
    }
}

fn profile_command(
    action: &ProfileAction,
    config: &Config,
    cli: &cli::Cli,
    color: bool,
    quiet: bool,
) -> Result<i32> {
    let registry = load_registry(config)?;
    match action {
        ProfileAction::List { filters } => {
            let profiles = registry.filter(&query(filters));
            if cli.json || config.log.json {
                let values: Vec<serde_json::Value> = profiles
                    .iter()
                    .map(|profile| {
                        serde_json::json!({
                            "id": profile.id(),
                            "php_version": profile.string("php_version"),
                            "sapi": profile.sapi().as_str(),
                            "arch": profile.arch().as_str(),
                            "status": profile.status(),
                            "rce": profile.rce(),
                            "file": profile.source,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&values).map_err(serde_error)?
                );
            } else {
                let rows = inventory_rows(profiles);
                println!("{}", render_inventory_table(&rows));
            }
            Ok(0)
        }
        ProfileAction::Show { id } => {
            let profile = registry
                .find(id)
                .ok_or_else(|| Error::ProfileNotFound(id.clone()))?;
            println!("{}", profile.export_json());
            Ok(0)
        }
        ProfileAction::Validate => {
            let bar = output::progress("validating profiles", quiet);
            let mut errors = 0usize;
            let mut warnings = 0usize;
            for issue in &registry.issues {
                match issue.severity {
                    php2shell_profiles::Severity::Error => {
                        errors += 1;
                        println!(
                            "{}",
                            output::failure(
                                color,
                                &format!("ERROR {}: {}", issue.pointer, issue.message)
                            )
                        );
                    }
                    php2shell_profiles::Severity::Warning => {
                        warnings += 1;
                        println!(
                            "{}",
                            output::warning(
                                color,
                                &format!("WARN  {}: {}", issue.pointer, issue.message)
                            )
                        );
                    }
                }
            }
            bar.finish_with_message("validation finished");
            println!(
                "{}",
                output::success(
                    color,
                    &format!(
                        "{} profiles: {} error(s), {} warning(s)",
                        registry.profiles.len(),
                        errors,
                        warnings
                    )
                )
            );
            Ok(if errors > 0 { 2 } else { 0 })
        }
        ProfileAction::Import { file } => {
            let bytes = std::fs::read(file).map_err(|err| Error::io(file, err))?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|err| Error::json(file, err))?;
            let issues = validate_profile(&value, None);
            let errors: Vec<_> = issues
                .iter()
                .filter(|issue| issue.severity == php2shell_profiles::Severity::Error)
                .collect();
            if !errors.is_empty() {
                for issue in errors {
                    eprintln!(
                        "{}",
                        output::failure(color, &format!("{}: {}", issue.pointer, issue.message))
                    );
                }
                return Ok(2);
            }
            let name = value
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::Profile {
                    id: file.display().to_string(),
                    message: "missing name".into(),
                })?;
            let safe: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || "-_".contains(c) {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            let target = config.profiles.directory.join(format!("{safe}.json"));
            if target.exists() {
                println!(
                    "{}",
                    output::muted(color, &format!("already present: {}", target.display()))
                );
                return Ok(0);
            }
            std::fs::create_dir_all(&config.profiles.directory)
                .map_err(|err| Error::io(&config.profiles.directory, err))?;
            let mut handle = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(|err| Error::io(&target, err))?;
            handle
                .write_all(&bytes)
                .map_err(|err| Error::io(&target, err))?;
            println!(
                "{}",
                output::success(color, &format!("imported {}", target.display()))
            );
            Ok(0)
        }
        ProfileAction::Export { id, output: path } => {
            let profile = registry
                .find(id)
                .ok_or_else(|| Error::ProfileNotFound(id.clone()))?;
            let mut handle = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|err| Error::io(path, err))?;
            handle
                .write_all(profile.export_json().as_bytes())
                .map_err(|err| Error::io(path, err))?;
            println!(
                "{}",
                output::success(color, &format!("exported {}", path.display()))
            );
            Ok(0)
        }
    }
}

fn inventory_command(filters: &Filters, config: &Config, cli: &cli::Cli) -> Result<i32> {
    let registry = load_registry(config)?;
    let profiles = registry.filter(&query(filters));
    let rows = inventory_rows(profiles);
    if cli.json || config.log.json {
        println!("{}", render_inventory_json(&rows));
    } else {
        println!("{}", render_inventory_table(&rows));
    }
    Ok(0)
}

fn format_fingerprint(fingerprint: &Fingerprint, color: bool) -> String {
    let mut out = String::new();
    out.push_str(&output::heading(color, "Fingerprint (passive observation)"));
    out.push('\n');
    out.push_str(&format!("target            : {}\n", fingerprint.target));
    out.push_str(&format!(
        "http status       : {}\n",
        fingerprint.http_status
    ));
    out.push_str(&format!(
        "php version       : {}\n",
        fingerprint.php_version.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "server software   : {}\n",
        fingerprint.server_software.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "sapi (inferred)   : {}\n",
        fingerprint.sapi.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "os hint           : {}\n",
        fingerprint.os_hint.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "completeness      : {}%\n",
        fingerprint.completeness
    ));
    out.push_str("\nconfirmed facts:\n");
    for fact in fingerprint.confident_facts() {
        out.push_str(&format!(
            "  + {}: {} ({})\n",
            fact.kind.as_str_name(),
            fact.value,
            fact.source
        ));
    }
    out.push_str("\nunconfirmed assumptions:\n");
    for assumption in fingerprint.assumptions() {
        out.push_str(&format!(
            "  ? {}: {} ({}, {})\n",
            assumption.kind.as_str_name(),
            assumption.value,
            assumption.source,
            assumption.confidence
        ));
    }
    out.push_str("\nuncertainty:\n");
    for item in &fingerprint.uncertainty {
        out.push_str(&format!("  - {item}\n"));
    }
    out
}

trait KindName {
    fn as_str_name(&self) -> &'static str;
}
impl KindName for php2shell_fingerprint::EvidenceKind {
    fn as_str_name(&self) -> &'static str {
        use php2shell_fingerprint::EvidenceKind;
        match self {
            EvidenceKind::ServerSoftware => "server",
            EvidenceKind::PhpVersion => "php_version",
            EvidenceKind::Sapi => "sapi",
            EvidenceKind::OsHint => "os_hint",
        }
    }
}

fn format_diagnostics(report: &DiagnosticReport, color: bool) -> String {
    let mut out = String::new();
    out.push_str(&output::heading(color, "Diagnostic result"));
    out.push('\n');
    out.push_str(&format!("target             : {}\n", report.target));
    out.push_str(&format!(
        "verdict            : {}\n",
        verdict_text(report.verdict)
    ));
    out.push_str(&format!(
        "php version        : {}\n",
        report
            .fingerprint
            .php_version
            .as_deref()
            .unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "sapi (inferred)    : {}\n",
        report.fingerprint.sapi.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "completeness       : {}%\n",
        report.fingerprint.completeness
    ));
    out.push_str(&format!(
        "compatible         : {}\n",
        report.compatible_profiles.len()
    ));
    out.push_str(&format!(
        "incompatible       : {}\n",
        report.incompatible_profiles.len()
    ));
    out.push_str("\ncompatible profiles:\n");
    for profile in &report.compatible_profiles {
        out.push_str(&format!(
            "  + {} ({}, {}) - {}\n",
            profile.id, profile.php_version, profile.arch, profile.reason
        ));
    }
    if report.compatible_profiles.is_empty() {
        out.push_str("  (none)\n");
    }
    out.push_str("\nuncertainty:\n");
    for item in &report.uncertainty {
        out.push_str(&format!("  ? {item}\n"));
    }
    out.push_str("\nrecommendations:\n");
    for item in &report.recommendations {
        out.push_str(&format!("  * {item}\n"));
    }
    out
}

fn verdict_text(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::SufficientEvidence => "sufficient evidence",
        Verdict::InsufficientEvidence => "insufficient evidence",
        Verdict::PatchedVersion => "patched version",
    }
}

async fn lab_command(action: &LabAction, config: &Config, color: bool) -> Result<i32> {
    let manager = LabManager::new(Arc::new(config.clone()));
    match action {
        LabAction::List => {
            let labs = manager.discover()?;
            if labs.is_empty() {
                println!("no compose files configured");
            }
            for lab in labs {
                println!(
                    "{} {} services={:?} ports={:?}",
                    output::heading(color, &lab.name),
                    lab.path.display(),
                    lab.services,
                    lab.ports
                );
            }
            Ok(0)
        }
        LabAction::Status { name } => {
            println!("{}", manager.status(name)?);
            Ok(0)
        }
        LabAction::Up { name } => {
            println!("{}", manager.up(name)?);
            Ok(0)
        }
        LabAction::Down { name } => {
            println!("{}", manager.down(name)?);
            Ok(0)
        }
        LabAction::Logs { name, tail } => {
            println!("{}", manager.logs(name, *tail)?);
            Ok(0)
        }
        LabAction::Clean => {
            let removed = manager.clean()?;
            for path in removed {
                println!("removed {}", path.display());
            }
            Ok(0)
        }
        LabAction::Serve { addr } => {
            println!(
                "{}",
                output::muted(color, "local mock laboratory; Ctrl-C to stop")
            );
            serve_mock_lab(addr).await?;
            Ok(0)
        }
    }
}

async fn report_command(
    action: &ReportAction,
    config: &Config,
    cli: &cli::Cli,
    color: bool,
) -> Result<i32> {
    match action {
        ReportAction::Export {
            url,
            fixture: path,
            arch,
            format,
            output: destination,
        } => {
            let response = obtain_response(url.as_deref(), path.as_ref(), config).await?;
            let diagnostics = build_diagnostics(&response, arch.clone(), config)?;
            let report = Report::new(config, diagnostics, Vec::new());
            match format {
                OutputFormat::Table => {
                    let text = render_report_table(&report);
                    if let Some(destination) = destination {
                        write_text(destination, &text)?;
                        println!(
                            "{}",
                            output::success(color, &format!("wrote {}", destination.display()))
                        );
                    } else {
                        print!("{text}");
                    }
                }
                OutputFormat::Json => {
                    let json = report.to_json()?;
                    if let Some(destination) = destination {
                        let checksum = write_report(&report, destination)?;
                        println!(
                            "{}",
                            output::success(
                                color,
                                &format!("wrote {} (sha256 {checksum})", destination.display())
                            )
                        );
                    } else {
                        println!("{json}");
                    }
                }
            }
            Ok(0)
        }
        ReportAction::List => {
            let dir = &config.report.output_dir;
            let mut files = Vec::new();
            if dir.is_dir() {
                for entry in std::fs::read_dir(dir).map_err(|err| Error::io(dir, err))? {
                    let entry = entry.map_err(|err| Error::io(dir, err))?;
                    if entry.path().extension().and_then(|e| e.to_str()) == Some("json") {
                        files.push(entry.path());
                    }
                }
            }
            files.sort();
            if cli.json || config.log.json {
                let names: Vec<String> = files
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&names).map_err(serde_error)?
                );
            } else {
                for path in files {
                    println!("{}", path.display());
                }
            }
            Ok(0)
        }
    }
}

fn write_text(path: &PathBuf, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
    }
    std::fs::write(path, text).map_err(|err| Error::io(path, err))
}

fn calibrate_command(action: &CalibrateAction, config: &Config, color: bool) -> Result<i32> {
    if config.mode != Mode::Lab && matches!(action, CalibrateAction::Metadata { .. }) {
        return Err(Error::LabOnly);
    }
    let record = match action {
        CalibrateAction::Metadata {
            container,
            artifact,
        } => {
            let metadata = collect_container_metadata(container, &config.lab.docker_command)?;
            let mut record = CalibrationRecord::new(
                &metadata.php_version,
                "apache2handler",
                "debian",
                &metadata.architecture,
                &metadata.container,
            );
            record.notes.push(format!(
                "collected memory_limit={} bytes, display_errors={}, session.upload_progress={}, workers={}",
                metadata.memory_limit_bytes,
                metadata.display_errors,
                metadata.session_upload_progress,
                metadata.workers
            ));
            if let Some(artifact) = artifact {
                record.artifact_sha256 = Some(php2shell_core::sha256::hash_file(artifact)?);
            }
            record
        }
        CalibrateAction::Record {
            php_version,
            sapi,
            os,
            arch,
            build,
            artifact,
            output,
        } => {
            let mut record = CalibrationRecord::new(php_version, sapi, os, arch, build);
            if let Some(artifact) = artifact {
                record.artifact_sha256 = Some(php2shell_core::sha256::hash_file(artifact)?);
            }
            if let Some(output) = output {
                write_text(output, &record.to_json()?)?;
                println!(
                    "{}",
                    output::success(color, &format!("wrote {}", output.display()))
                );
                return Ok(0);
            }
            record
        }
    };
    println!("{}", record.to_json()?);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_exit_codes_follow_the_diagnostic_contract() {
        assert_eq!(exit_for_verdict(Verdict::SufficientEvidence), 0);
        assert_eq!(exit_for_verdict(Verdict::PatchedVersion), 0);
        assert_eq!(exit_for_verdict(Verdict::InsufficientEvidence), 1);
    }

    #[test]
    fn filters_map_to_the_registry_query() {
        let filters = Filters {
            php_version: Some("8.4.26".into()),
            sapi: Some("fpm".into()),
            rce: Some(true),
            ..Default::default()
        };
        let query = query(&filters);
        assert_eq!(query.php_version.as_deref(), Some("8.4.26"));
        assert_eq!(query.sapi.as_deref(), Some("fpm"));
        assert_eq!(query.rce, Some(true));
    }
}
