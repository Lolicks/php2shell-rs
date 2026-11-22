//! Passive metadata collection from an explicitly named local lab container
//! and from ELF files. All external commands use fixed argv arrays: no shell
//! interpolation and no remote targets.

use std::process::Command;
use std::time::Duration;

use php2shell_core::{Error, Result};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ContainerMetadata {
    pub container: String,
    pub php_version: String,
    pub memory_limit_bytes: i64,
    pub display_errors: String,
    pub session_upload_progress: String,
    pub workers: usize,
    pub architecture: String,
}

fn run(argv: &[&str], timeout: Duration) -> Result<String> {
    let child = Command::new(argv[0])
        .args(&argv[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| Error::other(format!("cannot start {}: {err}", argv[0])))?;
    let output = child
        .wait_with_output()
        .map_err(|err| Error::other(format!("waiting for {}: {err}", argv[0])))?;
    let _ = timeout; // std::process has no deadline API; lab command set is fixed.
    if !output.status.success() {
        return Err(Error::other(format!(
            "{} exited with status {}",
            argv[0], output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn valid_container(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// Parses a PHP ini-style memory limit into bytes. `-1` means unlimited.
pub fn parse_memory_limit(text: &str) -> Option<i64> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("memory_limit")? + "memory_limit".len();
    let rest = &lower[start..];
    let rest = rest
        .trim_start()
        .strip_prefix("=>")
        .or_else(|| rest.trim_start().strip_prefix('='))?;
    let value = rest.trim_start();
    if let Some(negative) = value.strip_prefix('-')
        && negative.starts_with('1')
    {
        return Some(-1);
    }
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let digits = &value[..split];
    let number = digits.parse::<i64>().ok()?;
    if number == 0 {
        return Some(-1);
    }
    let multiplier = value[split..].trim_start().chars().next();
    let factor = match multiplier {
        None | Some(';') | Some('\n') => 1,
        Some('k') => 1024,
        Some('m') => 1024 * 1024,
        Some('g') => 1024 * 1024 * 1024,
        _ => return None,
    };
    number.checked_mul(factor)
}

pub fn collect_container_metadata(container: &str, docker: &str) -> Result<ContainerMetadata> {
    if !valid_container(container) {
        return Err(Error::Config(format!(
            "invalid lab container name: {container}"
        )));
    }
    if !valid_container(docker) && !docker.starts_with('/') {
        return Err(Error::Config("invalid docker command".into()));
    }
    let timeout = Duration::from_secs(30);
    let info = run(&[docker, "exec", container, "php", "-i"], timeout)?;
    let uname = run(&[docker, "exec", container, "uname", "-m"], timeout)?;

    let version = info
        .lines()
        .find(|line| line.trim_start().starts_with("PHP Version =>"))
        .and_then(|line| line.split("=>").nth(1))
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let memory_limit_bytes = info
        .lines()
        .find(|line| line.contains("memory_limit"))
        .and_then(parse_memory_limit)
        .unwrap_or(-1);
    let display_errors = extract_ini(&info, "display_errors");
    let session_upload_progress = extract_ini(&info, "session.upload_progress.enabled");
    let workers = info
        .lines()
        .filter(|line| line.contains("apache2handler"))
        .count()
        .max(1);

    Ok(ContainerMetadata {
        container: container.to_owned(),
        php_version: version,
        memory_limit_bytes,
        display_errors,
        session_upload_progress,
        workers,
        architecture: php2shell_core::Architecture::from_uname(&uname)
            .as_str()
            .to_owned(),
    })
}

fn extract_ini(info: &str, key: &str) -> String {
    info.lines()
        .find(|line| line.trim_start().starts_with(key))
        .and_then(|line| line.split("=>").nth(1))
        .map(str::trim)
        .unwrap_or("unknown")
        .to_owned()
}

pub fn symbol_offsets(path: &std::path::Path) -> Result<serde_json::Value> {
    let bytes = std::fs::read(path).map_err(|err| Error::io(path, err))?;
    let info = php2shell_binary_parser::parse_elf64(&bytes)
        .map_err(|err| Error::other(format!("cannot parse {}: {err}", path.display())))?;
    let symbols: Vec<serde_json::Value> = info
        .symbols
        .iter()
        .map(|symbol| {
            serde_json::json!({
                "name": symbol.name,
                "value": format!("0x{:x}", symbol.value),
                "virtual_address": symbol.virtual_address.map(|value| format!("0x{value:x}")),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "file": path.to_string_lossy(),
        "bias": format!("0x{:x}", info.bias),
        "symbols": symbols,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_php_memory_limit_units() {
        assert_eq!(
            parse_memory_limit("memory_limit => 8M\n"),
            Some(8 * 1024 * 1024)
        );
        assert_eq!(
            parse_memory_limit("memory_limit => 512K\n"),
            Some(512 * 1024)
        );
        assert_eq!(parse_memory_limit("memory_limit => -1\n"), Some(-1));
        assert_eq!(parse_memory_limit("memory_limit => 0\n"), Some(-1));
        assert_eq!(parse_memory_limit("unrelated => 8M\n"), None);
    }

    #[test]
    fn rejects_unsafe_container_names() {
        assert!(collect_container_metadata("p2s-lab-8426; id", "docker").is_err());
        assert!(collect_container_metadata("", "docker").is_err());
    }
}
