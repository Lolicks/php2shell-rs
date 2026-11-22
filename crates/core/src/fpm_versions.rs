//! Full port of the upstream `php2shell_fpm_versions.py` registry.
//!
//! This is classification metadata and source inspection only. It never
//! decides that a system is exploitable.

use std::io::Read;
use std::path::Path;
use std::process::Command;

use crate::error::{Error, Result};
use crate::types::Version;

const VERSION_MARKER: &str = "php_basic_early_rinit";
const CANCEL_DECODE_MARKER: &str = "php_session_cancel_decode";
const BASIC_FUNCTIONS: &str = "ext/standard/basic_functions.c";
const SESSION_C: &str = "ext/session/session.c";
const SLOT_BLOCK: u32 = 100;
const SLOT_BASE_HTTP: u32 = 8200;
const SLOT_BASE_FPM: u32 = 9200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchMeta {
    pub fixed_in: Option<&'static str>,
    pub last_release: &'static str,
    pub slot: u32,
}

pub const BRANCHES: &[(&str, BranchMeta)] = &[
    (
        "7.2",
        BranchMeta {
            fixed_in: None,
            last_release: "7.2.34",
            slot: 0,
        },
    ),
    (
        "7.4",
        BranchMeta {
            fixed_in: None,
            last_release: "7.4.33",
            slot: 1,
        },
    ),
    (
        "8.2",
        BranchMeta {
            fixed_in: Some("8.2.35"),
            last_release: "8.2.34",
            slot: 2,
        },
    ),
    (
        "8.3",
        BranchMeta {
            fixed_in: Some("8.3.36"),
            last_release: "8.3.35",
            slot: 3,
        },
    ),
    (
        "8.4",
        BranchMeta {
            fixed_in: Some("8.4.27"),
            last_release: "8.4.26",
            slot: 4,
        },
    ),
    (
        "8.0",
        BranchMeta {
            fixed_in: None,
            last_release: "8.0.30",
            slot: 6,
        },
    ),
    (
        "8.1",
        BranchMeta {
            fixed_in: None,
            last_release: "8.1.33",
            slot: 7,
        },
    ),
];

pub const EOL_BRANCHES: &[&str] = &["5.x", "7.x", "8.0", "8.1"];
pub const LEGACY_PORTS: &[(&str, [u16; 4])] = &[
    ("8.4.25", [8130, 8131, 9021, 9022]),
    ("8.4.26", [8110, 8111, 9001, 9002]),
    ("8.4.27", [8120, 8121, 9011, 9012]),
];

pub fn parse(version: &str) -> Result<Version> {
    Version::parse(version).ok_or_else(|| Error::Config(format!("unknown PHP version: {version}")))
}

pub fn branch_of(version: &str) -> Result<String> {
    Ok(parse(version)?.branch())
}

pub fn known_branch(version: &str) -> bool {
    Version::parse(version).is_some_and(|version| meta(&version.branch()).is_some())
}

fn meta(branch: &str) -> Option<BranchMeta> {
    BRANCHES
        .iter()
        .find(|(name, _)| *name == branch)
        .map(|(_, meta)| *meta)
}

pub fn fixed_in(version: &str) -> Result<Option<Version>> {
    let version = parse(version)?;
    Ok(meta(&version.branch())
        .and_then(|meta| meta.fixed_in)
        .and_then(Version::parse))
}

pub fn is_vulnerable(version: &str) -> Result<bool> {
    let version = parse(version)?;
    match fixed_in(&version.to_string())? {
        Some(fixed) => Ok(version < fixed),
        None => Ok(true),
    }
}

pub fn is_fixed(version: &str) -> Result<bool> {
    Ok(!is_vulnerable(version)?)
}

/// All affected patch releases of a branch, matching upstream ordering.
pub fn affected_versions() -> Vec<String> {
    let mut branches: Vec<&str> = BRANCHES.iter().map(|(name, _)| *name).collect();
    branches.sort_unstable();
    let mut out = Vec::new();
    for branch in branches {
        let Some(meta) = meta(branch) else { continue };
        let last = parse(meta.last_release).unwrap_or(Version::new(0, 0, 0));
        if meta.fixed_in.is_none() {
            out.push(meta.last_release.to_owned());
        } else {
            for patch in 0..=last.patch {
                out.push(format!("{}.{}", branch, patch));
            }
        }
    }
    out
}

/// Deterministic port map from the upstream registry.
pub fn ports_for(version: &str) -> Result<[u16; 4]> {
    if let Some((_, ports)) = LEGACY_PORTS.iter().find(|(name, _)| *name == version) {
        return Ok(*ports);
    }
    let version = parse(version)?;
    let meta = meta(&version.branch())
        .ok_or_else(|| Error::Config(format!("unknown branch for {version}")))?;
    let slot = meta.slot * SLOT_BLOCK + version.patch * 2;
    Ok([
        (SLOT_BASE_HTTP + slot) as u16,
        (SLOT_BASE_HTTP + slot + 1) as u16,
        (SLOT_BASE_FPM + slot) as u16,
        (SLOT_BASE_FPM + slot + 1) as u16,
    ])
}

/// The stale-state chain applies from PHP 7.4 onward.
pub fn chain_applies(version: &str) -> Result<bool> {
    let version = parse(version)?;
    Ok((version.major, version.minor) >= (7, 4))
}

fn read_source_member(source: &Path, wanted: &str) -> Result<String> {
    if source.is_dir() {
        let file = source.join(wanted);
        return std::fs::read_to_string(&file).map_err(|err| Error::io(&file, err));
    }
    let file = std::fs::File::open(source).map_err(|err| Error::io(source, err))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive
        .entries()
        .map_err(|err| Error::other(format!("reading tar: {err}")))?
    {
        let mut entry = entry.map_err(|err| Error::other(format!("reading tar entry: {err}")))?;
        let path = entry
            .path()
            .map_err(|err| Error::other(format!("tar entry path: {err}")))?;
        if path.to_string_lossy().ends_with(wanted) {
            let mut text = String::new();
            entry
                .read_to_string(&mut text)
                .map_err(|err| Error::other(format!("reading {wanted} from tar: {err}")))?;
            return Ok(text);
        }
    }
    Err(Error::Config(format!(
        "{wanted} not found in source archive"
    )))
}

/// Checks for the upstream fix marker in a PHP source directory or tarball.
pub fn source_is_fixed(source: &Path) -> Result<bool> {
    Ok(read_source_member(source, BASIC_FUNCTIONS)?.contains(VERSION_MARKER))
}

pub fn has_session_cancel_decode(source: &Path) -> Result<bool> {
    Ok(read_source_member(source, SESSION_C)?.contains(CANCEL_DECODE_MARKER))
}

/// Runs an explicitly supplied PHP binary with `-v` and parses its banner.
pub fn build_status(binary: &Path) -> Result<Version> {
    let output = Command::new(binary)
        .arg("-v")
        .output()
        .map_err(|err| Error::other(format!("running {}: {err}", binary.display())))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let start = text
        .find("PHP ")
        .ok_or_else(|| Error::Config("no PHP banner in binary output".into()))?
        + 4;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    parse(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_upstream_examples() {
        assert_eq!(branch_of("8.4.26").unwrap(), "8.4");
        assert!(known_branch("8.4.26"));
        assert!(!known_branch("9.0.0"));
        assert_eq!(
            fixed_in("8.4.26").unwrap(),
            Some(Version::parse("8.4.27").unwrap())
        );
        assert!(is_vulnerable("8.4.26").unwrap());
        assert!(is_fixed("8.4.27").unwrap());
        assert!(is_vulnerable("7.4.33").unwrap());
        assert!(!chain_applies("7.2.34").unwrap());
        assert!(chain_applies("7.4.33").unwrap());
    }

    #[test]
    fn ports_are_deterministic() {
        assert_eq!(ports_for("8.4.26").unwrap(), [8110, 8111, 9001, 9002]);
        assert_eq!(ports_for("8.4.25").unwrap(), [8130, 8131, 9021, 9022]);
        let a = ports_for("8.4.10").unwrap();
        let b = ports_for("8.4.11").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn source_markers_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ext/standard")).unwrap();
        std::fs::create_dir_all(dir.path().join("ext/session")).unwrap();
        std::fs::write(
            dir.path().join(BASIC_FUNCTIONS),
            "void php_basic_early_rinit(void) {}",
        )
        .unwrap();
        std::fs::write(dir.path().join(SESSION_C), "php_session_cancel_decode(x);").unwrap();
        assert!(source_is_fixed(dir.path()).unwrap());
        assert!(has_session_cancel_decode(dir.path()).unwrap());
    }

    #[test]
    fn full_affected_matrix_is_generated() {
        let versions = affected_versions();
        assert!(versions.contains(&"8.4.0".to_owned()));
        assert!(versions.contains(&"8.4.26".to_owned()));
        assert!(versions.contains(&"7.4.33".to_owned()));
        assert!(!versions.contains(&"8.4.27".to_owned()));
    }
}
