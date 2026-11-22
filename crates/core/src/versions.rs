//! Version registry ported from the upstream Python tooling.
//!
//! This is classification metadata only. It never decides that a system is
//! exploitable; it only reports which releases are known to be patched.

use crate::types::Version;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    Vulnerable,
    VulnerableEol,
    Patched,
    OutsideMatrix,
    Unknown,
}

impl VersionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::VulnerableEol => "vulnerable_eol",
            Self::Patched => "patched",
            Self::OutsideMatrix => "outside_matrix",
            Self::Unknown => "unknown",
        }
    }
}

/// First patched release per supported branch (upstream `FIXED` table).
pub const FIXED_RELEASES: &[(&str, &str)] = &[
    ("8.2", "8.2.35"),
    ("8.3", "8.3.36"),
    ("8.4", "8.4.27"),
    ("8.5", "8.5.12"),
];

/// Branches with no official fix at the time of the upstream audit.
pub const EOL_BRANCHES: &[&str] = &[
    "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1",
];

pub fn fixed_in(version: &Version) -> Option<Version> {
    let branch = version.branch();
    FIXED_RELEASES
        .iter()
        .find(|(b, _)| *b == branch)
        .and_then(|(_, v)| Version::parse(v))
}

pub fn is_eol_branch(branch: &str) -> bool {
    EOL_BRANCHES.contains(&branch)
}

/// Matches the upstream `classify()` semantics: strict three-component parse,
/// unknown branches return `None` for both `fixed` and `patched`.
pub fn classify(value: &str) -> Option<Classification> {
    let version = Version::parse(value)?;
    let branch = version.branch();
    let fixed = fixed_in(&version);
    let patched = fixed.as_ref().map(|f| &version >= f);
    let status = match (&fixed, is_eol_branch(&branch)) {
        (Some(f), _) if &version >= f => VersionStatus::Patched,
        (Some(_), _) => VersionStatus::Vulnerable,
        (None, true) => VersionStatus::VulnerableEol,
        (None, false) => VersionStatus::OutsideMatrix,
    };
    Some(Classification {
        version,
        branch,
        fixed,
        patched,
        status,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    pub version: Version,
    pub branch: String,
    pub fixed: Option<Version>,
    pub patched: Option<bool>,
    pub status: VersionStatus,
}

impl Classification {
    pub fn is_vulnerable(&self) -> bool {
        matches!(
            self.status,
            VersionStatus::Vulnerable | VersionStatus::VulnerableEol
        )
    }
}

/// Enumerates the affected patch releases of a branch. Unfixed EOL branches
/// contribute their last known release only (the upstream registry behaviour).
pub fn affected_versions(branch: &str, last_release: &str) -> Vec<Version> {
    let Some(last) = Version::parse(last_release) else {
        return Vec::new();
    };
    if last.branch() != branch {
        return Vec::new();
    }
    if fixed_in(&last).is_none() {
        return vec![last];
    }
    (0..=last.patch)
        .map(|patch| Version::new(last.major, last.minor, patch))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_classification_examples() {
        let c = classify("8.5.11").unwrap();
        assert_eq!(c.branch, "8.5");
        assert_eq!(c.fixed, Some(Version::parse("8.5.12").unwrap()));
        assert_eq!(c.patched, Some(false));

        let c = classify("8.4.27").unwrap();
        assert_eq!(c.status, VersionStatus::Patched);

        let c = classify("7.4.33").unwrap();
        assert_eq!(c.fixed, None);
        assert_eq!(c.patched, None);
        assert_eq!(c.status, VersionStatus::VulnerableEol);

        assert!(classify("not-a-version").is_none());
    }

    #[test]
    fn affected_versions_cover_the_patched_branches() {
        assert_eq!(affected_versions("8.4", "8.4.26").len(), 27);
        assert_eq!(
            affected_versions("7.4", "7.4.33"),
            vec![Version::parse("7.4.33").unwrap()]
        );
    }
}
