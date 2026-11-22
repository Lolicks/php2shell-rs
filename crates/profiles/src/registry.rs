use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use php2shell_core::{Architecture, Error, Result};
use serde_json::Value;

use crate::manifest::Manifest;
use crate::model::Profile;
use crate::validation::{Issue, Severity, validate_registry};

const SKIP_FILES: &[&str] = &["schema.json", "fpm-schema.json", "manifest.json"];

#[derive(Clone, Debug, Default)]
pub struct ProfileQuery {
    pub search: Option<String>,
    pub php_version: Option<String>,
    pub branch: Option<String>,
    pub sapi: Option<String>,
    pub arch: Option<String>,
    pub status: Option<String>,
    pub rce: Option<bool>,
    pub verified: Option<bool>,
}

impl ProfileQuery {
    pub fn matches(&self, profile: &Profile) -> bool {
        if let Some(text) = &self.search {
            let haystack = format!(
                "{} {} {} {}",
                profile.id(),
                profile.string("php_version").unwrap_or_default(),
                profile.status(),
                profile.source.display()
            )
            .to_ascii_lowercase();
            if !haystack.contains(&text.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(value) = &self.php_version
            && profile.string("php_version").unwrap_or_default() != value
        {
            return false;
        }
        if let Some(value) = &self.branch
            && profile.branch() != value
        {
            return false;
        }
        if let Some(value) = &self.sapi
            && profile.sapi().as_str() != value
        {
            return false;
        }
        if let Some(value) = &self.arch
            && profile.arch().as_str() != value
        {
            return false;
        }
        if let Some(value) = &self.status
            && !profile
                .status()
                .to_ascii_lowercase()
                .contains(&value.to_ascii_lowercase())
        {
            return false;
        }
        if let Some(value) = self.rce
            && profile.rce() != value
        {
            return false;
        }
        if let Some(value) = self.verified
            && profile.verified() != value
        {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug)]
pub struct Registry {
    pub root: PathBuf,
    pub profiles: Vec<Profile>,
    pub issues: Vec<Issue>,
    pub manifest: Option<Manifest>,
}

impl Registry {
    /// Loads profiles from the upstream flat `profiles/` directory and from
    /// the optional `profiles/apache/` and `profiles/fpm/` subdirectories.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.is_file() {
            Some(Manifest::load(&manifest_path)?)
        } else {
            None
        };
        Self::load_with_manifest(root, manifest)
    }

    pub fn load_with_manifest(root: impl AsRef<Path>, manifest: Option<Manifest>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(Error::Config(format!(
                "profile directory does not exist: {}",
                root.display()
            )));
        }

        let mut issues = Vec::new();
        let mut profiles = Vec::new();
        let mut seen_paths = HashSet::new();

        for subdir in [
            PathBuf::new(),
            PathBuf::from("apache"),
            PathBuf::from("fpm"),
        ] {
            let dir = root.join(&subdir);
            if !dir.is_dir() {
                continue;
            }
            let entries = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
            for entry in entries {
                let entry = entry.map_err(|e| Error::io(&dir, e))?;
                let path = entry.path();
                if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if SKIP_FILES.contains(&name) {
                    continue;
                }
                let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                if !seen_paths.insert(canonical) {
                    continue;
                }
                let text = match fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(err) => {
                        issues.push(Issue::error(
                            path.display().to_string(),
                            format!("cannot read profile: {err}"),
                        ));
                        continue;
                    }
                };
                let value: Value = match serde_json::from_str(&text) {
                    Ok(value) => value,
                    Err(err) => {
                        issues.push(Issue::error(
                            path.display().to_string(),
                            format!("invalid JSON: {err}"),
                        ));
                        continue;
                    }
                };
                // Keep paths relative to the repository root (matching the
                // upstream inventory), falling back to the profile directory
                // for temporary/external registries.
                let repo_root = root.parent().unwrap_or(&root);
                let relative = path
                    .strip_prefix(repo_root)
                    .or_else(|_| path.strip_prefix(&root))
                    .unwrap_or(&path)
                    .to_path_buf();
                profiles.push(Profile::new(value, relative));
            }
        }

        profiles.sort_by(|a, b| a.source.cmp(&b.source));
        issues.extend(validate_registry(&profiles));

        if let Some(manifest) = &manifest {
            let problems = manifest.verify(&root);
            for (path, message) in problems {
                issues.push(Issue {
                    pointer: path,
                    message,
                    severity: Severity::Warning,
                });
            }
        } else {
            issues.push(Issue::warning(
                "manifest.json",
                "no profile checksum manifest found; provenance cannot be verified",
            ));
        }

        Ok(Self {
            root,
            profiles,
            issues,
            manifest,
        })
    }

    pub fn find(&self, id: &str) -> Option<&Profile> {
        self.profiles
            .iter()
            .find(|profile| profile.id() == id || profile.source.to_string_lossy() == id)
    }

    pub fn filter(&self, query: &ProfileQuery) -> Vec<&Profile> {
        self.profiles
            .iter()
            .filter(|profile| query.matches(profile))
            .collect()
    }

    /// Deterministic profile selection: exact version first, then branch.
    /// An unknown architecture never silently matches a build-specific profile.
    pub fn select(&self, version: &str, arch: Option<&Architecture>) -> Vec<&Profile> {
        let target = php2shell_core::Version::parse(version);
        let mut scored: Vec<(i32, &Profile)> = self
            .profiles
            .iter()
            .filter_map(|profile| {
                let arch_ok = match arch {
                    Some(requested) if requested.is_known() => &profile.arch() == requested,
                    _ => true,
                };
                if !arch_ok {
                    return None;
                }
                let score = match (&target, profile.version()) {
                    (Some(a), Some(b)) if a == &b => 100,
                    (Some(a), Some(b)) if a.branch() == b.branch() => 60,
                    _ => 10,
                };
                let score = if arch.is_some() && arch.is_some_and(|a| a.is_known()) {
                    score + 5
                } else {
                    score
                };
                Some((score, profile))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.source.cmp(&b.1.source)));
        scored.into_iter().map(|(_, profile)| profile).collect()
    }

    pub fn errors(&self) -> Vec<&Issue> {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Error)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("8.4.26-bookworm-amd64.json"),
            r#"{"name":"php-8.4.26-bookworm-amd64","php_version":"8.4.26","branch":"8.4","sapi":"apache2handler","arch":"amd64","rce":false,"libphp":{"zif_system":"0x1","zval_ptr_dtor":"0x2","htdata":null},"stages":{},"config":{}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("8.4.26-fpm.json"),
            r#"{"name":"php-8.4.26-fpm","php_version":"8.4.26","branch":"8.4","sapi":"fpm","arch":"amd64","rce":false,"libphp":{"zif_system":"0x1","zval_ptr_dtor":"0x2","htdata":null},"stages":{},"config":{}}"#,
        )
        .unwrap();
        Registry::load_with_manifest(dir.path(), None).unwrap()
    }

    #[test]
    fn loads_and_filters_profiles() {
        let registry = registry();
        assert_eq!(registry.profiles.len(), 2);
        let fpm = registry.filter(&ProfileQuery {
            sapi: Some("fpm".into()),
            ..Default::default()
        });
        assert_eq!(fpm.len(), 1);
        assert_eq!(fpm[0].id(), "php-8.4.26-fpm");
    }

    #[test]
    fn selection_is_deterministic() {
        let registry = registry();
        let selected = registry.select("8.4.26", Some(&Architecture::Amd64));
        assert_eq!(selected[0].kind(), crate::ProfileKind::ApacheModPhp);
    }
}
