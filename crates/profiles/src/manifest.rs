use std::collections::BTreeMap;
use std::path::Path;

use php2shell_core::{Error, Result, sha256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub description: Option<String>,
    pub generated_from: Option<String>,
    pub count: Option<usize>,
    pub files: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: Option<u64>,
    pub category: String,
}

impl Manifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let manifest: Self = serde_json::from_str(&text).map_err(|e| Error::json(path, e))?;
        if manifest.schema_version != 1 {
            return Err(Error::Config(format!(
                "unsupported manifest schema version: {}",
                manifest.schema_version
            )));
        }
        Ok(manifest)
    }

    /// Returns a map of path -> problem. Missing files and hash mismatches are
    /// reported instead of failing the whole registry load.
    pub fn verify(&self, root: impl AsRef<Path>) -> Vec<(String, String)> {
        let root = root.as_ref();
        let mut problems = BTreeMap::new();
        for entry in &self.files {
            // Manifest paths are recorded relative to the repository root
            // (e.g. `profiles/8.4.26-bookworm-amd64.json`), while `root` is the
            // profile directory. Accept both layouts.
            let direct = root.join(&entry.path);
            let from_repo = root.parent().unwrap_or(root).join(&entry.path);
            let file = if direct.is_file() { direct } else { from_repo };
            match sha256::hash_text_file(&file) {
                Ok(actual) if actual == entry.sha256 => {}
                Ok(actual) => {
                    problems.insert(
                        entry.path.clone(),
                        format!(
                            "checksum mismatch: expected {}, got {}",
                            entry.sha256, actual
                        ),
                    );
                }
                Err(err) => {
                    problems.insert(entry.path.clone(), format!("cannot read file: {err}"));
                }
            }
        }
        problems.into_iter().collect()
    }

    pub fn checksum(&self, path: &str) -> Option<&str> {
        self.files
            .iter()
            .find(|entry| entry.path == path)
            .map(|entry| entry.sha256.as_str())
    }
}
