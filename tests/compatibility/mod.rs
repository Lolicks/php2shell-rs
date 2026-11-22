//! JSON-compatibility and migration-invariant tests.
//!
//! These tests treat the upstream profile files as immutable input. They fail
//! if a profile is edited without updating `profiles/manifest.json`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use php2shell_core::sha256;
use php2shell_profiles::{Manifest, ProfileKind, Registry};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn manifest_records_every_original_profile_and_checksum() {
    let manifest = Manifest::load(root().join("profiles/manifest.json")).unwrap();
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.count, Some(manifest.files.len()));
    assert!(manifest.files.len() >= 100);

    for entry in &manifest.files {
        let file = root().join(&entry.path);
        assert!(file.is_file(), "missing recorded file: {}", entry.path);
        assert_eq!(
            sha256::hash_text_file(&file).unwrap(),
            entry.sha256,
            "{}",
            entry.path
        );
    }
}

#[test]
fn rust_registry_reads_all_upstream_profiles_without_errors() {
    let registry = Registry::load(root().join("profiles")).unwrap();
    assert_eq!(registry.profiles.len(), 56);
    let errors: Vec<_> = registry.errors();
    assert!(
        errors.is_empty(),
        "unexpected validation errors: {errors:?}"
    );
    assert!(registry.manifest.is_some());

    let apache = registry
        .profiles
        .iter()
        .filter(|profile| profile.kind() == ProfileKind::ApacheModPhp)
        .count();
    let fpm = registry
        .profiles
        .iter()
        .filter(|profile| profile.kind() == ProfileKind::Fpm)
        .count();
    assert_eq!(apache, 48);
    assert_eq!(fpm, 8);
}

#[test]
fn no_duplicate_profile_identity() {
    let registry = Registry::load(root().join("profiles")).unwrap();
    let mut seen = HashSet::new();
    for profile in &registry.profiles {
        let arch = profile.arch();
        let sapi = profile.sapi();
        let key = (
            profile.id().to_owned(),
            profile.string("php_version").unwrap_or_default().to_owned(),
            arch.as_str().to_owned(),
            sapi.as_str().to_owned(),
        );
        assert!(seen.insert(key), "duplicate profile {}", profile.id());
    }
}

#[test]
fn upstream_schemas_are_preserved() {
    let generic = root().join("profiles/schema.json");
    let fpm = root().join("profiles/fpm-schema.json");
    assert!(generic.is_file());
    assert!(fpm.is_file());
    let generic_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&generic).unwrap()).unwrap();
    let fpm_value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fpm).unwrap()).unwrap();
    assert_eq!(
        generic_value["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        fpm_value["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
}

#[test]
fn version_registry_preserves_upstream_classification() {
    use php2shell_core::versions;
    let cases = [
        ("8.5.11", Some("8.5.12"), true),
        ("8.4.26", Some("8.4.27"), true),
        ("8.4.27", Some("8.4.27"), false),
        ("7.4.33", None, true),
    ];
    for (version, expected_fixed, vulnerable) in cases {
        let classification = versions::classify(version).unwrap();
        assert_eq!(
            classification
                .fixed
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            expected_fixed
        );
        assert_eq!(classification.is_vulnerable(), vulnerable);
    }
}

#[test]
fn catalog_is_still_machine_readable() {
    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("catalog/vulnerable.json")).unwrap(),
    )
    .unwrap();
    assert!(
        catalog["branches"]
            .as_array()
            .is_some_and(|branches| !branches.is_empty())
    );
    assert!(
        catalog["profiles"]
            .as_object()
            .is_some_and(|profiles| !profiles.is_empty())
    );
    assert_eq!(catalog["updated"], "2026-10-30");
}

#[test]
fn active_rust_tree_has_no_python_runtime_dependency() {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, files);
            } else {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root().join("crates"), &mut files);
    walk(&root().join("src"), &mut files);
    files.push(root().join("Cargo.toml"));
    for file in files {
        if file.extension().and_then(|e| e.to_str()) != Some("rs")
            && file.file_name().unwrap() != "Cargo.toml"
        {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            !text.contains("python3"),
            "python3 reference in {}",
            file.display()
        );
        assert!(
            !text.contains("Command::new(\"python"),
            "python invocation in {}",
            file.display()
        );
        assert!(
            !text.contains("pyo3"),
            "Python binding in {}",
            file.display()
        );
    }
}
