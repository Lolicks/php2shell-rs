//! Schema-aware validation of profile JSON.
//!
//! The upstream `schema.json` and `fpm-schema.json` are preserved verbatim in
//! `profiles/`. This module implements their constraints (required fields,
//! types, enums, hex patterns, conditionals) and adds the checks the migration
//! needs: schema version, provenance and duplicate detection.

use std::collections::HashSet;

use php2shell_core::Version;
use serde_json::Value;

use crate::model::{Profile, ProfileKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub pointer: String,
    pub message: String,
    pub severity: Severity,
}

impl Issue {
    pub(crate) fn error(pointer: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            message: message.into(),
            severity: Severity::Error,
        }
    }

    pub(crate) fn warning(pointer: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            message: message.into(),
            severity: Severity::Warning,
        }
    }
}

const GENERIC_REQUIRED: &[&str] = &[
    "name",
    "php_version",
    "branch",
    "sapi",
    "arch",
    "rce",
    "libphp",
    "stages",
    "config",
];
const FPM_REQUIRED: &[&str] = &[
    "name",
    "php_version",
    "branch",
    "fixed_in",
    "sapi",
    "verified",
    "rce",
    "distro",
    "arch",
    "libphp",
    "fpm",
    "stages",
    "config",
    "status",
    "oom_mb",
];
const FPM_SECTION_REQUIRED: &[&str] = &[
    "basic_globals",
    "bg_unserialize_data_off",
    "bg_unserialize_level_off",
    "struct_size",
    "reclaim_pads",
    "reclaim_size",
    "oracle",
    "no_oracle",
    "leak",
];
const FPM_LEAK_REQUIRED: &[&str] = &[
    "arm_path",
    "pads",
    "size",
    "header_content_off",
    "read_len",
    "chunk_ptr_off",
    "chunk_base_off",
    "pie_ptr_off",
    "pie_base_off",
];

pub fn validate_profile(value: &Value, kind_hint: Option<ProfileKind>) -> Vec<Issue> {
    let mut issues = Vec::new();
    if !value.is_object() {
        return vec![Issue::error("", "profile root must be a JSON object")];
    }

    let sapi = value
        .get("sapi")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = match sapi {
        "apache2handler" => ProfileKind::ApacheModPhp,
        "fpm" => ProfileKind::Fpm,
        "" => ProfileKind::Unknown,
        other => {
            issues.push(Issue::error(
                "/sapi",
                format!("unsupported SAPI `{other}` (expected apache2handler or fpm)"),
            ));
            ProfileKind::Unknown
        }
    };
    if let Some(hint) = kind_hint
        && hint != ProfileKind::Unknown
        && kind != ProfileKind::Unknown
        && hint != kind
    {
        issues.push(Issue::warning(
            "/sapi",
            format!("file placement suggests {hint:?} but SAPI says {kind:?}"),
        ));
    }

    let required: &[&str] = if kind == ProfileKind::Fpm {
        FPM_REQUIRED
    } else {
        GENERIC_REQUIRED
    };
    for field in required {
        if value.get(field).is_none() {
            issues.push(Issue::error(
                format!("/{field}"),
                format!("missing required field `{field}`"),
            ));
        }
    }

    check_string(value, "name", &mut issues, false);
    check_string(value, "php_version", &mut issues, false);
    check_string(value, "branch", &mut issues, false);
    check_string(value, "status", &mut issues, true);
    check_string(value, "distro", &mut issues, true);
    check_string(value, "upstream_profile", &mut issues, true);

    check_bool(value, "rce", &mut issues, false);
    check_bool(value, "verified", &mut issues, kind != ProfileKind::Fpm);
    check_integer(value, "oom_mb", &mut issues, true);
    check_object(value, "stages", &mut issues, false);
    check_object(value, "config", &mut issues, false);
    check_object(value, "measured", &mut issues, true);
    check_object(value, "layout", &mut issues, true);

    if let Some(name) = value.get("name").and_then(Value::as_str)
        && !name.starts_with("php-")
    {
        issues.push(Issue::error("/name", "profile name must start with `php-`"));
    }

    if let Some(version) = value.get("php_version").and_then(Value::as_str)
        && Version::parse(version).is_none()
    {
        issues.push(Issue::error(
            "/php_version",
            format!("`{version}` is not a strict three-component PHP version"),
        ));
    }

    if let Some(branch) = value.get("branch").and_then(Value::as_str) {
        let mut parts = branch.split('.');
        let valid = parts
            .next()
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            && parts
                .next()
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            && parts.next().is_none();
        if !valid {
            issues.push(Issue::error(
                "/branch",
                format!("`{branch}` is not a valid branch"),
            ));
        }
        if let Some(version) = value.get("php_version").and_then(Value::as_str)
            && let Some(v) = Version::parse(version)
            && v.branch() != branch
        {
            issues.push(Issue::warning(
                "/branch",
                format!("branch `{branch}` does not match php_version `{version}`"),
            ));
        }
    }

    // The upstream schemas accept `null` and descriptive strings such as
    // "none (EOL branch, no upstream fix)" for `fixed_in`. Keep that exact
    // compatibility instead of enforcing a stricter version pattern.
    if let Some(fixed) = value.get("fixed_in")
        && !fixed.is_null()
        && !fixed.is_string()
    {
        issues.push(Issue::error(
            "/fixed_in",
            "fixed_in must be a string or null",
        ));
    }

    match value.get("arch").and_then(Value::as_str) {
        Some("amd64" | "aarch64") => {}
        Some(other) => issues.push(Issue::error(
            "/arch",
            format!("unsupported architecture `{other}` (expected amd64 or aarch64)"),
        )),
        None => {}
    }

    if let Some(libphp) = value.get("libphp") {
        if let Some(libphp) = libphp.as_object() {
            for field in ["zif_system", "zval_ptr_dtor"] {
                match libphp.get(field).and_then(Value::as_str) {
                    Some(hex) if is_hex(hex) => {}
                    Some(other) => issues.push(Issue::error(
                        format!("/libphp/{field}"),
                        format!("`{other}` is not a hexadecimal offset"),
                    )),
                    None => issues.push(Issue::error(
                        format!("/libphp/{field}"),
                        format!("missing or non-string `{field}`"),
                    )),
                }
            }
            if let Some(htdata) = libphp.get("htdata")
                && !htdata.is_null()
                && !htdata.as_str().is_some_and(is_hex)
            {
                issues.push(Issue::error(
                    "/libphp/htdata",
                    "htdata must be a hex string or null",
                ));
            }
        } else {
            issues.push(Issue::error("/libphp", "libphp must be an object"));
        }
    }

    if value.get("rce") == Some(&Value::Bool(true)) && kind == ProfileKind::ApacheModPhp {
        if value.get("oom_mb").and_then(Value::as_i64).unwrap_or(0) <= 0 {
            issues.push(Issue::error(
                "/oom_mb",
                "rce=true profiles require a positive oom_mb",
            ));
        }
        let stages = value.get("stages").and_then(Value::as_object);
        for field in [
            "stage1_n",
            "stage1_forge_len",
            "stage2_t",
            "stage2_v",
            "stage3_mode",
            "stage3_pads",
            "stage3_carrier",
        ] {
            if stages.and_then(|s| s.get(field)).is_none() {
                issues.push(Issue::warning(
                    format!("/stages/{field}"),
                    format!("rce=true profile is missing `{field}`"),
                ));
            }
        }
    }

    if kind == ProfileKind::Fpm
        && let Some(fpm) = value.get("fpm")
    {
        if let Some(fpm) = fpm.as_object() {
            for field in FPM_SECTION_REQUIRED {
                if fpm.get(*field).is_none() {
                    issues.push(Issue::error(
                        format!("/fpm/{field}"),
                        format!("missing required FPM field `{field}`"),
                    ));
                }
            }
            if let Some(basic) = fpm.get("basic_globals").and_then(Value::as_str)
                && !is_hex(basic)
            {
                issues.push(Issue::error(
                    "/fpm/basic_globals",
                    "basic_globals must be a hex string",
                ));
            }
            for field in [
                "bg_unserialize_data_off",
                "bg_unserialize_level_off",
                "struct_size",
                "reclaim_size",
            ] {
                if let Some(number) = fpm.get(field).and_then(Value::as_i64)
                    && number < 0
                {
                    issues.push(Issue::error(
                        format!("/fpm/{field}"),
                        "must not be negative",
                    ));
                }
            }
            if let Some(leak) = fpm.get("leak") {
                if let Some(leak) = leak.as_object() {
                    for field in FPM_LEAK_REQUIRED {
                        if leak.get(*field).is_none() {
                            issues.push(Issue::error(
                                format!("/fpm/leak/{field}"),
                                format!("missing required leak field `{field}`"),
                            ));
                        }
                    }
                } else {
                    issues.push(Issue::error("/fpm/leak", "leak must be an object"));
                }
            }
            if let Some(no_oracle) = fpm.get("no_oracle")
                && let Some(candidates) = no_oracle.get("candidates").and_then(Value::as_array)
                && candidates.is_empty()
            {
                issues.push(Issue::error(
                    "/fpm/no_oracle/candidates",
                    "candidates must not be empty",
                ));
            }
        } else {
            issues.push(Issue::error("/fpm", "fpm must be an object"));
        }
    }

    if let Some(version) = value.get("schema_version") {
        match version.as_str() {
            Some("1.0" | "fpm-1.0") => {}
            Some(other) => issues.push(Issue::warning(
                "/schema_version",
                format!("unrecognised schema version `{other}`; parsed in compatibility mode"),
            )),
            None => issues.push(Issue::error(
                "/schema_version",
                "schema_version must be a string",
            )),
        }
    }

    if let Some(provenance) = value.get("provenance") {
        match provenance.as_object() {
            Some(map) => {
                if let Some(hash) = map.get("original_sha256").and_then(Value::as_str)
                    && (hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    issues.push(Issue::error(
                        "/provenance/original_sha256",
                        "expected a 64-character SHA-256 digest",
                    ));
                }
            }
            None => issues.push(Issue::error("/provenance", "provenance must be an object")),
        }
    }

    issues
}

pub fn validate_registry(profiles: &[Profile]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut seen = HashSet::new();
    for profile in profiles {
        for issue in validate_profile(&profile.raw, Some(profile.kind())) {
            issues.push(Issue {
                pointer: format!("{}:{}", profile.source.display(), issue.pointer),
                ..issue
            });
        }
        let key = (
            profile.id().to_owned(),
            profile.string("php_version").unwrap_or_default().to_owned(),
            profile.arch().as_str().to_owned(),
            profile.sapi().as_str().to_owned(),
        );
        if !seen.insert(key) {
            issues.push(Issue::error(
                profile.source.display().to_string(),
                format!("duplicate profile `{}`", profile.id()),
            ));
        }
    }
    issues
}

fn is_hex(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn check_string(value: &Value, field: &str, issues: &mut Vec<Issue>, optional: bool) {
    match value.get(field) {
        None if !optional => issues.push(Issue::error(format!("/{field}"), "missing field")),
        Some(Value::String(_)) => {}
        Some(_) => issues.push(Issue::error(format!("/{field}"), "must be a string")),
        _ => {}
    }
}

fn check_bool(value: &Value, field: &str, issues: &mut Vec<Issue>, optional: bool) {
    match value.get(field) {
        None if !optional => issues.push(Issue::error(format!("/{field}"), "missing field")),
        Some(Value::Bool(_)) => {}
        Some(_) => issues.push(Issue::error(format!("/{field}"), "must be a boolean")),
        _ => {}
    }
}

fn check_integer(value: &Value, field: &str, issues: &mut Vec<Issue>, optional: bool) {
    match value.get(field) {
        None if !optional => issues.push(Issue::error(format!("/{field}"), "missing field")),
        Some(Value::Number(number)) if number.is_i64() => {}
        Some(_) => issues.push(Issue::error(format!("/{field}"), "must be an integer")),
        _ => {}
    }
}

fn check_object(value: &Value, field: &str, issues: &mut Vec<Issue>, optional: bool) {
    match value.get(field) {
        None if !optional => issues.push(Issue::error(format!("/{field}"), "missing field")),
        Some(Value::Object(_)) => {}
        Some(_) => issues.push(Issue::error(format!("/{field}"), "must be an object")),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> Value {
        json!({
            "name": "php-8.4.26-bookworm-amd64",
            "php_version": "8.4.26",
            "branch": "8.4",
            "sapi": "apache2handler",
            "arch": "amd64",
            "rce": false,
            "libphp": { "zif_system": "0x465370", "zval_ptr_dtor": "0x65eb60", "htdata": null },
            "stages": {},
            "config": {}
        })
    }

    #[test]
    fn minimal_profile_is_valid() {
        let issues = validate_profile(&minimal(), None);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn missing_fields_and_bad_types_are_reported() {
        let mut value = minimal();
        value.as_object_mut().unwrap().remove("branch");
        value["arch"] = json!("sparc");
        value["libphp"]["zif_system"] = json!("465370");
        let issues = validate_profile(&value, None);
        assert!(issues.iter().any(|i| i.pointer == "/branch"));
        assert!(issues.iter().any(|i| i.pointer == "/arch"));
        assert!(issues.iter().any(|i| i.pointer == "/libphp/zif_system"));
    }

    #[test]
    fn future_schema_version_is_only_a_warning() {
        let mut value = minimal();
        value["schema_version"] = json!("2.0");
        let issues = validate_profile(&value, None);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Warning);
    }
}
