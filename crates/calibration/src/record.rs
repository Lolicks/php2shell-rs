use php2shell_core::{Error, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationResult {
    /// A reproducible experiment with an operator-supplied artifact hash.
    Verified,
    /// Metadata collected, but no experiment performed.
    NotVerified,
    /// Experiment attempted and failed.
    Failed,
    /// Explicitly skipped by the operator.
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationRecord {
    pub schema_version: String,
    pub php_version: String,
    pub sapi: String,
    pub os: String,
    pub architecture: String,
    pub build: String,
    pub tested_at: String,
    pub tool_version: String,
    pub result: CalibrationResult,
    pub artifact_sha256: Option<String>,
    pub notes: Vec<String>,
}

impl CalibrationRecord {
    pub fn new(
        php_version: impl Into<String>,
        sapi: impl Into<String>,
        os: impl Into<String>,
        architecture: impl Into<String>,
        build: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: "1.0".to_owned(),
            php_version: php_version.into(),
            sapi: sapi.into(),
            os: os.into(),
            architecture: architecture.into(),
            build: build.into(),
            // Formatting an RFC 3339 timestamp from now cannot fail with the
            // well-known format; keep a deterministic fallback rather than
            // panicking in library code.
            tested_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
            tool_version: php2shell_core::TOOL_VERSION.to_owned(),
            result: CalibrationResult::NotVerified,
            artifact_sha256: None,
            notes: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let required = [
            ("php_version", self.php_version.as_str()),
            ("sapi", self.sapi.as_str()),
            ("os", self.os.as_str()),
            ("architecture", self.architecture.as_str()),
            ("build", self.build.as_str()),
            ("tool_version", self.tool_version.as_str()),
        ];
        for (field, value) in required {
            if value.trim().is_empty() {
                return Err(Error::Config(format!(
                    "calibration record has an empty {field}"
                )));
            }
        }
        if php2shell_core::Version::parse(&self.php_version).is_none() {
            return Err(Error::Config(
                "calibration record has an invalid php_version".into(),
            ));
        }
        OffsetDateTime::parse(&self.tested_at, &Rfc3339).map_err(|err| {
            Error::Config(format!(
                "calibration record has an invalid tested_at: {err}"
            ))
        })?;
        if let Some(hash) = &self.artifact_sha256
            && (hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(Error::Config(
                "calibration artifact_sha256 must be a 64-character SHA-256 digest".into(),
            ));
        }
        if self.result == CalibrationResult::Verified && self.artifact_sha256.is_none() {
            return Err(Error::Config(
                "a verified calibration record requires an artifact_sha256".into(),
            ));
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|err| Error::other(format!("serialising calibration record: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> CalibrationRecord {
        CalibrationRecord::new(
            "8.4.26",
            "apache2handler",
            "debian",
            "amd64",
            "php:8.4.26-apache",
        )
    }

    #[test]
    fn default_record_is_not_verified() {
        let record = record();
        assert_eq!(record.result, CalibrationResult::NotVerified);
        assert_eq!(record.schema_version, "1.0");
        assert!(record.validate().is_ok());
    }

    #[test]
    fn verified_requires_an_artifact_hash() {
        let mut record = record();
        record.result = CalibrationResult::Verified;
        assert!(record.validate().is_err());
        record.artifact_sha256 = Some("a".repeat(64));
        assert!(record.validate().is_ok());
    }

    #[test]
    fn metadata_is_mandatory() {
        let mut record = record();
        record.build.clear();
        assert!(record.validate().is_err());
        record.build = "build".into();
        record.tested_at = "yesterday".into();
        assert!(record.validate().is_err());
    }
}
