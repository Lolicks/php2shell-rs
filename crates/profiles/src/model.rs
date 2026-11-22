use std::path::PathBuf;

use php2shell_core::{Architecture, Sapi, Version};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProfileKind {
    ApacheModPhp,
    Fpm,
    Unknown,
}

impl ProfileKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApacheModPhp => "apache",
            Self::Fpm => "fpm",
            Self::Unknown => "unknown",
        }
    }
}

/// A profile is kept as the original JSON value. Typed accessors are a thin
/// view over it, so export is byte-for-byte equivalent at the data level and
/// unknown future fields are never dropped.
#[derive(Clone, Debug)]
pub struct Profile {
    pub raw: Value,
    pub source: PathBuf,
}

impl Profile {
    pub fn new(raw: Value, source: impl Into<PathBuf>) -> Self {
        Self {
            raw,
            source: source.into(),
        }
    }

    pub fn id(&self) -> &str {
        self.string("name").unwrap_or_default()
    }

    pub fn string(&self, key: &str) -> Option<&str> {
        self.raw.get(key).and_then(Value::as_str)
    }

    pub fn boolean(&self, key: &str) -> Option<bool> {
        self.raw.get(key).and_then(Value::as_bool)
    }

    pub fn integer(&self, key: &str) -> Option<i64> {
        self.raw.get(key).and_then(Value::as_i64)
    }

    pub fn object(&self, key: &str) -> Option<&Map<String, Value>> {
        self.raw.get(key).and_then(Value::as_object)
    }

    pub fn version(&self) -> Option<Version> {
        Version::parse(self.string("php_version").unwrap_or_default())
    }

    pub fn branch(&self) -> &str {
        self.string("branch").unwrap_or_default()
    }

    pub fn fixed_in(&self) -> Option<Version> {
        Version::parse(self.string("fixed_in").unwrap_or_default())
    }

    pub fn sapi(&self) -> Sapi {
        self.string("sapi")
            .map(|value| match value {
                "apache2handler" => Sapi::Apache2Handler,
                "fpm" => Sapi::Fpm,
                other => Sapi::Unknown(other.to_owned()),
            })
            .unwrap_or_else(|| Sapi::Unknown(String::new()))
    }

    pub fn arch(&self) -> Architecture {
        self.string("arch")
            .map(|value| match value {
                "amd64" => Architecture::Amd64,
                "aarch64" => Architecture::Aarch64,
                other => Architecture::Unknown(other.to_owned()),
            })
            .unwrap_or_else(|| Architecture::Unknown(String::new()))
    }

    pub fn status(&self) -> &str {
        self.string("status").unwrap_or("unspecified")
    }

    pub fn rce(&self) -> bool {
        self.boolean("rce").unwrap_or(false)
    }

    pub fn verified(&self) -> bool {
        self.boolean("verified").unwrap_or(false)
    }

    pub fn kind(&self) -> ProfileKind {
        match self.sapi() {
            Sapi::Apache2Handler => ProfileKind::ApacheModPhp,
            Sapi::Fpm => ProfileKind::Fpm,
            Sapi::Unknown(_) => ProfileKind::Unknown,
        }
    }

    pub fn schema_version(&self) -> Option<&str> {
        self.string("schema_version")
    }

    pub fn provenance(&self) -> Option<&Map<String, Value>> {
        self.object("provenance")
    }

    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.raw).unwrap_or_else(|_| self.raw.to_string())
    }
}
