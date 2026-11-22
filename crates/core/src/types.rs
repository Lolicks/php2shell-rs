//! Small value types shared by the workspace.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Unknown,
    Possible,
    Probable,
    Confirmed,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Possible => "possible",
            Self::Probable => "probable",
            Self::Confirmed => "confirmed",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Possible => 1,
            Self::Probable => 2,
            Self::Confirmed => 3,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Architecture {
    Amd64,
    Aarch64,
    Unknown(String),
}

impl Architecture {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Amd64 => "amd64",
            Self::Aarch64 => "aarch64",
            Self::Unknown(value) => value,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Amd64 | Self::Aarch64)
    }

    /// Maps `uname -m` output to the profile vocabulary.
    pub fn from_uname(value: &str) -> Self {
        match value.trim() {
            "x86_64" | "amd64" => Self::Amd64,
            "aarch64" | "arm64" => Self::Aarch64,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "amd64" | "x86_64" => Ok(Self::Amd64),
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            "" => Err("empty architecture".to_owned()),
            other => Ok(Self::Unknown(other.to_owned())),
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Sapi {
    Apache2Handler,
    Fpm,
    Unknown(String),
}

impl Sapi {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Apache2Handler => "apache2handler",
            Self::Fpm => "fpm",
            Self::Unknown(value) => value,
        }
    }
}

impl FromStr for Sapi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "apache2handler" | "apache" | "mod_php" => Ok(Self::Apache2Handler),
            "fpm" => Ok(Self::Fpm),
            "" => Err("empty SAPI".to_owned()),
            other => Ok(Self::Unknown(other.to_owned())),
        }
    }
}

impl fmt::Display for Sapi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.trim().split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self::new(major, minor, patch))
    }

    pub fn branch(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_is_strict() {
        assert_eq!(Version::parse("8.4.26"), Some(Version::new(8, 4, 26)));
        assert_eq!(Version::parse("8.4"), None);
        assert_eq!(Version::parse("8.4.26-rc1"), None);
        assert_eq!(Version::parse("v8.4.26"), None);
    }

    #[test]
    fn architecture_maps_uname() {
        assert_eq!(Architecture::from_uname("x86_64"), Architecture::Amd64);
        assert_eq!(Architecture::from_uname("arm64"), Architecture::Aarch64);
        assert!(!Architecture::from_uname("riscv64").is_known());
    }

    #[test]
    fn sapi_accepts_profile_vocabulary() {
        assert_eq!(
            "apache2handler".parse::<Sapi>().unwrap(),
            Sapi::Apache2Handler
        );
        assert_eq!("fpm".parse::<Sapi>().unwrap(), Sapi::Fpm);
    }
}
