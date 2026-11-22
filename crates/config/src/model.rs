use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use php2shell_core::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Diagnostic-only mode: no lab control, no TLS overrides, loopback only.
    Safe,
    /// Allows explicitly approved laboratory operations.
    Lab,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Lab => "lab",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Table,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub max_response_bytes: usize,
    pub max_redirects: usize,
    pub pool_max_idle_per_host: usize,
    /// Always true unless explicitly overridden in lab mode.
    pub tls_verify: bool,
    pub user_agent: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfilesConfig {
    pub directory: PathBuf,
    pub manifest: Option<PathBuf>,
    pub strict: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LabConfig {
    pub docker_command: String,
    pub compose_files: Vec<PathBuf>,
    pub runtime_dir: PathBuf,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub output_dir: PathBuf,
    /// Strip URLs of user info, query strings and fragments.
    pub redact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub verbosity: u8,
    pub quiet: bool,
    pub json: bool,
    pub color: ColorChoice,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub http: HttpConfig,
    pub profiles: ProfilesConfig,
    pub lab: LabConfig,
    pub report: ReportConfig,
    pub log: LogConfig,
    /// Extra hosts (or CIDRs) the user explicitly authorises for diagnostics.
    /// Loopback addresses are always allowed; nothing is discovered or swept.
    pub allowed_addresses: Vec<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            connect_timeout_secs: 5,
            max_response_bytes: 2 * 1024 * 1024,
            max_redirects: 3,
            pool_max_idle_per_host: 4,
            tls_verify: true,
            user_agent: format!("php2shell-rs/{}", php2shell_core::TOOL_VERSION),
        }
    }
}

impl Default for ProfilesConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("profiles"),
            manifest: Some(PathBuf::from("profiles/manifest.json")),
            strict: true,
        }
    }
}

impl Default for LabConfig {
    fn default() -> Self {
        Self {
            docker_command: "docker".to_owned(),
            compose_files: vec![PathBuf::from("lab/wordpress/docker-compose.yml")],
            runtime_dir: PathBuf::from("lab"),
            timeout_secs: 60,
        }
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Json,
            output_dir: PathBuf::from("reports"),
            redact: true,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            verbosity: 1,
            quiet: false,
            json: false,
            color: ColorChoice::Auto,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Safe,
            http: HttpConfig::default(),
            profiles: ProfilesConfig::default(),
            lab: LabConfig::default(),
            report: ReportConfig::default(),
            log: LogConfig::default(),
            allowed_addresses: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let config: Self = toml::from_str(&text).map_err(|e| Error::Toml {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.http.timeout_secs == 0 {
            return Err(Error::Config(
                "http.timeout_secs must be greater than zero".into(),
            ));
        }
        if self.http.connect_timeout_secs == 0 {
            return Err(Error::Config(
                "http.connect_timeout_secs must be greater than zero".into(),
            ));
        }
        if self.http.max_response_bytes < 1024 {
            return Err(Error::Config(
                "http.max_response_bytes must be at least 1024".into(),
            ));
        }
        if self.http.max_redirects > 20 {
            return Err(Error::Config(
                "http.max_redirects must not exceed 20".into(),
            ));
        }
        if self.http.pool_max_idle_per_host == 0 {
            return Err(Error::Config(
                "http.pool_max_idle_per_host must be at least 1".into(),
            ));
        }
        if self.http.user_agent.trim().is_empty() {
            return Err(Error::Config("http.user_agent must not be empty".into()));
        }
        if !self.http.tls_verify && self.mode != Mode::Lab {
            return Err(Error::Config(
                "http.tls_verify = false requires mode = \"lab\"; TLS verification stays on by default"
                    .into(),
            ));
        }
        if self.lab.timeout_secs == 0 {
            return Err(Error::Config(
                "lab.timeout_secs must be greater than zero".into(),
            ));
        }
        for entry in &self.allowed_addresses {
            if entry.trim().is_empty() {
                return Err(Error::Config(
                    "allowed_addresses contains an empty entry".into(),
                ));
            }
            let _ = parse_allow_entry(entry).ok_or_else(|| {
                Error::Config(format!(
                    "allowed_addresses contains an invalid entry: {entry}"
                ))
            })?;
        }
        Ok(())
    }

    /// Explicit allow-list check. Every address must be loopback or named by
    /// the operator; no discovery, guessing or mass scanning is performed.
    pub fn is_host_allowed(&self, host: &str) -> bool {
        let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        if host == "localhost" || host == "ip6-localhost" {
            return true;
        }
        if let Ok(ip) = IpAddr::from_str(&host)
            && ip.is_loopback()
        {
            return true;
        }
        self.allowed_addresses
            .iter()
            .any(|entry| allow_entry_matches(entry, &host))
    }

    pub fn lab_enabled(&self) -> bool {
        self.mode == Mode::Lab
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AllowEntry {
    Host(String),
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

fn parse_allow_entry(entry: &str) -> Option<AllowEntry> {
    let entry = entry.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if entry.is_empty() {
        return None;
    }
    if let Some((addr, prefix)) = entry.split_once('/') {
        let network = IpAddr::from_str(addr).ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        let bits = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > bits {
            return None;
        }
        return Some(AllowEntry::Cidr { network, prefix });
    }
    if let Ok(ip) = IpAddr::from_str(&entry) {
        Some(AllowEntry::Ip(ip))
    } else if entry
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*')
    {
        Some(AllowEntry::Host(entry))
    } else {
        None
    }
}

fn allow_entry_matches(entry: &str, host: &str) -> bool {
    let Some(parsed) = parse_allow_entry(entry) else {
        return false;
    };
    match parsed {
        AllowEntry::Host(value) => {
            value == host
                || value
                    .strip_prefix("*.")
                    .is_some_and(|suffix| host.ends_with(suffix))
        }
        AllowEntry::Ip(ip) => IpAddr::from_str(host).is_ok_and(|h| h == ip),
        AllowEntry::Cidr { network, prefix } => {
            let Ok(host_ip) = IpAddr::from_str(host) else {
                return false;
            };
            cidr_contains(network, prefix, host_ip)
        }
    }
}

fn cidr_contains(network: IpAddr, prefix: u8, host: IpAddr) -> bool {
    match (network, host) {
        (IpAddr::V4(net), IpAddr::V4(host)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(net) & mask == u32::from(host) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(host)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(net) & mask == u128::from(host) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let config = Config::default();
        assert_eq!(config.mode, Mode::Safe);
        assert!(config.http.tls_verify);
        assert!(config.is_host_allowed("127.0.0.1"));
        assert!(config.is_host_allowed("localhost"));
        assert!(!config.is_host_allowed("example.org"));
    }

    #[test]
    fn tls_override_requires_lab_mode() {
        let mut config = Config::default();
        config.http.tls_verify = false;
        assert!(config.validate().is_err());
        config.mode = Mode::Lab;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn allow_list_supports_host_ip_and_cidr() {
        let config = Config {
            allowed_addresses: vec![
                "lab.example.test".into(),
                "192.0.2.10".into(),
                "198.51.100.0/24".into(),
            ],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        assert!(config.is_host_allowed("lab.example.test"));
        assert!(config.is_host_allowed("192.0.2.10"));
        assert!(config.is_host_allowed("198.51.100.42"));
        assert!(!config.is_host_allowed("198.51.101.1"));
        assert!(!config.is_host_allowed("not-listed.example.test"));
    }

    #[test]
    fn config_round_trips_through_toml() {
        let text = toml::to_string_pretty(&Config::default()).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed, Config::default());
    }
}
