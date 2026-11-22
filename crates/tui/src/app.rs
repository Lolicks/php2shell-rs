use std::path::{Path, PathBuf};
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use php2shell_config::Config;
use php2shell_core::{Error, Result};
use php2shell_lab_manager::{Lab, LabManager};
use php2shell_profiles::Registry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Dashboard,
    Fingerprinting,
    Profiles,
    Inventory,
    Diagnostics,
    Laboratories,
    Reports,
    Settings,
}

impl Section {
    pub const ALL: [Section; 8] = [
        Section::Dashboard,
        Section::Fingerprinting,
        Section::Profiles,
        Section::Inventory,
        Section::Diagnostics,
        Section::Laboratories,
        Section::Reports,
        Section::Settings,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Fingerprinting => "Fingerprinting",
            Self::Profiles => "Profiles",
            Self::Inventory => "Inventory",
            Self::Diagnostics => "Diagnostics",
            Self::Laboratories => "Laboratories",
            Self::Reports => "Reports",
            Self::Settings => "Settings",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReportSummary {
    pub target: String,
    pub verdict: String,
    pub php_version: String,
    pub server: String,
    pub sapi: String,
    pub completeness: u8,
    pub compatible: usize,
    pub uncertainty: Vec<String>,
    pub recommendations: Vec<String>,
}

pub struct App {
    pub config: Config,
    pub registry: Registry,
    pub labs: Vec<Lab>,
    pub docker_available: bool,
    pub reports: Vec<PathBuf>,
    pub summary: Option<ReportSummary>,
    pub section_index: usize,
    pub selected: usize,
    pub scroll: usize,
    pub show_help: bool,
    pub logs: Vec<String>,
}

impl App {
    pub fn new(config: Config, registry: Registry) -> Result<Self> {
        let manager = LabManager::new(Arc::new(config.clone()));
        let labs = manager.discover().unwrap_or_default();
        let docker_available = manager.docker_available();
        let (reports, summary) = load_reports(&config.report.output_dir)?;
        let mut logs = vec![
            format!(
                "loaded {} profiles from {}",
                registry.profiles.len(),
                registry.root.display()
            ),
            format!(
                "mode={} tls_verify={}",
                config.mode.as_str(),
                config.http.tls_verify
            ),
        ];
        if docker_available {
            logs.push("docker available for local laboratories".to_owned());
        } else {
            logs.push("docker not available; laboratory controls are read-only".to_owned());
        }
        Ok(Self {
            config,
            registry,
            labs,
            docker_available,
            reports,
            summary,
            section_index: 0,
            selected: 0,
            scroll: 0,
            show_help: false,
            logs,
        })
    }

    pub fn section(&self) -> Section {
        Section::ALL[self.section_index]
    }

    pub fn push_log(&mut self, message: impl Into<String>) {
        self.logs.push(message.into());
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }

    /// Returns true when the application should exit.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Tab => {
                self.section_index = (self.section_index + 1) % Section::ALL.len();
                self.selected = 0;
                self.scroll = 0;
            }
            KeyCode::BackTab => {
                self.section_index =
                    (self.section_index + Section::ALL.len() - 1) % Section::ALL.len();
                self.selected = 0;
                self.scroll = 0;
            }
            KeyCode::Char('1'..='8') => {
                if let KeyCode::Char(digit) = key.code {
                    self.section_index = digit.to_digit(10).unwrap_or(1) as usize - 1;
                    self.selected = 0;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => self.selected = self.selected.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Char('?') => self.show_help = !self.show_help,
            KeyCode::Char('r') => {
                let path = self.config.profiles.directory.clone();
                match Registry::load(&path) {
                    Ok(registry) => {
                        let count = registry.profiles.len();
                        self.registry = registry;
                        self.push_log(format!("reloaded {count} profiles"));
                    }
                    Err(err) => self.push_log(format!("reload failed: {err}")),
                }
            }
            _ => {}
        }
        false
    }
}

fn load_reports(dir: &Path) -> Result<(Vec<PathBuf>, Option<ReportSummary>)> {
    let mut files = Vec::new();
    if dir.is_dir() {
        let entries = std::fs::read_dir(dir).map_err(|err| Error::io(dir, err))?;
        for entry in entries {
            let entry = entry.map_err(|err| Error::io(dir, err))?;
            if entry.path().extension().and_then(|e| e.to_str()) == Some("json") {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    let latest = files
        .last()
        .and_then(|path| std::fs::read_to_string(path).ok());
    let summary = latest
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .map(|value| {
            let diagnostics = &value["diagnostics"];
            let fingerprint = &diagnostics["fingerprint"];
            let strings = |key: &str| -> Vec<String> {
                diagnostics[key]
                    .as_array()
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            ReportSummary {
                target: value["target"].as_str().unwrap_or_default().to_owned(),
                verdict: diagnostics["verdict"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_owned(),
                php_version: fingerprint["php_version"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_owned(),
                server: fingerprint["server_software"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_owned(),
                sapi: fingerprint["sapi"].as_str().unwrap_or("unknown").to_owned(),
                completeness: fingerprint["completeness"].as_u64().unwrap_or(0) as u8,
                compatible: diagnostics["compatible_profiles"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or(0),
                uncertainty: strings("uncertainty"),
                recommendations: strings("recommendations"),
            }
        });
    Ok((files, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyboard_navigation_covers_all_sections() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::default();
        let registry = Registry::load_with_manifest(dir.path(), None).unwrap();
        let mut app = App::new(config, registry).unwrap();
        assert_eq!(app.section(), Section::Dashboard);
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.section(), Section::Fingerprinting);
        app.handle_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE));
        assert_eq!(app.section(), Section::Diagnostics);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.selected, 1);
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(app.show_help);
        assert!(app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    }
}
