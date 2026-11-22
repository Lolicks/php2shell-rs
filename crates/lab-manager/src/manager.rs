use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use php2shell_config::{Config, Mode};
use php2shell_core::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lab {
    pub name: String,
    pub path: PathBuf,
    pub services: Vec<String>,
    pub ports: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct LabManager {
    config: Arc<Config>,
}

impl LabManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub fn docker_available(&self) -> bool {
        Command::new(&self.config.lab.docker_command)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    pub fn discover(&self) -> Result<Vec<Lab>> {
        let mut labs = Vec::new();
        for path in &self.config.lab.compose_files {
            if !path.is_file() {
                continue;
            }
            let text = std::fs::read_to_string(path).map_err(|err| Error::io(path, err))?;
            labs.push(parse_compose(path, &text));
        }
        Ok(labs)
    }

    fn compose_path(&self, name: &str) -> Result<PathBuf> {
        if self.config.mode != Mode::Lab {
            return Err(Error::LabOnly);
        }
        let root = std::fs::canonicalize(&self.config.lab.runtime_dir)
            .map_err(|err| Error::io(&self.config.lab.runtime_dir, err))?;
        let candidate = self
            .config
            .lab
            .compose_files
            .iter()
            .find(|path| {
                path.file_name().and_then(|n| n.to_str()) == Some(name)
                    || path.to_string_lossy() == name
            })
            .ok_or_else(|| {
                Error::Config(format!(
                    "lab `{name}` is not in the configured compose list"
                ))
            })?;
        let resolved = std::fs::canonicalize(candidate).map_err(|err| Error::io(candidate, err))?;
        if !resolved.starts_with(&root) {
            return Err(Error::LabOnly);
        }
        Ok(resolved)
    }

    fn compose(&self, name: &str, arguments: &[&str]) -> Result<String> {
        let path = self.compose_path(name)?;
        let output = Command::new(&self.config.lab.docker_command)
            .arg("compose")
            .arg("-f")
            .arg(&path)
            .args(arguments)
            .output()
            .map_err(|err| Error::other(format!("running docker compose: {err}")))?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.status.success() {
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            return Err(Error::other(format!(
                "docker compose {} failed: {}",
                arguments.join(" "),
                text.trim()
            )));
        }
        Ok(text)
    }

    pub fn up(&self, name: &str) -> Result<String> {
        self.compose(name, &["up", "-d"])
    }

    pub fn down(&self, name: &str) -> Result<String> {
        self.compose(name, &["down", "--remove-orphans"])
    }

    pub fn status(&self, name: &str) -> Result<String> {
        self.compose(name, &["ps", "--format", "json"])
    }

    pub fn logs(&self, name: &str, tail: usize) -> Result<String> {
        let count = tail.min(1000).to_string();
        self.compose(name, &["logs", "--tail", &count])
    }

    /// Removes only generated files below the configured lab runtime dir.
    pub fn clean(&self) -> Result<Vec<PathBuf>> {
        if self.config.mode != Mode::Lab {
            return Err(Error::LabOnly);
        }
        let root = std::fs::canonicalize(&self.config.lab.runtime_dir)
            .map_err(|err| Error::io(&self.config.lab.runtime_dir, err))?;
        let mut removed = Vec::new();
        let candidates = [
            root.join("rce").join("out"),
            root.join("fpm").join("webroot").join("out"),
        ];
        for path in candidates {
            if !path.is_dir() || !path.starts_with(&root) {
                continue;
            }
            std::fs::remove_dir_all(&path).map_err(|err| Error::io(&path, err))?;
            removed.push(path);
        }
        Ok(removed)
    }
}

fn parse_compose(path: &Path, text: &str) -> Lab {
    let mut services = Vec::new();
    let mut ports = Vec::new();
    let mut in_services = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !line.starts_with(' ') && trimmed == "services:" {
            in_services = true;
            continue;
        }
        if !line.starts_with(' ') && trimmed.ends_with(':') {
            in_services = false;
        }
        if !in_services {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 2 && trimmed.ends_with(':') {
            services.push(trimmed.trim_end_matches(':').to_owned());
        } else if trimmed.starts_with("- \"") || trimmed.starts_with("- '") {
            ports.push(
                trimmed
                    .trim_start_matches("- \"")
                    .trim_start_matches("- '")
                    .trim_end_matches(['"', '\''])
                    .to_owned(),
            );
        }
    }
    Lab {
        name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("compose")
            .to_owned(),
        path: path.to_path_buf(),
        services,
        ports,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_compose_file() {
        let lab = parse_compose(
            Path::new("lab/wordpress/docker-compose.yml"),
            "services:\n  db:\n    image: mysql:8.0\n  wordpress:\n    ports:\n      - \"127.0.0.1:8080:80\"\nvolumes:\n  db_data:\n",
        );
        assert_eq!(lab.services, vec!["db", "wordpress"]);
        assert_eq!(lab.ports, vec!["127.0.0.1:8080:80"]);
    }

    #[test]
    fn lab_operations_are_refused_outside_lab_mode() {
        let config = Arc::new(Config::default());
        let manager = LabManager::new(config);
        assert!(matches!(
            manager.up("docker-compose.yml"),
            Err(Error::LabOnly)
        ));
        assert!(matches!(manager.clean(), Err(Error::LabOnly)));
    }
}
