use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use php2shell_core::Architecture;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorArg {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Table,
}

#[derive(Debug, Parser)]
#[command(
    name = "php2shell-rs",
    version = php2shell_core::TOOL_VERSION,
    about = "Diagnostic and laboratory toolkit for PHP build profiles. No Python runtime, no exploitation features.",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Configuration file. Defaults to ./config.toml when present.
    #[arg(long, value_name = "FILE", global = true)]
    pub config: Option<PathBuf>,

    /// Increase log verbosity (repeatable).
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress informational output.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Emit structured JSON where supported.
    #[arg(long, global = true)]
    pub json: bool,

    /// Colour output mode.
    #[arg(long, value_enum, global = true, default_value = "auto")]
    pub color: ColorArg,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Args, Default)]
pub struct Filters {
    /// Filter by exact PHP version.
    #[arg(long)]
    pub php_version: Option<String>,
    /// Filter by branch (for example 8.4).
    #[arg(long)]
    pub branch: Option<String>,
    /// Filter by SAPI (apache2handler or fpm).
    #[arg(long)]
    pub sapi: Option<String>,
    /// Filter by architecture.
    #[arg(long)]
    pub arch: Option<String>,
    /// Filter by verification status text.
    #[arg(long)]
    pub status: Option<String>,
    /// Only profiles with (or without) a verified result.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub rce: Option<bool>,
    /// Free-text search over name, version, status and file path.
    #[arg(long)]
    pub search: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print build information and the safety model.
    Version,
    /// Manage JSON build profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Show the profile and offset inventory.
    Inventory {
        #[command(flatten)]
        filters: Filters,
    },
    /// Fingerprint a captured HTTP response or an explicitly supplied URL.
    Fingerprint {
        #[arg(long)]
        url: Option<String>,
        #[arg(long, value_name = "FILE")]
        fixture: Option<PathBuf>,
    },
    /// Produce a diagnostic report from passive observations only.
    Diagnostics {
        #[arg(long)]
        url: Option<String>,
        #[arg(long, value_name = "FILE")]
        fixture: Option<PathBuf>,
        #[arg(long)]
        arch: Option<Architecture>,
    },
    /// Check harmless configuration preconditions on an explicitly allowed lab target.
    Preconditions {
        #[arg(long)]
        base: String,
        #[arg(long, default_value = "/app.php")]
        app_path: String,
        #[arg(long, default_value = "/ref.php")]
        ref_path: String,
        #[arg(long, default_value = "PHPSESSID")]
        session: String,
        #[arg(long)]
        php_version: Option<String>,
    },
    /// Manage local Docker Compose laboratories (lab mode required).
    Lab {
        #[command(subcommand)]
        action: LabAction,
    },
    /// Export reports with redacted targets.
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
    /// Collect reproducible calibration metadata (no payload execution).
    Calibrate {
        #[command(subcommand)]
        action: CalibrateAction,
    },
    /// Read ELF64 symbol offsets from a local file.
    Elf {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
    /// Build a markdown offset inventory from JSON offset files.
    Offsets {
        #[arg(long, value_name = "DIR", default_value = "profiles/offsets")]
        dir: PathBuf,
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Start the interactive terminal interface.
    Tui,
}

#[derive(Debug, Subcommand)]
pub enum ProfileAction {
    /// List profiles with optional filters.
    List {
        #[command(flatten)]
        filters: Filters,
    },
    /// Print the original JSON of one profile.
    Show { id: String },
    /// Validate every profile against the schema and checksum manifest.
    Validate,
    /// Import a JSON profile without modifying existing profiles.
    Import {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
    /// Export a profile as JSON.
    Export {
        id: String,
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum LabAction {
    /// Discover configured compose files.
    List,
    /// Show container status for a lab.
    Status { name: String },
    /// Start a lab (lab mode required).
    Up { name: String },
    /// Stop a lab (lab mode required).
    Down { name: String },
    /// Show recent lab logs (lab mode required).
    Logs {
        name: String,
        #[arg(long, default_value_t = 50)]
        tail: usize,
    },
    /// Remove generated lab output directories (lab mode required).
    Clean,
    /// Serve the local mock laboratory on a loopback address.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReportAction {
    /// Create and write a diagnostic report.
    Export {
        #[arg(long)]
        url: Option<String>,
        #[arg(long, value_name = "FILE")]
        fixture: Option<PathBuf>,
        #[arg(long)]
        arch: Option<Architecture>,
        #[arg(long, value_enum, default_value = "json")]
        format: OutputFormat,
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// List previously written reports.
    List,
}

#[derive(Debug, Subcommand)]
pub enum CalibrateAction {
    /// Collect passive metadata from an explicitly named local container.
    Metadata {
        #[arg(long)]
        container: String,
        #[arg(long, value_name = "FILE")]
        artifact: Option<PathBuf>,
    },
    /// Inspect a PHP source tree or tarball for the upstream fix markers.
    Source {
        #[arg(long, value_name = "PATH")]
        path: PathBuf,
    },
    /// Parse a PHP build banner from an explicitly supplied local binary.
    Binary {
        #[arg(long, value_name = "FILE")]
        path: PathBuf,
    },
    /// Parse a stage-3 pad specification without executing anything.
    Pads {
        #[arg(long)]
        spec: Option<String>,
    },
    /// Create a calibration record with complete reproducible metadata.
    Record {
        #[arg(long)]
        php_version: String,
        #[arg(long)]
        sapi: String,
        #[arg(long)]
        os: String,
        #[arg(long)]
        arch: String,
        #[arg(long)]
        build: String,
        #[arg(long, value_name = "FILE")]
        artifact: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
}
