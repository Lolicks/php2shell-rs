//! Command line interface. All logic lives in this crate's modules; the
//! workspace binary is a three-line shim.

mod cli;
mod commands;
mod fixture;
mod output;

use std::ffi::OsString;

use clap::{CommandFactory, Parser, error::ErrorKind};
use php2shell_config::{ColorChoice, Config, LogConfig};
use php2shell_core::Error;
use tracing::Level;

pub use cli::{CalibrateAction, Cli, ColorArg, Command, LabAction, ProfileAction, ReportAction};

/// Entry point returning a process exit code.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let code = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
            let _ = err.print();
            return code;
        }
    };

    let config = match load_config(&cli) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return err.exit_code().into();
        }
    };
    init_logging(&config);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("error: cannot start async runtime: {err}");
            return 6;
        }
    };

    match runtime.block_on(commands::execute(&cli, config)) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            err.exit_code().into()
        }
    }
}

fn load_config(cli: &Cli) -> Result<Config, Error> {
    let path = cli
        .config
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
    let mut config = if path.is_file() {
        Config::load(&path)?
    } else if cli.config.is_some() {
        return Err(Error::Config(format!(
            "configuration file not found: {}",
            path.display()
        )));
    } else {
        Config::default()
    };

    config.log = LogConfig {
        verbosity: config.log.verbosity.saturating_add(cli.verbose),
        quiet: config.log.quiet || cli.quiet,
        json: config.log.json || cli.json,
        color: match cli.color {
            ColorArg::Auto => config.log.color,
            ColorArg::Always => ColorChoice::Always,
            ColorArg::Never => ColorChoice::Never,
        },
    };
    Ok(config)
}

fn init_logging(config: &Config) {
    let level = if config.log.quiet {
        Level::ERROR
    } else {
        match config.log.verbosity {
            0 => Level::WARN,
            1 => Level::INFO,
            2 => Level::DEBUG,
            _ => Level::TRACE,
        }
    };
    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr);
    let _ = if config.log.json {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
}

pub fn long_help() -> String {
    let mut command = Cli::command();
    let mut help = Vec::new();
    command.write_long_help(&mut help).map_err(|_| ()).ok();
    String::from_utf8_lossy(&help).into_owned()
}
