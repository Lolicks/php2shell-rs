use std::io::IsTerminal;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget};
use php2shell_config::ColorChoice;

pub fn color_enabled(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => std::io::stdout().is_terminal(),
    }
}

fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub fn heading(enabled: bool, text: &str) -> String {
    paint(enabled, "1;36", text)
}

pub fn success(enabled: bool, text: &str) -> String {
    paint(enabled, "32", text)
}

pub fn warning(enabled: bool, text: &str) -> String {
    paint(enabled, "33", text)
}

pub fn failure(enabled: bool, text: &str) -> String {
    paint(enabled, "31", text)
}

pub fn muted(enabled: bool, text: &str) -> String {
    paint(enabled, "2", text)
}

pub fn progress(message: impl Into<String>, quiet: bool) -> ProgressBar {
    let bar = ProgressBar::new_spinner();
    if quiet {
        bar.set_draw_target(ProgressDrawTarget::hidden());
    } else {
        bar.enable_steady_tick(Duration::from_millis(80));
    }
    bar.set_message(message.into());
    bar
}
