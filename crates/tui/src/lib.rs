//! Ratatui terminal interface. Sections display real registry, laboratory and
//! report data; no section is a static mock-up.

mod app;
mod render;

pub use app::{App, ReportSummary, Section};
pub use render::render_app;

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use php2shell_config::Config;
use php2shell_core::{Error, Result};
use php2shell_profiles::Registry;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

pub fn run(config: Config, registry: Registry) -> Result<()> {
    let mut app = App::new(config, registry)?;
    enable_raw_mode().map_err(|err| Error::other(format!("cannot enable raw mode: {err}")))?;
    let mut stdout = io::stdout();
    let setup = execute!(stdout, EnterAlternateScreen);
    if let Err(err) = setup {
        let _ = disable_raw_mode();
        return Err(Error::other(format!(
            "cannot enter alternate screen: {err}"
        )));
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)
        .map_err(|err| Error::other(format!("cannot create terminal: {err}")))?;

    let result = event_loop(&mut terminal, &mut app);
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    result
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal
            .draw(|frame| render_app(frame, app))
            .map_err(|err| Error::other(format!("terminal draw failed: {err}")))?;
        if !event::poll(Duration::from_millis(200))
            .map_err(|err| Error::other(format!("terminal poll failed: {err}")))?
        {
            continue;
        }
        let Event::Key(key) =
            event::read().map_err(|err| Error::other(format!("terminal read failed: {err}")))?
        else {
            continue;
        };
        if app.handle_key(key) {
            break;
        }
        if matches!(key.code, KeyCode::Char('c')) && key.modifiers.contains(KeyModifiers::CONTROL) {
            break;
        }
    }
    Ok(())
}
