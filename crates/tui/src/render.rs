//! Dark-theme rendering. Every widget is backed by live data from the app.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Wrap};

use crate::app::{App, Section};

const CYAN: Color = Color::Cyan;
const GREEN: Color = Color::Green;
const YELLOW: Color = Color::Yellow;
const GREY: Color = Color::Gray;

pub fn render_app(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(9),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let title = format!(
        " PHP2Shell-RS  ·  {}  ·  mode={}  ·  profiles={} ",
        app.section().title(),
        app.config.mode.as_str(),
        app.registry.profiles.len()
    );
    frame.render_widget(
        Paragraph::new(Line::from(title))
            .style(Style::default().fg(CYAN).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );

    render_section(frame, app, chunks[1]);
    render_logs(frame, app, chunks[2]);

    let help = if app.show_help {
        " Tab/Shift+Tab sections · 1-8 jump · j/k navigate · PgUp/PgDn scroll · r reload · ? help · q quit "
    } else {
        " ? help · q quit "
    };
    frame.render_widget(
        Paragraph::new(help).style(Style::default().fg(GREY)),
        chunks[3],
    );
}

fn render_section(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", app.section().title()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match app.section() {
        Section::Dashboard => {
            let summary = app.summary.as_ref();
            let text = format!(
                "Tool       : php2shell-rs {}\n\
                 Mode       : {}\n\
                 Profiles   : {}\n\
                 Schema issues: {}\n\
                 Labs       : {}\n\
                 Docker     : {}\n\
                 TLS verify : {}\n\
                 Last report: {}\n\
                 Verdict    : {}\n\
                 Compatibility is never asserted from headers alone.\n\
                 No Python runtime. No exploitation features.",
                php2shell_core::TOOL_VERSION,
                app.config.mode.as_str(),
                app.registry.profiles.len(),
                app.registry.errors().len(),
                app.labs.len(),
                if app.docker_available {
                    "available"
                } else {
                    "not available"
                },
                app.config.http.tls_verify,
                summary.map(|s| s.target.as_str()).unwrap_or("none"),
                summary.map(|s| s.verdict.as_str()).unwrap_or("no report"),
            );
            frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
        }
        Section::Fingerprinting => {
            let text = match &app.summary {
                Some(summary) => format!(
                    "Target       : {}\nPHP version  : {}\nServer       : {}\nSAPI         : {} (inferred)\nCompleteness : {}%\n\nAll observations are labelled with a confidence level. Headers cannot confirm the SAPI.",
                    summary.target, summary.php_version, summary.server, summary.sapi, summary.completeness
                ),
                None => "No report loaded. Run `php2shell-rs report export --fixture FILE` to load observations into the TUI.".to_owned(),
            };
            frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
        }
        Section::Profiles => {
            let rows: Vec<Row> = app
                .registry
                .profiles
                .iter()
                .enumerate()
                .map(|(index, profile)| {
                    let style = if index == app.selected {
                        Style::default().fg(Color::Black).bg(CYAN)
                    } else {
                        Style::default()
                    };
                    Row::new(vec![
                        Cell::from(profile.id().to_owned()),
                        Cell::from(profile.string("php_version").unwrap_or("-").to_owned()),
                        Cell::from(profile.sapi().as_str().to_owned()),
                        Cell::from(profile.arch().as_str().to_owned()),
                        Cell::from(if profile.rce() { "yes" } else { "no" }),
                    ])
                    .style(style)
                })
                .collect();
            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(42),
                    Constraint::Length(10),
                    Constraint::Length(18),
                    Constraint::Length(12),
                    Constraint::Length(6),
                ],
            )
            .header(
                Row::new(vec!["profile", "version", "sapi", "arch", "rce"])
                    .style(Style::default().fg(GREEN)),
            );
            frame.render_widget(table, inner);
        }
        Section::Inventory => {
            let profiles: Vec<&php2shell_profiles::Profile> =
                app.registry.profiles.iter().collect();
            let data = php2shell_inventory::rows(profiles);
            let rows: Vec<Row> = data
                .iter()
                .enumerate()
                .map(|(index, row)| {
                    let style = if index == app.selected {
                        Style::default().fg(Color::Black).bg(CYAN)
                    } else {
                        Style::default()
                    };
                    Row::new(vec![
                        Cell::from(row.php.clone()),
                        Cell::from(row.build.clone()),
                        Cell::from(row.stage3.clone()),
                        Cell::from(row.rce.clone()),
                    ])
                    .style(style)
                })
                .collect();
            let table = Table::new(
                rows,
                [
                    Constraint::Length(10),
                    Constraint::Percentage(40),
                    Constraint::Length(12),
                    Constraint::Length(8),
                ],
            )
            .header(
                Row::new(vec!["PHP", "build", "stage3", "RCE"]).style(Style::default().fg(GREEN)),
            );
            frame.render_widget(table, inner);
        }
        Section::Diagnostics => {
            let text = match &app.summary {
                Some(summary) => {
                    let mut lines = vec![
                        format!("target: {}", summary.target),
                        format!("verdict: {}", summary.verdict),
                        format!("php version: {}", summary.php_version),
                        format!("sapi (inferred): {}", summary.sapi),
                        format!("compatible profiles: {}", summary.compatible),
                        String::new(),
                        "uncertainty:".to_owned(),
                    ];
                    for item in summary.uncertainty.iter().skip(app.scroll).take(6) {
                        lines.push(format!("  ? {item}"));
                    }
                    lines.push(String::new());
                    lines.push("recommendations:".to_owned());
                    for item in summary.recommendations.iter().take(6) {
                        lines.push(format!("  * {item}"));
                    }
                    lines.join("\n")
                }
                None => "No diagnostics loaded. Export a report first, then press 'r' to reload."
                    .to_owned(),
            };
            frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
        }
        Section::Laboratories => {
            let items: Vec<ListItem> = app
                .labs
                .iter()
                .map(|lab| {
                    ListItem::new(format!(
                        "{}  services={:?}  ports={:?}",
                        lab.path.display(),
                        lab.services,
                        lab.ports
                    ))
                })
                .collect();
            let list = List::new(items).block(Block::default().title(" compose files "));
            frame.render_widget(list, inner);
        }
        Section::Reports => {
            let items: Vec<ListItem> = app
                .reports
                .iter()
                .map(|path| ListItem::new(path.display().to_string()))
                .collect();
            if items.is_empty() {
                frame.render_widget(
                    Paragraph::new("No reports yet. Use `report export`."),
                    inner,
                );
            } else {
                frame.render_widget(List::new(items), inner);
            }
        }
        Section::Settings => {
            let http = &app.config.http;
            let text = format!(
                "mode              : {}\n\
                 config source     : profiles={} manifest={:?}\n\
                 http timeout      : {}s (connect {}s)\n\
                 max response      : {} bytes\n\
                 redirects         : {}\n\
                 pool per host     : {}\n\
                 TLS verification  : {}\n\
                 user agent        : {}\n\
                 allowed addresses : {:?}\n\
                 report format     : {:?}\n\
                 verbosity         : {} quiet={} json={}\n\
                 report output     : {}",
                app.config.mode.as_str(),
                app.config.profiles.directory.display(),
                app.config.profiles.manifest,
                http.timeout_secs,
                http.connect_timeout_secs,
                http.max_response_bytes,
                http.max_redirects,
                http.pool_max_idle_per_host,
                http.tls_verify,
                http.user_agent,
                app.config.allowed_addresses,
                app.config.report.format,
                app.config.log.verbosity,
                app.config.log.quiet,
                app.config.log.json,
                app.config.report.output_dir.display(),
            );
            frame.render_widget(
                Paragraph::new(text)
                    .style(Style::default().fg(if http.tls_verify { GREEN } else { YELLOW }))
                    .wrap(Wrap { trim: false }),
                inner,
            );
        }
    }
}

fn render_logs(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default().borders(Borders::ALL).title(" event log ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let start = app.logs.len().saturating_sub(6);
    let items: Vec<ListItem> = app.logs[start..]
        .iter()
        .map(|line| ListItem::new(line.clone()).style(Style::default().fg(GREY)))
        .collect();
    frame.render_widget(List::new(items), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::App;
    use php2shell_config::Config;
    use php2shell_profiles::Registry;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn all_sections_render_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::default();
        let registry = Registry::load_with_manifest(dir.path(), None).unwrap();
        let app = App::new(config, registry).unwrap();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        for _ in 0..8 {
            terminal.draw(|frame| render_app(frame, &app)).unwrap();
        }
        let buffer = terminal.backend().buffer().clone();
        let contents: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
        assert!(contents.contains("PHP2Shell-RS"));
    }
}
