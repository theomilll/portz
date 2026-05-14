use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};

use crate::app::App;
use crate::ports::PortProcess;

type Tui = Terminal<CrosstermBackend<Stdout>>;

pub fn run() -> Result<()> {
    let mut terminal_guard = TerminalGuard::new()?;
    let terminal = &mut terminal_guard.terminal;
    let mut app = App::load()?;

    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(8),
                    Constraint::Length(3),
                ])
                .split(area);

            let title = Paragraph::new(Line::from(vec![
                Span::styled("portwatch", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" / "),
                Span::raw("portz"),
            ]))
            .block(Block::default().borders(Borders::ALL).title("Ports"));
            frame.render_widget(title, chunks[0]);

            let mut table_state = TableState::default().with_selected(if app.items.is_empty() {
                None
            } else {
                Some(app.selected)
            });
            frame.render_stateful_widget(port_table(&app), chunks[1], &mut table_state);

            let status_style = if app.confirm_kill.is_some() {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            let status = Paragraph::new(app.status.clone())
                .style(status_style)
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title("Status"));
            frame.render_widget(status, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(250))? {
            match event::read()? {
                Event::Key(key) if should_quit(&key) => break,
                Event::Key(key) => match key.code {
                    KeyCode::Char('k') | KeyCode::Char('K') => app.request_or_confirm_kill(),
                    KeyCode::Char('r') | KeyCode::Char('R') => app.refresh(),
                    KeyCode::Down => app.select_next(),
                    KeyCode::Up => app.select_previous(),
                    KeyCode::Esc => app.cancel_confirmation(),
                    _ => {}
                },
                _ => {}
            }
        }
    }

    Ok(())
}

fn port_table(app: &App) -> Table<'_> {
    let rows = if app.items.is_empty() {
        vec![Row::new(vec![
            Cell::from("-"),
            Cell::from("-"),
            Cell::from("-"),
            Cell::from("No code TCP listeners found"),
            Cell::from(""),
        ])]
    } else {
        app.items.iter().map(process_row).collect::<Vec<_>>()
    };

    Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(18),
            Constraint::Length(22),
            Constraint::Min(24),
        ],
    )
    .header(
        Row::new(vec!["PORT", "PID", "COMMAND", "BIND", "ARGS"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Listening TCP ports"),
    )
    .row_highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ")
}

fn process_row(process: &PortProcess) -> Row<'_> {
    Row::new(vec![
        Cell::from(process.port.to_string()),
        Cell::from(process.pid.to_string()),
        Cell::from(process.command.clone()),
        Cell::from(format!("{}:{}", process.address, process.port)),
        Cell::from(process.display_command().to_string()),
    ])
}

fn should_quit(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
        || matches!(
            (key.code, key.modifiers),
            (KeyCode::Char('c'), KeyModifiers::CONTROL)
        )
}

struct TerminalGuard {
    terminal: Tui,
}

impl TerminalGuard {
    fn new() -> Result<Self> {
        enable_raw_mode().context("failed to enable terminal raw mode")?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).context("failed to initialize terminal")?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}
