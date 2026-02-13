use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Sparkline},
    Frame,
};

use crate::app::{App, ConnectionState};
use crate::ui::style;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::horizontal([
        Constraint::Length(24), // Title + mode
        Constraint::Min(20),    // Sparkline
        Constraint::Length(20), // Event rate + count
        Constraint::Length(3),  // Connection dot
    ])
    .split(area);

    // Title + mode badge
    let mode = match app.connection_state {
        ConnectionState::Demo => Span::styled(
            " DEMO ",
            Style::default()
                .fg(style::BRIGHT_TEXT)
                .bg(style::ACCENT_COLOR)
                .add_modifier(Modifier::BOLD),
        ),
        ConnectionState::Connected => Span::styled(
            " LIVE ",
            Style::default()
                .fg(style::BRIGHT_TEXT)
                .bg(style::POLICY_ALLOW_COLOR)
                .add_modifier(Modifier::BOLD),
        ),
        ConnectionState::Connecting => Span::styled(
            " ... ",
            Style::default()
                .fg(style::BRIGHT_TEXT)
                .bg(style::POLICY_AUDIT_COLOR),
        ),
    };

    let title_line = Line::from(vec![
        Span::styled(
            " [B] Busted ",
            Style::default()
                .fg(style::ACCENT_COLOR)
                .add_modifier(Modifier::BOLD),
        ),
        mode,
    ]);
    f.render_widget(title_line, chunks[0]);

    // Sparkline
    let data = app.sparkline_data();
    let sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::NONE))
        .data(&data)
        .style(Style::default().fg(style::ACCENT_COLOR));
    f.render_widget(sparkline, chunks[1]);

    // Rate + count
    let eps = app.events_per_second();
    let total = app.total_event_count;
    let pause_indicator = if app.paused { " PAUSED" } else { "" };
    let stats_line = Line::from(vec![
        Span::styled(format!("{eps:.1}/s"), style::normal_style()),
        Span::styled(format!("  {total}{pause_indicator}"), style::dim_style()),
    ]);
    f.render_widget(stats_line, chunks[2]);

    // Connection indicator
    let dot_color = match app.connection_state {
        ConnectionState::Connected | ConnectionState::Demo => style::POLICY_ALLOW_COLOR,
        ConnectionState::Connecting => style::POLICY_AUDIT_COLOR,
    };
    let dot = Line::from(Span::styled(" \u{25CF}", Style::default().fg(dot_color)));
    f.render_widget(dot, chunks[3]);
}
