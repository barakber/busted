use busted_types::agentic::BustedEvent;
use ratatui::{
    layout::Constraint,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

use crate::app::{action_arrow, format_bytes, App};
use crate::ui::style;

pub fn draw(f: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let filtered = app.filtered_events();

    let header = Row::new(vec![
        Cell::from("Time"),
        Cell::from("Action"),
        Cell::from("Process"),
        Cell::from("PID"),
        Cell::from("Provider"),
        Cell::from("Destination"),
        Cell::from("Bytes"),
        Cell::from("Pol"),
    ])
    .style(
        Style::default()
            .fg(style::BRIGHT_TEXT)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let rows: Vec<Row> = filtered.iter().map(|ev| event_row(ev)).collect();

    let widths = [
        Constraint::Length(12), // Time (fixed)
        Constraint::Length(14), // Action: arrow + type (fixed)
        Constraint::Fill(1),    // Process (flexible)
        Constraint::Length(6),  // PID (fixed)
        Constraint::Fill(1),    // Provider (flexible)
        Constraint::Fill(2),    // Destination (flexible, gets 2x share)
        Constraint::Length(7),  // Bytes (fixed)
        Constraint::Length(5),  // Policy (fixed)
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE))
        .row_highlight_style(style::selected_style());

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn event_row(ev: &BustedEvent) -> Row<'static> {
    let action_color = style::action_color(&ev.action);
    let arrow = action_arrow(&ev.action);
    let action_type = ev.action_type();

    let time = ev.timestamp.clone();
    let time_short = if time.len() > 12 {
        time[..12].to_string()
    } else {
        time
    };

    let provider = ev.provider().unwrap_or("-").to_string();
    let dest = ev
        .file_path()
        .map(|p| {
            // Show last ~30 chars of path to fit column
            if p.len() > 30 {
                format!("...{}", &p[p.len() - 27..])
            } else {
                p.to_string()
            }
        })
        .or_else(|| ev.sni().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string());
    let bytes = ev.bytes();
    let bytes_str = if bytes > 0 {
        format_bytes(bytes)
    } else {
        "-".to_string()
    };
    let policy = ev.policy.as_deref().unwrap_or("-").to_string();
    let policy_color = style::policy_color(ev.policy.as_deref());

    let action_cell = Cell::from(Line::from(vec![
        Span::styled(format!("{arrow} "), Style::default().fg(action_color)),
        Span::styled(action_type.to_string(), Style::default().fg(action_color)),
    ]));

    let row = Row::new(vec![
        Cell::from(Span::styled(time_short, style::dim_style())),
        action_cell,
        Cell::from(Span::styled(ev.process.name.clone(), style::normal_style())),
        Cell::from(Span::styled(ev.process.pid.to_string(), style::dim_style())),
        Cell::from(Span::styled(provider, style::normal_style())),
        Cell::from(Span::styled(dest, style::dim_style())),
        Cell::from(Span::styled(bytes_str, style::normal_style())),
        Cell::from(Span::styled(policy, Style::default().fg(policy_color))),
    ]);

    if ev.pii_detected() {
        row.style(style::pii_row_style())
    } else {
        row
    }
}
