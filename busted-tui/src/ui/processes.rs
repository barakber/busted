use ratatui::{
    layout::Constraint,
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

use crate::app::{format_bytes, App};
use crate::ui::style as s;

pub fn draw(f: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let stats = app.process_stats();

    let header = Row::new(vec![
        Cell::from("Process"),
        Cell::from("PID"),
        Cell::from("Events"),
        Cell::from("Bytes"),
        Cell::from("PII"),
        Cell::from("Providers"),
    ])
    .style(
        Style::default()
            .fg(s::BRIGHT_TEXT)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let rows: Vec<Row> = stats
        .iter()
        .map(|stat| {
            let pii_style = if stat.pii_count > 0 {
                Style::default().fg(s::PII_COLOR)
            } else {
                s::dim_style()
            };
            Row::new(vec![
                Cell::from(Span::styled(stat.name.clone(), s::normal_style())),
                Cell::from(Span::styled(stat.pid.to_string(), s::dim_style())),
                Cell::from(Span::styled(
                    stat.event_count.to_string(),
                    s::normal_style(),
                )),
                Cell::from(Span::styled(format_bytes(stat.bytes), s::normal_style())),
                Cell::from(Span::styled(stat.pii_count.to_string(), pii_style)),
                Cell::from(Span::styled(stat.providers.join(", "), s::dim_style())),
            ])
        })
        .collect();

    let widths = [
        Constraint::Fill(1),    // Process (flexible)
        Constraint::Length(7),  // PID (fixed)
        Constraint::Length(8),  // Events (fixed)
        Constraint::Length(10), // Bytes (fixed)
        Constraint::Length(5),  // PII (fixed)
        Constraint::Fill(2),    // Providers (flexible, gets 2x share)
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE))
        .row_highlight_style(s::selected_style());

    f.render_stateful_widget(table, area, &mut app.process_table_state);
}
