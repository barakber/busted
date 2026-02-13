use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    Frame,
};

use crate::app::{App, InputMode};
use crate::ui::style as s;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = Vec::new();

    // Search field
    match app.input_mode {
        InputMode::Search => {
            spans.push(Span::styled(
                " /",
                Style::default()
                    .fg(s::ACCENT_COLOR)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                &app.search_query,
                Style::default().fg(s::BRIGHT_TEXT),
            ));
            spans.push(Span::styled(
                "\u{2588}",
                Style::default().fg(s::ACCENT_COLOR),
            )); // cursor block
        }
        InputMode::Normal => {
            if app.search_query.is_empty() {
                spans.push(Span::styled(" /search\u{2026}", s::dim_style()));
            } else {
                spans.push(Span::styled(" /", s::dim_style()));
                spans.push(Span::styled(
                    &app.search_query,
                    Style::default().fg(s::ACCENT_COLOR),
                ));
            }
        }
    }

    spans.push(Span::styled("  ", s::dim_style()));

    // Provider filter
    let prov = app.provider_filter.as_deref().unwrap_or("All");
    spans.push(Span::styled("Provider:", s::dim_style()));
    spans.push(Span::styled(
        prov,
        if app.provider_filter.is_some() {
            Style::default().fg(s::ACCENT_COLOR)
        } else {
            s::dim_style()
        },
    ));

    spans.push(Span::styled("  ", s::dim_style()));

    // Type filter
    let typ = app.type_filter.as_deref().unwrap_or("All");
    spans.push(Span::styled("Type:", s::dim_style()));
    spans.push(Span::styled(
        typ,
        if app.type_filter.is_some() {
            Style::default().fg(s::ACCENT_COLOR)
        } else {
            s::dim_style()
        },
    ));

    if app.has_active_filters() {
        spans.push(Span::styled(
            "  [C:clear]",
            Style::default().fg(s::POLICY_AUDIT_COLOR),
        ));
    }

    let line = Line::from(spans);
    f.render_widget(line, area);
}
