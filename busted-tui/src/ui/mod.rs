pub mod detail;
pub mod events;
pub mod filter;
pub mod header;
pub mod help;
pub mod processes;
pub mod providers;
pub mod stats;
pub mod style;

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    Frame,
};

use crate::app::{App, InputMode, Tab};

pub fn draw(f: &mut Frame, app: &mut App) {
    let full = f.area();

    // Inset: 1-column padding on the right so content doesn't hug the edge
    let area = Rect {
        width: full.width.saturating_sub(1),
        ..full
    };

    // Main vertical layout: header | stats | tabs | filter | content | footer
    let main_chunks = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1), // stats
        Constraint::Length(1), // tabs
        Constraint::Length(1), // filter
        Constraint::Min(5),    // content
        Constraint::Length(1), // footer
    ])
    .split(area);

    // Store content height so key handlers can compute page scroll
    app.content_height = main_chunks[4].height;

    header::draw(f, main_chunks[0], app);
    stats::draw(f, main_chunks[1], app);
    draw_tabs(f, main_chunks[2], app);
    filter::draw(f, main_chunks[3], app);
    draw_content(f, main_chunks[4], app);
    draw_footer(f, main_chunks[5], app);

    // Help popup overlay
    if app.show_help {
        help::draw(f, area);
    }
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![Span::styled(" ", style::dim_style())];
    for (i, tab) in Tab::ALL.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", style::dim_style()));
        }
        if *tab == app.active_tab {
            spans.push(Span::styled(
                format!("[{}]", tab.label()),
                Style::default()
                    .fg(style::ACCENT_COLOR)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", tab.label()),
                style::dim_style(),
            ));
        }
    }
    f.render_widget(Line::from(spans), area);
}

fn draw_content(f: &mut Frame, area: Rect, app: &mut App) {
    if app.show_detail && app.active_tab == Tab::Events {
        // Split horizontally: events | detail
        let min_detail_width = 40u16;
        let detail_pct = 40;
        let detail_width = (area.width * detail_pct / 100)
            .max(min_detail_width)
            .min(area.width);
        let events_width = area.width.saturating_sub(detail_width);

        let content_chunks = Layout::horizontal([
            Constraint::Length(events_width),
            Constraint::Length(detail_width),
        ])
        .split(area);

        events::draw(f, content_chunks[0], app);
        detail::draw(f, content_chunks[1], app);
    } else {
        match app.active_tab {
            Tab::Events => events::draw(f, area, app),
            Tab::Processes => processes::draw(f, area, app),
            Tab::Providers => providers::draw(f, area, app),
        }
    }
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let a = Style::default().fg(style::ACCENT_COLOR);
    let d = style::dim_style();
    let spans = if app.show_detail {
        vec![
            Span::styled(" Esc", a),
            Span::styled(":Close  ", d),
            Span::styled("j/k", a),
            Span::styled(":Scroll  ", d),
            Span::styled("C-d/u", a),
            Span::styled(":HalfPg  ", d),
            Span::styled("n/N", a),
            Span::styled(":Next/Prev  ", d),
            Span::styled("?", a),
            Span::styled(":Help", d),
        ]
    } else if app.input_mode == InputMode::Search {
        vec![
            Span::styled(" Enter", a),
            Span::styled(":Search  ", d),
            Span::styled("Esc", a),
            Span::styled(":Cancel", d),
        ]
    } else {
        vec![
            Span::styled(" q", a),
            Span::styled(":Quit  ", d),
            Span::styled("j/k", a),
            Span::styled(":Nav  ", d),
            Span::styled("C-d/u", a),
            Span::styled(":HalfPg  ", d),
            Span::styled("/", a),
            Span::styled(":Search  ", d),
            Span::styled("Enter", a),
            Span::styled(":Detail  ", d),
            Span::styled("Tab", a),
            Span::styled(":Tabs  ", d),
            Span::styled("Space", a),
            Span::styled(":Pause  ", d),
            Span::styled("?", a),
            Span::styled(":Help", d),
        ]
    };
    f.render_widget(Line::from(spans), area);
}
