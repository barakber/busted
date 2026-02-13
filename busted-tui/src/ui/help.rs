use ratatui::{
    layout::{Constraint, Flex, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::ui::style as s;

const BINDINGS: &[(&str, &str)] = &[
    ("Navigation:", ""),
    ("j / k / \u{2191} / \u{2193}", "Move selection up / down"),
    ("Ctrl-d / Ctrl-u", "Half-page down / up"),
    ("Ctrl-f / Ctrl-b", "Full-page down / up"),
    ("PgDn / PgUp", "Full-page down / up"),
    ("g / Home", "Jump to top"),
    ("G / End", "Jump to bottom"),
    ("H / M / L", "Select high / mid / low in page"),
    ("", ""),
    ("Actions:", ""),
    ("Enter", "Toggle detail panel"),
    ("Esc", "Close detail / clear search"),
    ("Space", "Pause / resume stream"),
    ("/", "Enter search mode"),
    ("Tab / Shift-Tab", "Cycle tabs"),
    ("1 / 2 / 3", "Jump to tab"),
    ("c", "Clear events"),
    ("C", "Clear filters"),
    ("p", "Cycle provider filter"),
    ("t", "Cycle type filter"),
    ("q / Ctrl-C", "Quit"),
    ("?", "Toggle this help"),
    ("", ""),
    ("In detail panel:", ""),
    ("j / k", "Scroll detail content"),
    ("Ctrl-d / Ctrl-u", "Half-page scroll detail"),
    ("g / G", "Top / bottom of detail"),
    ("n / N", "Next / previous event"),
    ("Esc", "Close detail"),
];

pub fn draw(f: &mut Frame, area: Rect) {
    let popup_area = centered_rect(50, 70, area);
    f.render_widget(Clear, popup_area);

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Key Bindings",
            Style::default()
                .fg(s::ACCENT_COLOR)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for (key, desc) in BINDINGS {
        if key.is_empty() {
            lines.push(Line::from(""));
            continue;
        }
        if desc.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("  {key}"),
                Style::default()
                    .fg(s::BRIGHT_TEXT)
                    .add_modifier(Modifier::BOLD),
            )));
            continue;
        }
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {key:>18}  "),
                Style::default().fg(s::ACCENT_COLOR),
            ),
            Span::styled(desc.to_string(), s::normal_style()),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press ? or Esc to close",
        s::dim_style(),
    )));

    let help = Paragraph::new(lines).block(
        Block::default()
            .title(" Help ")
            .title_style(
                Style::default()
                    .fg(s::ACCENT_COLOR)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(s::BORDER_COLOR))
            .style(Style::default().bg(s::HEADER_BG)),
    );

    f.render_widget(help, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)])
        .flex(Flex::Center)
        .split(area);
    Layout::horizontal([Constraint::Percentage(percent_x)])
        .flex(Flex::Center)
        .split(vertical[0])[0]
}
