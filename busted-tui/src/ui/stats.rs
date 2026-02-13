use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    Frame,
};

use crate::app::{format_bytes, App};
use crate::ui::style as s;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let total = app.events.len();
    let bytes = app.total_bytes();
    let procs = app.unique_processes();
    let pii = app.pii_count();
    let (allow, audit, deny) = app.policy_breakdown();

    let top_providers: Vec<String> = app
        .provider_stats()
        .iter()
        .take(3)
        .map(|p| p.name.clone())
        .collect();
    let providers_str = if top_providers.is_empty() {
        String::new()
    } else {
        format!("  {}", top_providers.join(", "))
    };

    let line = Line::from(vec![
        Span::styled(" Events:", s::dim_style()),
        Span::styled(format!("{total}"), s::normal_style()),
        Span::styled("  Data:", s::dim_style()),
        Span::styled(format_bytes(bytes), s::normal_style()),
        Span::styled("  Procs:", s::dim_style()),
        Span::styled(format!("{procs}"), s::normal_style()),
        Span::styled("  PII:", s::dim_style()),
        Span::styled(
            format!("{pii}"),
            if pii > 0 {
                Style::default().fg(s::PII_COLOR)
            } else {
                s::normal_style()
            },
        ),
        Span::styled("  A:", s::dim_style()),
        Span::styled(
            format!("{allow}"),
            Style::default().fg(s::POLICY_ALLOW_COLOR),
        ),
        Span::styled(" U:", s::dim_style()),
        Span::styled(
            format!("{audit}"),
            Style::default().fg(s::POLICY_AUDIT_COLOR),
        ),
        Span::styled(" D:", s::dim_style()),
        Span::styled(format!("{deny}"), Style::default().fg(s::POLICY_DENY_COLOR)),
        Span::styled(providers_str, s::dim_style()),
    ]);
    f.render_widget(line, area);
}
