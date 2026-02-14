use busted_types::agentic::{AgenticAction, BustedEvent};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::{format_bytes, App};
use crate::ui::style as s;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let event = match app.selected_event() {
        Some(ev) => ev,
        None => {
            let empty = Paragraph::new("No event selected")
                .style(s::dim_style())
                .block(
                    Block::default()
                        .title(" Detail ")
                        .borders(Borders::LEFT)
                        .border_style(Style::default().fg(s::BORDER_COLOR)),
                );
            f.render_widget(empty, area);
            return;
        }
    };

    let mut lines = Vec::new();
    build_detail_lines(event, &mut lines);

    let scroll = app.detail_scroll as u16;
    let para = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(format!(" {} ", event.action_type()))
                .title_style(
                    Style::default()
                        .fg(s::action_color(&event.action))
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::LEFT)
                .border_style(Style::default().fg(s::BORDER_COLOR)),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    f.render_widget(para, area);
}

/// Width of the key column (characters).
const KEY_W: usize = 14;

fn build_detail_lines(ev: &BustedEvent, lines: &mut Vec<Line<'static>>) {
    // ── Action ───────────────────────────────────────────────────
    section_header("ACTION", lines);
    kv("Time", &ev.timestamp, lines);
    kv("Type", ev.action_type(), lines);

    match &ev.action {
        AgenticAction::Prompt {
            provider,
            model,
            sdk,
            bytes,
            sni,
            endpoint,
            stream,
            confidence,
            pii_detected,
            user_message,
            system_prompt,
            ..
        } => {
            kv("Provider", provider, lines);
            opt_kv("Model", model.as_deref(), lines);
            opt_kv("SDK", sdk.as_deref(), lines);
            opt_kv("SNI", sni.as_deref(), lines);
            opt_kv("Endpoint", endpoint.as_deref(), lines);
            kv("Bytes", &format_bytes(*bytes), lines);
            kv("Stream", if *stream { "yes" } else { "no" }, lines);
            if let Some(c) = confidence {
                kv("Confidence", &format!("{:.0}%", c * 100.0), lines);
            }
            if let Some(true) = pii_detected {
                kv_colored("PII", "DETECTED", s::PII_COLOR, lines);
            }
            if let Some(sp) = system_prompt {
                text_block("SYSTEM PROMPT", sp, lines);
            }
            if let Some(um) = user_message {
                text_block("USER MESSAGE", um, lines);
            }
        }
        AgenticAction::Response {
            provider,
            model,
            bytes,
            sni,
            confidence,
        } => {
            kv("Provider", provider, lines);
            opt_kv("Model", model.as_deref(), lines);
            opt_kv("SNI", sni.as_deref(), lines);
            kv("Bytes", &format_bytes(*bytes), lines);
            if let Some(c) = confidence {
                kv("Confidence", &format!("{:.0}%", c * 100.0), lines);
            }
        }
        AgenticAction::ToolCall {
            tool_name,
            input_json,
            provider,
        } => {
            kv("Provider", provider, lines);
            kv("Tool", tool_name, lines);
            if let Some(input) = input_json {
                text_block("TOOL INPUT", input, lines);
            }
        }
        AgenticAction::ToolResult {
            tool_name,
            output_preview,
        } => {
            kv("Tool", tool_name, lines);
            if let Some(output) = output_preview {
                text_block("TOOL OUTPUT", output, lines);
            }
        }
        AgenticAction::McpRequest {
            method,
            category,
            params_preview,
        } => {
            kv("Method", method, lines);
            opt_kv("Category", category.as_deref(), lines);
            if let Some(params) = params_preview {
                text_block("MCP PARAMS", params, lines);
            }
        }
        AgenticAction::McpResponse {
            method,
            result_preview,
        } => {
            kv("Method", method, lines);
            if let Some(result) = result_preview {
                text_block("MCP RESULT", result, lines);
            }
        }
        AgenticAction::PiiDetected {
            direction,
            pii_types,
        } => {
            kv("Direction", direction, lines);
            if let Some(types) = pii_types {
                kv_colored("Types", &types.join(", "), s::PII_COLOR, lines);
            }
        }
        AgenticAction::Network {
            kind,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            bytes,
            sni,
            provider,
        } => {
            kv("Kind", &format!("{kind:?}"), lines);
            kv("Source", &format!("{src_ip}:{src_port}"), lines);
            kv("Dest", &format!("{dst_ip}:{dst_port}"), lines);
            opt_kv("SNI", sni.as_deref(), lines);
            opt_kv("Provider", provider.as_deref(), lines);
            kv("Bytes", &format_bytes(*bytes), lines);
        }
    }

    // ── Process ──────────────────────────────────────────────────
    section_header("PROCESS", lines);
    kv("Name", &ev.process.name, lines);
    kv("PID", &ev.process.pid.to_string(), lines);
    kv("UID", &ev.process.uid.to_string(), lines);
    if !ev.process.container_id.is_empty() {
        kv("Container", &ev.process.container_id, lines);
    }
    if let Some(pod) = &ev.process.pod_name {
        let ns = ev.process.pod_namespace.as_deref().unwrap_or("default");
        kv("Pod", &format!("{ns}/{pod}"), lines);
    }

    // ── Policy ───────────────────────────────────────────────────
    section_header("POLICY", lines);
    if let Some(ref pol) = ev.policy {
        let color = s::policy_color(Some(pol.as_str()));
        kv_colored("Decision", pol, color, lines);
    } else {
        kv("Decision", "-", lines);
    }
    if ev.pii_detected() {
        kv_colored("PII", "DETECTED", s::PII_COLOR, lines);
    }

    // ── Identity ─────────────────────────────────────────────────
    if let Some(ref id) = ev.identity {
        section_header("IDENTITY", lines);
        kv(
            "Confidence",
            &format!("{:.0}%", id.confidence * 100.0),
            lines,
        );
        opt_kv("Match", id.match_type.as_deref(), lines);
        if let Some(nodes) = id.graph_node_count {
            let edges = id.graph_edge_count.unwrap_or(0);
            kv("Graph", &format!("{nodes}n / {edges}e"), lines);
        }
        if let Some(ref narrative) = id.narrative {
            text_block("NARRATIVE", narrative, lines);
        }
    }

    // ── Session ──────────────────────────────────────────────────
    section_header("SESSION", lines);
    kv("ID", &ev.session_id, lines);
}

// ── Formatting helpers ──────────────────────────────────────────────

fn section_header(title: &str, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));
    // "─── TITLE ─────────────────"
    let label = format!(" {title} ");
    let pad = 30usize.saturating_sub(label.len() + 3);
    let rule = "─".repeat(pad);
    lines.push(Line::from(vec![
        Span::styled("───", Style::default().fg(s::BORDER_COLOR)),
        Span::styled(
            label,
            Style::default()
                .fg(s::ACCENT_COLOR)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(rule, Style::default().fg(s::BORDER_COLOR)),
    ]));
}

fn kv(key: &str, value: &str, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(vec![
        Span::styled(
            format!("  {key:>width$}", width = KEY_W),
            Style::default().fg(s::DIM_TEXT).add_modifier(Modifier::DIM),
        ),
        Span::styled(" │ ", Style::default().fg(s::BORDER_COLOR)),
        Span::styled(value.to_string(), s::normal_style()),
    ]));
}

fn opt_kv(key: &str, value: Option<&str>, lines: &mut Vec<Line<'static>>) {
    if let Some(v) = value {
        kv(key, v, lines);
    }
}

fn kv_colored(
    key: &str,
    value: &str,
    color: ratatui::style::Color,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(Line::from(vec![
        Span::styled(
            format!("  {key:>width$}", width = KEY_W),
            Style::default().fg(s::DIM_TEXT).add_modifier(Modifier::DIM),
        ),
        Span::styled(" │ ", Style::default().fg(s::BORDER_COLOR)),
        Span::styled(
            value.to_string(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ]));
}

fn text_block(label: &str, text: &str, lines: &mut Vec<Line<'static>>) {
    // Sub-section rule
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(format!("  {:>width$}", "", width = KEY_W), Style::default()),
        Span::styled(" ┌ ", Style::default().fg(s::BORDER_COLOR)),
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(s::DIM_TEXT)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    for l in text.lines() {
        lines.push(Line::from(vec![
            Span::styled(format!("  {:>width$}", "", width = KEY_W), Style::default()),
            Span::styled(" │ ", Style::default().fg(s::BORDER_COLOR)),
            Span::styled(l.to_string(), s::dim_style()),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled(format!("  {:>width$}", "", width = KEY_W), Style::default()),
        Span::styled(" └─", Style::default().fg(s::BORDER_COLOR)),
    ]));
}
