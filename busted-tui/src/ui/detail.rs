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

fn build_detail_lines(ev: &BustedEvent, lines: &mut Vec<Line<'static>>) {
    // Action section
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
            if let Some(m) = model {
                kv("Model", m, lines);
            }
            if let Some(s) = sdk {
                kv("SDK", s, lines);
            }
            if let Some(sni) = sni {
                kv("SNI", sni, lines);
            }
            if let Some(ep) = endpoint {
                kv("Endpoint", ep, lines);
            }
            kv("Bytes", &format_bytes(*bytes), lines);
            kv("Stream", &stream.to_string(), lines);
            if let Some(c) = confidence {
                kv("Confidence", &format!("{:.0}%", c * 100.0), lines);
            }
            if let Some(true) = pii_detected {
                kv_colored("PII", "DETECTED", s::PII_COLOR, lines);
            }
            if let Some(sp) = system_prompt {
                lines.push(Line::from(""));
                section_header("SYSTEM PROMPT", lines);
                for l in sp.lines() {
                    lines.push(Line::from(Span::styled(format!("  {l}"), s::dim_style())));
                }
            }
            if let Some(um) = user_message {
                lines.push(Line::from(""));
                section_header("USER MESSAGE", lines);
                for l in um.lines() {
                    lines.push(Line::from(Span::styled(
                        format!("  {l}"),
                        s::normal_style(),
                    )));
                }
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
            if let Some(m) = model {
                kv("Model", m, lines);
            }
            if let Some(sni) = sni {
                kv("SNI", sni, lines);
            }
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
                lines.push(Line::from(""));
                section_header("TOOL INPUT", lines);
                for l in input.lines() {
                    lines.push(Line::from(Span::styled(format!("  {l}"), s::dim_style())));
                }
            }
        }
        AgenticAction::ToolResult {
            tool_name,
            output_preview,
        } => {
            kv("Tool", tool_name, lines);
            if let Some(output) = output_preview {
                lines.push(Line::from(""));
                section_header("TOOL OUTPUT", lines);
                for l in output.lines() {
                    lines.push(Line::from(Span::styled(format!("  {l}"), s::dim_style())));
                }
            }
        }
        AgenticAction::McpRequest {
            method,
            category,
            params_preview,
        } => {
            kv("Method", method, lines);
            if let Some(cat) = category {
                kv("Category", cat, lines);
            }
            if let Some(params) = params_preview {
                lines.push(Line::from(""));
                section_header("MCP PARAMS", lines);
                for l in params.lines() {
                    lines.push(Line::from(Span::styled(format!("  {l}"), s::dim_style())));
                }
            }
        }
        AgenticAction::McpResponse {
            method,
            result_preview,
        } => {
            kv("Method", method, lines);
            if let Some(result) = result_preview {
                lines.push(Line::from(""));
                section_header("MCP RESULT", lines);
                for l in result.lines() {
                    lines.push(Line::from(Span::styled(format!("  {l}"), s::dim_style())));
                }
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
            if let Some(sni) = sni {
                kv("SNI", sni, lines);
            }
            if let Some(p) = provider {
                kv("Provider", p, lines);
            }
            kv("Bytes", &format_bytes(*bytes), lines);
        }
    }

    // Process section
    lines.push(Line::from(""));
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

    // Policy section
    lines.push(Line::from(""));
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

    // Identity section
    if let Some(ref id) = ev.identity {
        lines.push(Line::from(""));
        section_header("IDENTITY", lines);
        kv(
            "Confidence",
            &format!("{:.0}%", id.confidence * 100.0),
            lines,
        );
        if let Some(ref mt) = id.match_type {
            kv("Match", mt, lines);
        }
        if let Some(nodes) = id.graph_node_count {
            let edges = id.graph_edge_count.unwrap_or(0);
            kv("Graph", &format!("{nodes}n / {edges}e"), lines);
        }
        if let Some(ref narrative) = id.narrative {
            lines.push(Line::from(""));
            section_header("NARRATIVE", lines);
            for l in narrative.lines() {
                lines.push(Line::from(Span::styled(format!("  {l}"), s::dim_style())));
            }
        }
    }

    // Session
    lines.push(Line::from(""));
    kv("Session", &ev.session_id, lines);
}

fn section_header(title: &str, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(Span::styled(
        format!(" {title}"),
        Style::default()
            .fg(s::DIM_TEXT)
            .add_modifier(Modifier::BOLD),
    )));
}

fn kv(key: &str, value: &str, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(vec![
        Span::styled(format!("  {key:>12}  "), s::dim_style()),
        Span::styled(value.to_string(), s::normal_style()),
    ]));
}

fn kv_colored(
    key: &str,
    value: &str,
    color: ratatui::style::Color,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(Line::from(vec![
        Span::styled(format!("  {key:>12}  "), s::dim_style()),
        Span::styled(value.to_string(), Style::default().fg(color)),
    ]));
}
