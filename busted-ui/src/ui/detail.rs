use busted_types::agentic::{AgenticAction, BustedEvent};
use eframe::egui;

use super::style;
use crate::app::{format_bytes, App};

pub fn draw(ui: &mut egui::Ui, app: &App) {
    let event = match app.selected_event() {
        Some(ev) => ev,
        None => {
            ui.colored_label(style::DIM_TEXT, "No event selected");
            return;
        }
    };

    let action_type = event.action_type();
    let title_color = style::action_color(&event.action);

    ui.vertical(|ui| {
        // Title: action type pill badge
        ui.horizontal(|ui| {
            style::action_pill(ui, action_type, title_color);
            ui.add_space(8.0);
            ui.colored_label(style::DIM_TEXT, &event.timestamp);
        });
        ui.add_space(8.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_offset(egui::vec2(0.0, app.detail_scroll))
            .show(ui, |ui| {
                build_detail(ui, event);
            });
    });
}

fn build_detail(ui: &mut egui::Ui, ev: &BustedEvent) {
    // Action section
    detail_card(ui, "ACTION", |ui| {
        kv(ui, "Type", ev.action_type());

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
                kv(ui, "Provider", provider);
                if let Some(m) = model {
                    kv(ui, "Model", m);
                }
                if let Some(s) = sdk {
                    kv(ui, "SDK", s);
                }
                if let Some(sni) = sni {
                    kv(ui, "SNI", sni);
                }
                if let Some(ep) = endpoint {
                    kv(ui, "Endpoint", ep);
                }
                kv(ui, "Bytes", &format_bytes(*bytes));
                kv(ui, "Stream", &stream.to_string());
                if let Some(c) = confidence {
                    kv(ui, "Confidence", &format!("{:.0}%", c * 100.0));
                }
                if let Some(true) = pii_detected {
                    kv_colored(ui, "PII", "DETECTED", style::PII_COLOR);
                }
                if let Some(sp) = system_prompt {
                    ui.add_space(4.0);
                    code_block(ui, "SYSTEM PROMPT", sp);
                }
                if let Some(um) = user_message {
                    ui.add_space(4.0);
                    code_block(ui, "USER MESSAGE", um);
                }
            }
            AgenticAction::Response {
                provider,
                model,
                bytes,
                sni,
                confidence,
            } => {
                kv(ui, "Provider", provider);
                if let Some(m) = model {
                    kv(ui, "Model", m);
                }
                if let Some(sni) = sni {
                    kv(ui, "SNI", sni);
                }
                kv(ui, "Bytes", &format_bytes(*bytes));
                if let Some(c) = confidence {
                    kv(ui, "Confidence", &format!("{:.0}%", c * 100.0));
                }
            }
            AgenticAction::ToolCall {
                tool_name,
                input_json,
                provider,
            } => {
                kv(ui, "Provider", provider);
                kv(ui, "Tool", tool_name);
                if let Some(input) = input_json {
                    ui.add_space(4.0);
                    code_block(ui, "TOOL INPUT", input);
                }
            }
            AgenticAction::ToolResult {
                tool_name,
                output_preview,
            } => {
                kv(ui, "Tool", tool_name);
                if let Some(output) = output_preview {
                    ui.add_space(4.0);
                    code_block(ui, "TOOL OUTPUT", output);
                }
            }
            AgenticAction::McpRequest {
                method,
                category,
                params_preview,
            } => {
                kv(ui, "Method", method);
                if let Some(cat) = category {
                    kv(ui, "Category", cat);
                }
                if let Some(params) = params_preview {
                    ui.add_space(4.0);
                    code_block(ui, "MCP PARAMS", params);
                }
            }
            AgenticAction::McpResponse {
                method,
                result_preview,
            } => {
                kv(ui, "Method", method);
                if let Some(result) = result_preview {
                    ui.add_space(4.0);
                    code_block(ui, "MCP RESULT", result);
                }
            }
            AgenticAction::PiiDetected {
                direction,
                pii_types,
            } => {
                kv(ui, "Direction", direction);
                if let Some(types) = pii_types {
                    kv_colored(ui, "Types", &types.join(", "), style::PII_COLOR);
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
                kv(ui, "Kind", &format!("{kind:?}"));
                kv(ui, "Source", &format!("{src_ip}:{src_port}"));
                kv(ui, "Dest", &format!("{dst_ip}:{dst_port}"));
                if let Some(sni) = sni {
                    kv(ui, "SNI", sni);
                }
                if let Some(p) = provider {
                    kv(ui, "Provider", p);
                }
                kv(ui, "Bytes", &format_bytes(*bytes));
            }
        }
    });

    ui.add_space(8.0);

    // Process section
    detail_card(ui, "PROCESS", |ui| {
        kv(ui, "Name", &ev.process.name);
        kv(ui, "PID", &ev.process.pid.to_string());
        kv(ui, "UID", &ev.process.uid.to_string());
        if !ev.process.container_id.is_empty() {
            kv(ui, "Container", &ev.process.container_id);
        }
        if let Some(pod) = &ev.process.pod_name {
            let ns = ev.process.pod_namespace.as_deref().unwrap_or("default");
            kv(ui, "Pod", &format!("{ns}/{pod}"));
        }
    });

    ui.add_space(8.0);

    // Policy section
    detail_card(ui, "POLICY", |ui| {
        if let Some(ref pol) = ev.policy {
            ui.horizontal(|ui| {
                ui.colored_label(style::DIM_TEXT, egui::RichText::new("Decision").size(11.0));
                ui.add_space(8.0);
                style::policy_pill(ui, pol, Some(pol.as_str()));
            });
        } else {
            kv(ui, "Decision", "-");
        }
        if ev.pii_detected() {
            kv_colored(ui, "PII", "DETECTED", style::PII_COLOR);
        }
    });

    // Identity section
    if let Some(ref id) = ev.identity {
        ui.add_space(8.0);
        detail_card(ui, "IDENTITY", |ui| {
            kv(ui, "Confidence", &format!("{:.0}%", id.confidence * 100.0));
            if let Some(ref mt) = id.match_type {
                kv(ui, "Match", mt);
            }
            if let Some(nodes) = id.graph_node_count {
                let edges = id.graph_edge_count.unwrap_or(0);
                kv(ui, "Graph", &format!("{nodes}n / {edges}e"));
            }
            if let Some(ref narrative) = id.narrative {
                ui.add_space(4.0);
                code_block(ui, "NARRATIVE", narrative);
            }
        });
    }

    ui.add_space(8.0);

    // Session
    detail_card(ui, "SESSION", |ui| {
        kv(ui, "ID", &ev.session_id);
    });
}

fn detail_card(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui)) {
    style::card_frame().show(ui, |ui| {
        ui.colored_label(
            style::ACCENT_COLOR,
            egui::RichText::new(title).size(10.0).strong(),
        );
        // Separator line
        let rect = ui.max_rect();
        let y = ui.cursor().top();
        ui.painter().line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            egui::Stroke::new(1.0, style::BORDER_COLOR),
        );
        ui.add_space(4.0);
        content(ui);
    });
}

fn code_block(ui: &mut egui::Ui, label: &str, text: &str) {
    ui.colored_label(
        style::DIM_TEXT,
        egui::RichText::new(label).size(10.0).strong(),
    );
    egui::Frame::NONE
        .fill(style::SURFACE_2)
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            ui.colored_label(style::NORMAL_TEXT, text);
        });
}

fn kv(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.colored_label(
            style::DIM_TEXT,
            egui::RichText::new(format!("{key:>12}")).size(11.0),
        );
        ui.add_space(8.0);
        ui.colored_label(style::NORMAL_TEXT, value);
    });
}

fn kv_colored(ui: &mut egui::Ui, key: &str, value: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        ui.colored_label(
            style::DIM_TEXT,
            egui::RichText::new(format!("{key:>12}")).size(11.0),
        );
        ui.add_space(8.0);
        ui.colored_label(color, value);
    });
}
