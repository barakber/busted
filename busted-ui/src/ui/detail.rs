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
        // Title: action type pill badge + timestamp
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
    // ── Action section ───────────────────────────────────────────
    detail_card(ui, "ACTION", |ui| {
        let grid_id = ui.id().with("action_grid");
        egui::Grid::new(grid_id)
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
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
                        ..
                    } => {
                        kv(ui, "Provider", provider);
                        opt_kv(ui, "Model", model.as_deref());
                        opt_kv(ui, "SDK", sdk.as_deref());
                        opt_kv(ui, "SNI", sni.as_deref());
                        opt_kv(ui, "Endpoint", endpoint.as_deref());
                        kv(ui, "Bytes", &format_bytes(*bytes));
                        kv(ui, "Stream", if *stream { "yes" } else { "no" });
                        if let Some(c) = confidence {
                            kv(ui, "Confidence", &format!("{:.0}%", c * 100.0));
                        }
                        if let Some(true) = pii_detected {
                            kv_colored(ui, "PII", "DETECTED", style::PII_COLOR);
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
                        opt_kv(ui, "Model", model.as_deref());
                        opt_kv(ui, "SNI", sni.as_deref());
                        kv(ui, "Bytes", &format_bytes(*bytes));
                        if let Some(c) = confidence {
                            kv(ui, "Confidence", &format!("{:.0}%", c * 100.0));
                        }
                    }
                    AgenticAction::ToolCall {
                        tool_name,
                        provider,
                        ..
                    } => {
                        kv(ui, "Provider", provider);
                        kv(ui, "Tool", tool_name);
                    }
                    AgenticAction::ToolResult { tool_name, .. } => {
                        kv(ui, "Tool", tool_name);
                    }
                    AgenticAction::McpRequest {
                        method, category, ..
                    } => {
                        kv(ui, "Method", method);
                        opt_kv(ui, "Category", category.as_deref());
                    }
                    AgenticAction::McpResponse { method, .. } => {
                        kv(ui, "Method", method);
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
                        opt_kv(ui, "SNI", sni.as_deref());
                        opt_kv(ui, "Provider", provider.as_deref());
                        kv(ui, "Bytes", &format_bytes(*bytes));
                    }
                    AgenticAction::FileAccess { path, mode, reason } => {
                        kv(ui, "Path", path);
                        kv(ui, "Mode", mode);
                        opt_kv(ui, "Reason", reason.as_deref());
                    }
                    AgenticAction::FileData {
                        path,
                        direction,
                        bytes,
                        truncated,
                        ..
                    } => {
                        kv(ui, "Path", path);
                        kv(ui, "Direction", direction);
                        kv(ui, "Bytes", &format_bytes(*bytes));
                        if let Some(true) = truncated {
                            kv(ui, "Truncated", "yes");
                        }
                    }
                }
            });

        // Text blocks after the grid (they need full width)
        match &ev.action {
            AgenticAction::Prompt {
                system_prompt,
                user_message,
                ..
            } => {
                if let Some(sp) = system_prompt {
                    ui.add_space(4.0);
                    code_block(ui, "SYSTEM PROMPT", sp);
                }
                if let Some(um) = user_message {
                    ui.add_space(4.0);
                    code_block(ui, "USER MESSAGE", um);
                }
            }
            AgenticAction::ToolCall {
                input_json: Some(input),
                ..
            } => {
                ui.add_space(4.0);
                code_block(ui, "TOOL INPUT", input);
            }
            AgenticAction::ToolResult {
                output_preview: Some(output),
                ..
            } => {
                ui.add_space(4.0);
                code_block(ui, "TOOL OUTPUT", output);
            }
            AgenticAction::McpRequest {
                params_preview: Some(params),
                ..
            } => {
                ui.add_space(4.0);
                code_block(ui, "MCP PARAMS", params);
            }
            AgenticAction::McpResponse {
                result_preview: Some(result),
                ..
            } => {
                ui.add_space(4.0);
                code_block(ui, "MCP RESULT", result);
            }
            AgenticAction::FileData { content, .. } => {
                ui.add_space(4.0);
                code_block(ui, "FILE CONTENT", content);
            }
            _ => {}
        }
    });

    ui.add_space(8.0);

    // ── Process section ──────────────────────────────────────────
    detail_card(ui, "PROCESS", |ui| {
        let grid_id = ui.id().with("process_grid");
        egui::Grid::new(grid_id)
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
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
    });

    ui.add_space(8.0);

    // ── Policy section ───────────────────────────────────────────
    detail_card(ui, "POLICY", |ui| {
        let grid_id = ui.id().with("policy_grid");
        egui::Grid::new(grid_id)
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                if let Some(ref pol) = ev.policy {
                    grid_key(ui, "Decision");
                    style::policy_pill(ui, pol, Some(pol.as_str()));
                    ui.end_row();
                } else {
                    kv(ui, "Decision", "-");
                }
                if ev.pii_detected() {
                    kv_colored(ui, "PII", "DETECTED", style::PII_COLOR);
                }
            });
    });

    // ── Identity section ─────────────────────────────────────────
    if let Some(ref id) = ev.identity {
        ui.add_space(8.0);
        detail_card(ui, "IDENTITY", |ui| {
            let grid_id = ui.id().with("identity_grid");
            egui::Grid::new(grid_id)
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    kv(ui, "Confidence", &format!("{:.0}%", id.confidence * 100.0));
                    opt_kv(ui, "Match", id.match_type.as_deref());
                    if let Some(nodes) = id.graph_node_count {
                        let edges = id.graph_edge_count.unwrap_or(0);
                        kv(ui, "Graph", &format!("{nodes}n / {edges}e"));
                    }
                });
            if let Some(ref narrative) = id.narrative {
                ui.add_space(4.0);
                code_block(ui, "NARRATIVE", narrative);
            }
        });
    }

    ui.add_space(8.0);

    // ── Session section ──────────────────────────────────────────
    detail_card(ui, "SESSION", |ui| {
        let grid_id = ui.id().with("session_grid");
        egui::Grid::new(grid_id)
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                kv(ui, "ID", &ev.session_id);
            });
    });
}

// ── Card wrapper ────────────────────────────────────────────────────

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

// ── Grid row helpers ────────────────────────────────────────────────

fn grid_key(ui: &mut egui::Ui, key: &str) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.colored_label(style::DIM_TEXT, egui::RichText::new(key).size(11.0));
    });
}

fn kv(ui: &mut egui::Ui, key: &str, value: &str) {
    grid_key(ui, key);
    ui.colored_label(style::NORMAL_TEXT, value);
    ui.end_row();
}

fn opt_kv(ui: &mut egui::Ui, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        kv(ui, key, v);
    }
}

fn kv_colored(ui: &mut egui::Ui, key: &str, value: &str, color: egui::Color32) {
    grid_key(ui, key);
    ui.colored_label(color, egui::RichText::new(value).strong());
    ui.end_row();
}

// ── Code block ──────────────────────────────────────────────────────

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
            ui.colored_label(style::NORMAL_TEXT, egui::RichText::new(text).size(11.0));
        });
}
