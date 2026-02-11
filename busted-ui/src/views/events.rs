use crate::app::BustedApp;
use busted_types::processed::ProcessedEvent;
use egui_extras::{Column, TableBuilder};

/// Categorize an event for the Action filter dropdown.
fn event_action_category(e: &ProcessedEvent) -> &'static str {
    if e.mcp_method.is_some() {
        return "MCP";
    }
    match e.event_type.as_str() {
        "TLS_DATA_WRITE" => "LLM Request",
        "TLS_DATA_READ" => "LLM Response",
        _ => "Network",
    }
}

/// Build the compact action string for the Action column.
fn action_label(e: &ProcessedEvent) -> String {
    if let Some(ref mcp) = e.mcp_method {
        let cat = e.mcp_category.as_deref().unwrap_or("");
        if cat.is_empty() {
            format!("MCP {}", mcp)
        } else {
            format!("MCP {} ({})", mcp, cat)
        }
    } else {
        let provider = e
            .llm_provider
            .as_deref()
            .or(e.provider.as_deref())
            .unwrap_or("");
        let model = e.llm_model.as_deref().unwrap_or("");
        match (provider, model) {
            ("", "") => "-".to_string(),
            (p, "") => p.to_string(),
            (p, m) => format!("{} {}", p, m),
        }
    }
}

/// Direction arrow for the Dir column.
fn direction_arrow(e: &ProcessedEvent) -> &'static str {
    match e.event_type.as_str() {
        "TLS_DATA_WRITE" => "\u{00bb}", // »
        "TLS_DATA_READ" => "\u{00ab}",  // «
        _ => "",
    }
}

/// Compact flags string.
fn flags_label(e: &ProcessedEvent) -> String {
    let mut parts = Vec::new();
    if e.pii_detected == Some(true) {
        parts.push("PII");
    }
    if e.llm_stream == Some(true) {
        parts.push("STR");
    }
    parts.join(" ")
}

/// Truncate a string at a character boundary.
fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => format!("{}...", &s[..idx]),
        None => s.to_string(),
    }
}

pub fn show(ui: &mut egui::Ui, app: &mut BustedApp) {
    // Filters
    ui.horizontal(|ui| {
        ui.label("Action:");
        egui::ComboBox::from_id_salt("filter_action")
            .selected_text(if app.filter_action.is_empty() {
                "All"
            } else {
                &app.filter_action
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.filter_action, String::new(), "All");
                for action in &["LLM Request", "LLM Response", "MCP", "Network"] {
                    ui.selectable_value(&mut app.filter_action, action.to_string(), *action);
                }
            });

        ui.label("Provider:");
        egui::ComboBox::from_id_salt("filter_provider")
            .selected_text(if app.filter_provider.is_empty() {
                "All"
            } else {
                &app.filter_provider
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.filter_provider, String::new(), "All");
                for provider in app.provider_stats.keys() {
                    ui.selectable_value(
                        &mut app.filter_provider,
                        provider.clone(),
                        provider.as_str(),
                    );
                }
            });

        ui.label("Process:");
        ui.text_edit_singleline(&mut app.filter_process);

        ui.checkbox(&mut app.show_network_events, "Network");
        ui.checkbox(&mut app.auto_scroll, "Auto-scroll");
    });

    ui.separator();

    // Filtered events — collect indices into app.events
    let filtered: Vec<usize> = app
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            // Hide non-TLS events unless show_network_events is on
            if !app.show_network_events && !e.event_type.starts_with("TLS_DATA_") {
                return false;
            }
            // Action filter
            if !app.filter_action.is_empty() && event_action_category(e) != app.filter_action {
                return false;
            }
            // Provider filter
            if !app.filter_provider.is_empty() {
                match &e.provider {
                    Some(p) if p == &app.filter_provider => {}
                    _ => return false,
                }
            }
            // Process name filter
            if !app.filter_process.is_empty()
                && !e
                    .process_name
                    .to_lowercase()
                    .contains(&app.filter_process.to_lowercase())
            {
                return false;
            }
            true
        })
        .map(|(i, _)| i)
        .collect();

    let row_count = filtered.len();

    let table = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .sense(egui::Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(80.0)) // Time
        .column(Column::auto().at_least(110.0)) // Process
        .column(Column::exact(30.0)) // Dir
        .column(Column::auto().at_least(200.0)) // Action
        .column(Column::auto().at_least(120.0)) // SDK
        .column(Column::remainder().at_least(150.0)) // Content
        .column(Column::auto().at_least(55.0)) // Policy
        .column(Column::auto().at_least(70.0)) // Flags
        .min_scrolled_height(0.0);

    let table = if app.auto_scroll {
        table.scroll_to_row(row_count.saturating_sub(1), None)
    } else {
        table
    };

    table
        .header(20.0, |mut header| {
            header.col(|ui| {
                ui.strong("Time");
            });
            header.col(|ui| {
                ui.strong("Process");
            });
            header.col(|ui| {
                ui.strong("Dir");
            });
            header.col(|ui| {
                ui.strong("Action");
            });
            header.col(|ui| {
                ui.strong("SDK");
            });
            header.col(|ui| {
                ui.strong("Content");
            });
            header.col(|ui| {
                ui.strong("Policy");
            });
            header.col(|ui| {
                ui.strong("Flags");
            });
        })
        .body(|body| {
            body.rows(18.0, row_count, |mut row| {
                let event_idx = filtered[row.index()];
                let selected = app.selected_event_idx == Some(event_idx);
                row.set_selected(selected);

                let event = &app.events[event_idx];

                row.col(|ui| {
                    // Show just HH:MM:SS (trim millis for compactness)
                    let ts = if event.timestamp.len() > 8 {
                        &event.timestamp[..8]
                    } else {
                        &event.timestamp
                    };
                    ui.label(ts);
                });
                row.col(|ui| {
                    ui.label(format!("{} ({})", event.process_name, event.pid));
                });
                row.col(|ui| {
                    ui.label(direction_arrow(event));
                });
                row.col(|ui| {
                    ui.label(action_label(event));
                });
                row.col(|ui| {
                    ui.label(event.agent_sdk.as_deref().unwrap_or("-"));
                });
                row.col(|ui| {
                    let content = event.llm_user_message.as_deref().unwrap_or("-");
                    ui.label(truncate_chars(content, 60));
                });
                row.col(|ui| {
                    let policy = event.policy.as_deref().unwrap_or("-");
                    let color = match policy {
                        "allow" => egui::Color32::from_rgb(80, 200, 80),
                        "audit" => egui::Color32::from_rgb(220, 180, 40),
                        "deny" => egui::Color32::from_rgb(220, 60, 60),
                        _ => ui.visuals().text_color(),
                    };
                    ui.colored_label(color, policy);
                });
                row.col(|ui| {
                    let flags = flags_label(event);
                    if flags.contains("PII") {
                        ui.colored_label(egui::Color32::from_rgb(220, 60, 60), &flags);
                    } else {
                        ui.label(&flags);
                    }
                });

                // Handle row click — toggle selection
                if row.response().clicked() {
                    if app.selected_event_idx == Some(event_idx) {
                        app.selected_event_idx = None;
                    } else {
                        app.selected_event_idx = Some(event_idx);
                    }
                }
            });
        });
}

/// Render the detail panel for a selected event.
pub fn show_detail_panel(ui: &mut egui::Ui, event: &ProcessedEvent) {
    egui::ScrollArea::vertical()
        .id_salt("detail_scroll")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("Event Detail");
                ui.label(format!("  {}  {}", event.event_type, event.timestamp));
            });
            ui.separator();

            // Key-value grid
            egui::Grid::new("detail_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    detail_row(
                        ui,
                        "Process",
                        &format!(
                            "{} (PID: {}, UID: {})",
                            event.process_name, event.pid, event.uid
                        ),
                    );
                    detail_row(
                        ui,
                        "Provider",
                        event
                            .llm_provider
                            .as_deref()
                            .or(event.provider.as_deref())
                            .unwrap_or("-"),
                    );
                    if let Some(ref model) = event.llm_model {
                        detail_row(ui, "Model", model);
                    }
                    if let Some(ref endpoint) = event.llm_endpoint {
                        detail_row(ui, "Endpoint", endpoint);
                    }
                    if let Some(ref sdk) = event.agent_sdk {
                        detail_row(ui, "SDK", sdk);
                    }
                    if let Some(ref method) = event.mcp_method {
                        detail_row(ui, "MCP Method", method);
                    }
                    if let Some(ref cat) = event.mcp_category {
                        detail_row(ui, "MCP Category", cat);
                    }
                    if let Some(ref policy) = event.policy {
                        detail_row(ui, "Policy", policy);
                    }
                    if let Some(pii) = event.pii_detected {
                        detail_row(ui, "PII Detected", if pii { "YES" } else { "no" });
                    }
                    if let Some(stream) = event.llm_stream {
                        detail_row(ui, "Streaming", if stream { "yes" } else { "no" });
                    }
                    if let Some(conf) = event.classifier_confidence {
                        detail_row(ui, "Confidence", &format!("{:.0}%", conf * 100.0));
                    }
                    // Identity
                    if let Some(ref narrative) = event.identity_narrative {
                        detail_row(ui, "Identity", narrative);
                    }
                    if let Some(ref timeline) = event.identity_timeline {
                        detail_row(ui, "Timeline", timeline);
                    }
                    // Network (secondary)
                    detail_row(
                        ui,
                        "Network",
                        &format!(
                            "{}:{} -> {}:{} ({} bytes)",
                            event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.bytes,
                        ),
                    );
                    if let Some(ref sni) = event.sni {
                        detail_row(ui, "SNI", sni);
                    }
                    if !event.container_id.is_empty() {
                        detail_row(ui, "Container", &event.container_id);
                    }
                });

            // Full content sections
            if let Some(ref msg) = event.llm_user_message {
                ui.separator();
                ui.strong("User Message");
                egui::ScrollArea::vertical()
                    .id_salt("user_msg_scroll")
                    .max_height(100.0)
                    .show(ui, |ui| {
                        ui.label(msg);
                    });
            }
            if let Some(ref prompt) = event.llm_system_prompt {
                ui.separator();
                ui.strong("System Prompt");
                egui::ScrollArea::vertical()
                    .id_salt("sys_prompt_scroll")
                    .max_height(100.0)
                    .show(ui, |ui| {
                        ui.label(prompt);
                    });
            }
        });
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}
