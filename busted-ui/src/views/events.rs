use crate::app::BustedApp;
use egui_extras::{Column, TableBuilder};

pub fn show(ui: &mut egui::Ui, app: &mut BustedApp) {
    // Filters
    ui.horizontal(|ui| {
        ui.label("Filter:");
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

        ui.label("Type:");
        egui::ComboBox::from_id_salt("filter_event_type")
            .selected_text(if app.filter_event_type.is_empty() {
                "All"
            } else {
                &app.filter_event_type
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.filter_event_type, String::new(), "All");
                for t in &["TCP_CONNECT", "DATA_SENT", "DATA_RECEIVED", "CONNECTION_CLOSED", "DNS_QUERY"] {
                    ui.selectable_value(
                        &mut app.filter_event_type,
                        t.to_string(),
                        *t,
                    );
                }
            });

        ui.label("Process:");
        ui.text_edit_singleline(&mut app.filter_process);

        ui.checkbox(&mut app.auto_scroll, "Auto-scroll");
    });

    ui.separator();

    // Filtered events
    let filtered: Vec<usize> = app
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            if !app.filter_provider.is_empty() {
                match &e.provider {
                    Some(p) if p == &app.filter_provider => {}
                    _ => return false,
                }
            }
            if !app.filter_event_type.is_empty() && e.event_type != app.filter_event_type {
                return false;
            }
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
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(80.0)) // Time
        .column(Column::auto().at_least(90.0)) // Type
        .column(Column::auto().at_least(50.0)) // PID
        .column(Column::auto().at_least(80.0)) // Process
        .column(Column::auto().at_least(110.0)) // Dst IP
        .column(Column::auto().at_least(50.0)) // Port
        .column(Column::auto().at_least(70.0)) // Bytes
        .column(Column::auto().at_least(70.0)) // Provider
        .column(Column::auto().at_least(80.0)) // Container
        .min_scrolled_height(0.0);

    let table = if app.auto_scroll {
        table.scroll_to_row(row_count.saturating_sub(1), None)
    } else {
        table
    };

    table
        .header(20.0, |mut header| {
            header.col(|ui| { ui.strong("Time"); });
            header.col(|ui| { ui.strong("Type"); });
            header.col(|ui| { ui.strong("PID"); });
            header.col(|ui| { ui.strong("Process"); });
            header.col(|ui| { ui.strong("Dst IP"); });
            header.col(|ui| { ui.strong("Port"); });
            header.col(|ui| { ui.strong("Bytes"); });
            header.col(|ui| { ui.strong("Provider"); });
            header.col(|ui| { ui.strong("Container"); });
        })
        .body(|body| {
            body.rows(18.0, row_count, |mut row| {
                let idx = filtered[row.index()];
                let event = &app.events[idx];
                row.col(|ui| { ui.label(&event.timestamp); });
                row.col(|ui| { ui.label(&event.event_type); });
                row.col(|ui| { ui.label(event.pid.to_string()); });
                row.col(|ui| { ui.label(&event.process_name); });
                row.col(|ui| { ui.label(&event.dst_ip); });
                row.col(|ui| { ui.label(event.dst_port.to_string()); });
                row.col(|ui| { ui.label(format_bytes(event.bytes)); });
                row.col(|ui| {
                    ui.label(event.provider.as_deref().unwrap_or("-"));
                });
                row.col(|ui| {
                    let cid = if event.container_id.is_empty() { "-" } else { &event.container_id };
                    ui.label(cid);
                });
            });
        });
}

fn format_bytes(b: u64) -> String {
    if b == 0 {
        "-".to_string()
    } else if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    }
}
