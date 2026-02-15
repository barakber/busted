use eframe::egui;
use egui_extras::{Column, TableBuilder};

use super::style;
use crate::app::{action_arrow, format_bytes, App};

/// Pre-extracted row data to avoid borrow conflicts with the table builder.
struct RowData {
    time_short: String,
    action_label: String,
    action_color: egui::Color32,
    process_name: String,
    pid: String,
    provider: String,
    dest: String,
    bytes_str: String,
    policy: String,
    policy_str: Option<String>,
    is_pii: bool,
}

pub fn draw(ui: &mut egui::Ui, app: &mut App) {
    let selected = app.selected_index;

    // Pre-extract all row data while borrowing app immutably
    let rows: Vec<RowData> = app
        .filtered_events()
        .iter()
        .map(|ev| {
            let action_color = style::action_color(&ev.action);
            let arrow = action_arrow(&ev.action);
            let action_type = ev.action_type();
            let time = &ev.timestamp;
            let time_short = if time.len() > 12 {
                time[..12].to_string()
            } else {
                time.clone()
            };
            let bytes = ev.bytes();
            RowData {
                time_short,
                action_label: format!("{arrow} {action_type}"),
                action_color,
                process_name: ev.process.name.clone(),
                pid: ev.process.pid.to_string(),
                provider: ev.provider().unwrap_or("-").to_string(),
                dest: ev
                    .file_path()
                    .map(|p| {
                        if p.len() > 30 {
                            format!("...{}", &p[p.len() - 27..])
                        } else {
                            p.to_string()
                        }
                    })
                    .or_else(|| ev.sni().map(|s| s.to_string()))
                    .unwrap_or_else(|| "-".to_string()),
                bytes_str: if bytes > 0 {
                    format_bytes(bytes)
                } else {
                    "-".into()
                },
                policy: ev.policy.as_deref().unwrap_or("-").to_string(),
                policy_str: ev.policy.clone(),
                is_pii: ev.pii_detected(),
            }
        })
        .collect();

    let row_count = rows.len();
    let row_height = 28.0;
    let mut clicked_row: Option<usize> = None;

    let mut table = TableBuilder::new(ui)
        .striped(false)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(90.0).resizable(true)) // Time
        .column(Column::initial(130.0).resizable(true)) // Action
        .column(Column::remainder().at_least(80.0).resizable(true)) // Process
        .column(Column::initial(50.0).resizable(true)) // PID
        .column(Column::remainder().at_least(80.0).resizable(true)) // Provider
        .column(Column::remainder().at_least(100.0).resizable(true)) // Destination
        .column(Column::initial(60.0).resizable(true)) // Bytes
        .column(Column::initial(55.0).resizable(true)) // Policy
        .min_scrolled_height(0.0);

    // Scroll the table viewport to keep the selected row visible
    if let Some(sel) = selected {
        table = table.scroll_to_row(sel, None);
    }

    table = table.sense(egui::Sense::click());

    table
        .header(row_height, |mut header| {
            let cols = [
                "TIME",
                "ACTION",
                "PROCESS",
                "PID",
                "PROVIDER",
                "DESTINATION",
                "BYTES",
                "POLICY",
            ];
            for col in cols {
                header.col(|ui| {
                    // Header background
                    ui.painter()
                        .rect_filled(ui.max_rect(), 0.0, style::SURFACE_2);
                    ui.colored_label(
                        style::DIM_TEXT,
                        egui::RichText::new(col).size(10.0).strong(),
                    );
                });
            }
        })
        .body(|body| {
            body.rows(row_height, row_count, |mut row| {
                let idx = row.index();
                let rd = &rows[idx];
                let is_selected = selected == Some(idx);

                if is_selected {
                    row.set_selected(true);
                }

                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    ui.colored_label(style::DIM_TEXT, &rd.time_short);
                });
                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    style::action_pill(ui, &rd.action_label, rd.action_color);
                });
                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    ui.colored_label(style::NORMAL_TEXT, &rd.process_name);
                });
                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    ui.colored_label(style::DIM_TEXT, &rd.pid);
                });
                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    ui.colored_label(style::NORMAL_TEXT, &rd.provider);
                });
                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    ui.colored_label(style::DIM_TEXT, &rd.dest);
                });
                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    ui.colored_label(style::NORMAL_TEXT, &rd.bytes_str);
                });
                row.col(|ui| {
                    paint_row_bg(ui, rd.is_pii, is_selected);
                    if rd.policy != "-" {
                        style::policy_pill(ui, &rd.policy, rd.policy_str.as_deref());
                    } else {
                        ui.colored_label(style::DIM_TEXT, "-");
                    }
                });

                if row.response().clicked() {
                    clicked_row = Some(idx);
                }
            });
        });

    // Apply click outside the borrow
    if let Some(idx) = clicked_row {
        app.selected_index = Some(idx);
        app.auto_scroll = false;
    }
}

/// Paint row background and return true if a left accent bar was drawn.
fn paint_row_bg(ui: &mut egui::Ui, is_pii: bool, is_selected: bool) -> bool {
    let rect = ui.max_rect();
    if is_selected {
        ui.painter().rect_filled(rect, 0.0, style::SELECTED_BG);
        true
    } else if is_pii {
        ui.painter().rect_filled(rect, 0.0, style::PII_ROW_BG);
        true
    } else {
        if ui.rect_contains_pointer(rect) {
            ui.painter().rect_filled(rect, 0.0, style::HOVER_BG);
        }
        false
    }
}
