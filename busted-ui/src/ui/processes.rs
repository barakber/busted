use eframe::egui;
use egui_extras::{Column, TableBuilder};

use super::style;
use crate::app::{format_bytes, App};

pub fn draw(ui: &mut egui::Ui, app: &mut App) {
    let stats = app.process_stats();
    let row_height = 28.0;

    TableBuilder::new(ui)
        .striped(false)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::remainder().at_least(100.0).resizable(true)) // Process
        .column(Column::initial(60.0).resizable(true)) // PID
        .column(Column::initial(60.0).resizable(true)) // Events
        .column(Column::initial(80.0).resizable(true)) // Bytes
        .column(Column::initial(45.0).resizable(true)) // PII
        .column(Column::remainder().at_least(120.0).resizable(true)) // Providers
        .min_scrolled_height(0.0)
        .header(row_height, |mut header| {
            let cols = ["PROCESS", "PID", "EVENTS", "BYTES", "PII", "PROVIDERS"];
            for col in cols {
                header.col(|ui| {
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
            body.rows(row_height, stats.len(), |mut row| {
                let stat = &stats[row.index()];
                let pii_color = if stat.pii_count > 0 {
                    style::PII_COLOR
                } else {
                    style::DIM_TEXT
                };

                row.col(|ui| {
                    if ui.rect_contains_pointer(ui.max_rect()) {
                        ui.painter()
                            .rect_filled(ui.max_rect(), 0.0, style::HOVER_BG);
                    }
                    ui.colored_label(style::NORMAL_TEXT, &stat.name);
                });
                row.col(|ui| {
                    if ui.rect_contains_pointer(ui.max_rect()) {
                        ui.painter()
                            .rect_filled(ui.max_rect(), 0.0, style::HOVER_BG);
                    }
                    ui.colored_label(style::DIM_TEXT, stat.pid.to_string());
                });
                row.col(|ui| {
                    if ui.rect_contains_pointer(ui.max_rect()) {
                        ui.painter()
                            .rect_filled(ui.max_rect(), 0.0, style::HOVER_BG);
                    }
                    ui.colored_label(style::NORMAL_TEXT, stat.event_count.to_string());
                });
                row.col(|ui| {
                    if ui.rect_contains_pointer(ui.max_rect()) {
                        ui.painter()
                            .rect_filled(ui.max_rect(), 0.0, style::HOVER_BG);
                    }
                    ui.colored_label(style::NORMAL_TEXT, format_bytes(stat.bytes));
                });
                row.col(|ui| {
                    if ui.rect_contains_pointer(ui.max_rect()) {
                        ui.painter()
                            .rect_filled(ui.max_rect(), 0.0, style::HOVER_BG);
                    }
                    ui.colored_label(pii_color, stat.pii_count.to_string());
                });
                row.col(|ui| {
                    if ui.rect_contains_pointer(ui.max_rect()) {
                        ui.painter()
                            .rect_filled(ui.max_rect(), 0.0, style::HOVER_BG);
                    }
                    ui.colored_label(style::DIM_TEXT, stat.providers.join(", "));
                });
            });
        });
}
