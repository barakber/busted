use eframe::egui;

use super::style;
use crate::app::{App, InputMode};

pub fn draw(ui: &mut egui::Ui, app: &mut App) {
    ui.horizontal(|ui| {
        // Search field in a rounded frame
        let search_frame = egui::Frame::NONE
            .fill(style::SURFACE)
            .stroke(egui::Stroke::new(
                1.0,
                if app.input_mode == InputMode::Search {
                    style::ACCENT_COLOR
                } else {
                    style::BORDER_COLOR
                },
            ))
            .corner_radius(egui::CornerRadius::same(style::ROUNDING))
            .inner_margin(egui::Margin::symmetric(8, 3));

        search_frame.show(ui, |ui| {
            ui.set_min_width(160.0);
            match app.input_mode {
                InputMode::Search => {
                    ui.horizontal(|ui| {
                        ui.colored_label(style::DIM_TEXT, "\u{1F50D}");
                        ui.colored_label(style::BRIGHT_TEXT, &app.search_query);
                        ui.colored_label(style::ACCENT_COLOR, "\u{2588}");
                    });
                }
                InputMode::Normal => {
                    if app.search_query.is_empty() {
                        ui.colored_label(style::DIM_TEXT, "\u{1F50D} Search...");
                    } else {
                        ui.horizontal(|ui| {
                            ui.colored_label(style::DIM_TEXT, "\u{1F50D}");
                            ui.colored_label(style::ACCENT_COLOR, &app.search_query);
                        });
                    }
                }
            }
        });

        ui.add_space(12.0);

        // Provider filter pill
        if let Some(ref prov) = app.provider_filter {
            style::pill(
                ui,
                &format!("Provider: {prov}"),
                style::ACCENT_COLOR,
                style::ACCENT_DIM,
            );
            ui.add_space(4.0);
        }

        // Type filter pill
        if let Some(ref typ) = app.type_filter {
            style::pill(
                ui,
                &format!("Type: {typ}"),
                style::ACCENT_COLOR,
                style::ACCENT_DIM,
            );
            ui.add_space(4.0);
        }

        // Clear filters
        if app.has_active_filters() {
            style::pill(ui, "Clear (C)", style::DIM_TEXT, style::SURFACE_2);
        }
    });
}
