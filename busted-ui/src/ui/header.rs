use eframe::egui;

use super::style;
use crate::app::{App, ConnectionState};

pub fn draw(ui: &mut egui::Ui, app: &App) {
    ui.horizontal(|ui| {
        // Title
        ui.colored_label(
            style::BRIGHT_TEXT,
            egui::RichText::new("Busted").strong().size(16.0),
        );

        ui.add_space(12.0);

        // Mode badge
        let (badge_text, badge_fg, badge_bg) = match app.connection_state {
            ConnectionState::Demo => ("DEMO", style::ACCENT_COLOR, style::ACCENT_DIM),
            ConnectionState::Connected => ("LIVE", style::POLICY_ALLOW_COLOR, style::SURFACE_2),
            ConnectionState::Connecting => ("...", style::POLICY_AUDIT_COLOR, style::SURFACE_2),
        };
        style::pill(ui, badge_text, badge_fg, badge_bg);

        if app.paused {
            ui.add_space(8.0);
            style::pill(ui, "PAUSED", style::POLICY_AUDIT_COLOR, style::SURFACE_2);
        }

        ui.add_space(20.0);

        // Sparkline
        let data = app.sparkline_data();
        let max_val = data.iter().copied().max().unwrap_or(1).max(1) as f32;
        let sparkline_width = 140.0;
        let sparkline_height = 20.0;
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(sparkline_width, sparkline_height),
            egui::Sense::hover(),
        );

        let bar_width = sparkline_width / data.len() as f32;
        for (i, &val) in data.iter().enumerate() {
            let h = (val as f32 / max_val) * sparkline_height;
            let x = rect.left() + i as f32 * bar_width;
            let bar_rect = egui::Rect::from_min_max(
                egui::pos2(x, rect.bottom() - h),
                egui::pos2(x + bar_width - 1.0, rect.bottom()),
            );
            let rounding = egui::CornerRadius {
                nw: 2,
                ne: 2,
                sw: 0,
                se: 0,
            };
            ui.painter()
                .rect_filled(bar_rect, rounding, style::ACCENT_COLOR);
        }

        ui.add_space(12.0);

        // Rate + count
        let eps = app.events_per_second();
        let total = app.total_event_count;
        ui.colored_label(
            style::BRIGHT_TEXT,
            egui::RichText::new(format!("{eps:.1}/s")).strong(),
        );
        ui.colored_label(style::DIM_TEXT, "\u{2022}");
        ui.colored_label(style::DIM_TEXT, format!("{total} total"));

        // Connection dot (right-aligned)
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let dot_color = match app.connection_state {
                ConnectionState::Connected | ConnectionState::Demo => style::POLICY_ALLOW_COLOR,
                ConnectionState::Connecting => style::POLICY_AUDIT_COLOR,
            };
            ui.colored_label(dot_color, "\u{25CF}");
        });
    });
}
