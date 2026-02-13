use eframe::egui;

use super::style;
use crate::app::{App, Tab};

pub fn draw(ui: &mut egui::Ui, app: &App) {
    ui.horizontal(|ui| {
        for (i, tab) in Tab::ALL.iter().enumerate() {
            if i > 0 {
                ui.add_space(16.0);
            }
            let is_active = *tab == app.active_tab;
            let label_text = tab.label();
            let text = egui::RichText::new(label_text).size(13.0);
            let text = if is_active { text.strong() } else { text };
            let color = if is_active {
                style::ACCENT_COLOR
            } else {
                style::DIM_TEXT
            };

            let response = ui.colored_label(color, text);

            // Active underline
            if is_active {
                let rect = response.rect;
                let line_y = rect.bottom() + 2.0;
                ui.painter().line_segment(
                    [
                        egui::pos2(rect.left(), line_y),
                        egui::pos2(rect.right(), line_y),
                    ],
                    egui::Stroke::new(2.0, style::ACCENT_COLOR),
                );
            }
        }
    });
}
