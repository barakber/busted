use eframe::egui;

use super::style;

const BINDINGS: &[(&str, &str)] = &[
    ("Navigation:", ""),
    ("j / k / \u{2191} / \u{2193}", "Move selection up / down"),
    ("Ctrl-d / Ctrl-u", "Half-page down / up"),
    ("Ctrl-f / Ctrl-b", "Full-page down / up"),
    ("PgDn / PgUp", "Full-page down / up"),
    ("g / Home", "Jump to top"),
    ("G / End", "Jump to bottom"),
    ("H / M / L", "Select high / mid / low in page"),
    ("", ""),
    ("Actions:", ""),
    ("Enter", "Toggle detail panel"),
    ("Esc", "Close detail / clear search"),
    ("Space", "Pause / resume stream"),
    ("/", "Enter search mode"),
    ("Tab / Shift-Tab", "Cycle tabs"),
    ("1 / 2 / 3", "Jump to tab"),
    ("c", "Clear events"),
    ("C", "Clear filters"),
    ("p", "Cycle provider filter"),
    ("t", "Cycle type filter"),
    ("q", "Quit"),
    ("?", "Toggle this help"),
    ("", ""),
    ("In detail panel:", ""),
    ("j / k", "Scroll detail content"),
    ("Ctrl-d / Ctrl-u", "Half-page scroll detail"),
    ("g / G", "Top / bottom of detail"),
    ("n / N", "Next / previous event"),
    ("Esc", "Close detail"),
];

pub fn draw(ctx: &egui::Context) {
    egui::Window::new("Help")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .frame(style::card_frame().fill(style::SURFACE))
        .show(ctx, |ui| {
            ui.colored_label(
                style::BRIGHT_TEXT,
                egui::RichText::new("Key Bindings").strong().size(16.0),
            );
            ui.add_space(8.0);

            for (key, desc) in BINDINGS {
                if key.is_empty() {
                    ui.add_space(6.0);
                    continue;
                }
                if desc.is_empty() {
                    // Section header
                    ui.colored_label(
                        style::ACCENT_COLOR,
                        egui::RichText::new(*key).strong().size(12.0),
                    );
                    // Separator
                    let rect = ui.max_rect();
                    let y = ui.cursor().top();
                    ui.painter().line_segment(
                        [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                        egui::Stroke::new(1.0, style::BORDER_COLOR),
                    );
                    ui.add_space(2.0);
                    continue;
                }
                ui.horizontal(|ui| {
                    // Key as pill
                    style::pill(ui, key, style::ACCENT_COLOR, style::ACCENT_DIM);
                    ui.add_space(8.0);
                    ui.colored_label(style::NORMAL_TEXT, *desc);
                });
            }

            ui.add_space(8.0);
            ui.colored_label(style::DIM_TEXT, "Press ? or Esc to close");
        });
}
