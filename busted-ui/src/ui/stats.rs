use eframe::egui;

use super::style;
use crate::app::{format_bytes, App};

pub fn draw(ui: &mut egui::Ui, app: &App) {
    let total = app.events.len();
    let bytes = app.total_bytes();
    let procs = app.unique_processes();
    let pii = app.pii_count();
    let (allow, audit, deny) = app.policy_breakdown();

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;

        stat_card(ui, "Events", &total.to_string(), style::NORMAL_TEXT, None);
        stat_card(ui, "Data", &format_bytes(bytes), style::NORMAL_TEXT, None);
        stat_card(
            ui,
            "Processes",
            &procs.to_string(),
            style::NORMAL_TEXT,
            None,
        );
        stat_card(
            ui,
            "PII",
            &pii.to_string(),
            if pii > 0 {
                style::PII_COLOR
            } else {
                style::NORMAL_TEXT
            },
            if pii > 0 {
                Some(style::PII_COLOR)
            } else {
                None
            },
        );
        stat_card(
            ui,
            "Allow",
            &allow.to_string(),
            style::POLICY_ALLOW_COLOR,
            None,
        );
        stat_card(
            ui,
            "Audit",
            &audit.to_string(),
            style::POLICY_AUDIT_COLOR,
            None,
        );
        stat_card(
            ui,
            "Deny",
            &deny.to_string(),
            style::POLICY_DENY_COLOR,
            None,
        );
    });
}

fn stat_card(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    value_color: egui::Color32,
    border_tint: Option<egui::Color32>,
) {
    let mut frame = style::card_frame();
    if let Some(tint) = border_tint {
        frame = frame.stroke(egui::Stroke::new(1.0, tint));
    }
    frame.show(ui, |ui| {
        ui.vertical(|ui| {
            ui.colored_label(
                style::DIM_TEXT,
                egui::RichText::new(label.to_uppercase()).size(10.0),
            );
            ui.colored_label(value_color, egui::RichText::new(value).strong().size(14.0));
        });
    });
}
