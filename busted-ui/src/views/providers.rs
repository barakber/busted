use crate::app::BustedApp;

pub fn show(ui: &mut egui::Ui, app: &mut BustedApp) {
    ui.heading("LLM Provider Summary");
    ui.separator();

    if app.provider_stats.is_empty() {
        ui.label("No LLM provider traffic detected yet.");
        return;
    }

    // Sort providers by event count (descending)
    let mut providers: Vec<_> = app.provider_stats.iter().collect();
    providers.sort_by(|a, b| b.1.event_count.cmp(&a.1.event_count));

    let max_events = providers
        .first()
        .map(|(_, s)| s.event_count)
        .unwrap_or(1)
        .max(1) as f32;

    egui::Grid::new("provider_grid")
        .num_columns(5)
        .spacing([20.0, 8.0])
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Provider");
            ui.strong("Events");
            ui.strong("Bytes");
            ui.strong("Processes");
            ui.strong("Activity");
            ui.end_row();

            for (name, stats) in &providers {
                ui.label(*name);
                ui.label(stats.event_count.to_string());
                ui.label(format_bytes(stats.bytes_total));
                ui.label(stats.processes.len().to_string());

                // Simple bar chart
                let fraction = stats.event_count as f32 / max_events;
                let (rect, _) = ui.allocate_exact_size(
                    egui::vec2(200.0, 16.0),
                    egui::Sense::hover(),
                );
                let bar_rect = egui::Rect::from_min_size(
                    rect.min,
                    egui::vec2(rect.width() * fraction, rect.height()),
                );
                ui.painter().rect_filled(
                    bar_rect,
                    2.0,
                    provider_color(name),
                );
                ui.painter().rect_stroke(
                    rect,
                    2.0,
                    egui::Stroke::new(1.0, egui::Color32::GRAY),
                    egui::StrokeKind::Outside,
                );

                ui.end_row();
            }
        });

    ui.separator();

    // Total summary
    let total_events: u64 = app.provider_stats.values().map(|s| s.event_count).sum();
    let total_bytes: u64 = app.provider_stats.values().map(|s| s.bytes_total).sum();
    ui.label(format!(
        "Total: {} events | {} transferred across {} providers",
        total_events,
        format_bytes(total_bytes),
        app.provider_stats.len(),
    ));
}

fn provider_color(name: &str) -> egui::Color32 {
    match name {
        "OpenAI" => egui::Color32::from_rgb(116, 184, 117),
        "Anthropic" => egui::Color32::from_rgb(204, 133, 80),
        "Google" => egui::Color32::from_rgb(66, 133, 244),
        "Azure" => egui::Color32::from_rgb(0, 120, 212),
        "AWS Bedrock" => egui::Color32::from_rgb(255, 153, 0),
        "Cohere" => egui::Color32::from_rgb(209, 98, 133),
        "HuggingFace" => egui::Color32::from_rgb(255, 216, 0),
        _ => egui::Color32::GRAY,
    }
}

fn format_bytes(b: u64) -> String {
    if b == 0 {
        "0 B".to_string()
    } else if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
