use crate::app::BustedApp;

pub fn show(ui: &mut egui::Ui, app: &mut BustedApp) {
    ui.heading("Processes Communicating with LLM APIs");
    ui.separator();

    // Only show processes that have communicated with LLM providers
    let mut llm_processes: Vec<_> = app
        .process_info
        .values()
        .filter(|p| !p.providers.is_empty())
        .collect();

    if llm_processes.is_empty() {
        ui.label("No processes have communicated with LLM APIs yet.");
        return;
    }

    llm_processes.sort_by_key(|b| std::cmp::Reverse(b.event_count));

    egui::Grid::new("process_grid")
        .num_columns(6)
        .spacing([20.0, 8.0])
        .striped(true)
        .show(ui, |ui| {
            ui.strong("PID");
            ui.strong("Process");
            ui.strong("UID");
            ui.strong("Events");
            ui.strong("Bytes");
            ui.strong("Providers");
            ui.end_row();

            for proc in &llm_processes {
                ui.label(proc.pid.to_string());
                ui.label(&proc.name);
                ui.label(proc.uid.to_string());
                ui.label(proc.event_count.to_string());
                ui.label(format_bytes(proc.bytes_total));
                let providers: Vec<_> = proc.providers.iter().map(|s| s.as_str()).collect();
                ui.label(providers.join(", "));
                ui.end_row();
            }
        });

    ui.separator();
    ui.label(format!(
        "{} unique processes detected communicating with LLM APIs",
        llm_processes.len()
    ));
}

fn format_bytes(b: u64) -> String {
    if b == 0 {
        "0 B".to_string()
    } else if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    }
}
