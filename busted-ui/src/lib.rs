pub mod app;
#[cfg(not(target_arch = "wasm32"))]
pub mod bridge;
pub mod demo;
pub mod ui;

/// Configuration for the GUI dashboard.
pub struct UiConfig {
    pub demo_mode: bool,
}

/// Launch the GUI dashboard (blocking — runs the eframe event loop).
#[cfg(not(target_arch = "wasm32"))]
pub fn run_ui(config: UiConfig) -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_title("Busted - LLM/AI Monitor"),
        ..Default::default()
    };

    eframe::run_native(
        "Busted",
        native_options,
        Box::new(move |cc| {
            // Enable egui_extras image support (needed for syntect etc.)
            egui_extras::install_image_loaders(&cc.egui_ctx);

            let app_state = app::App::new(config.demo_mode);
            let rx = bridge::spawn_bridge(cc.egui_ctx.clone(), config.demo_mode);
            Ok(Box::new(ui::BustedApp::new(app_state, rx)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}
