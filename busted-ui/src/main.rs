#[cfg(not(target_arch = "wasm32"))]
fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = <Args as clap::Parser>::parse();

    busted_ui::run_ui(busted_ui::UiConfig {
        demo_mode: args.demo,
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(clap::Parser)]
#[command(name = "busted-ui", about = "Busted GUI dashboard")]
struct Args {
    /// Run in demo mode with synthetic events
    #[arg(long)]
    demo: bool,
}

#[cfg(target_arch = "wasm32")]
fn main() {
    // WASM entry point: always demo mode
    wasm_bindgen_futures::spawn_local(async {
        let web_options = eframe::WebOptions::default();
        eframe::WebRunner::new()
            .start(
                "the_canvas_id",
                web_options,
                Box::new(|cc| {
                    egui_extras::install_image_loaders(&cc.egui_ctx);
                    let app_state = busted_ui::app::App::new(true);
                    Ok(Box::new(busted_ui::ui::BustedApp::new_wasm(app_state)))
                }),
            )
            .await
            .expect("Failed to start eframe");
    });
}
