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
    use wasm_bindgen::JsCast;

    // WASM entry point: always demo mode
    wasm_bindgen_futures::spawn_local(async {
        let web_options = eframe::WebOptions::default();

        // eframe 0.33: start() expects an HtmlCanvasElement, not a string ID.
        // Trunk injects a <canvas> with data-raw-handle; we create one ourselves.
        let document = web_sys::window()
            .expect("no window")
            .document()
            .expect("no document");
        let canvas = document
            .create_element("canvas")
            .expect("failed to create canvas")
            .dyn_into::<web_sys::HtmlCanvasElement>()
            .expect("not a canvas element");
        canvas.set_id("busted_canvas");
        document
            .body()
            .expect("no body")
            .append_child(&canvas)
            .expect("failed to append canvas");

        eframe::WebRunner::new()
            .start(
                canvas,
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
