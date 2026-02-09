fn main() -> eframe::Result<()> {
    let demo_mode = std::env::args().any(|a| a == "--demo");

    busted_ui::run_ui(busted_ui::UiConfig { demo_mode })
}
