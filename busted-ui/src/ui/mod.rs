pub mod detail;
pub mod events;
pub mod filter;
pub mod header;
pub mod help;
pub mod processes;
pub mod providers;
pub mod stats;
pub mod style;
pub mod tabs;

use eframe::egui;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use busted_types::agentic::BustedEvent;

use crate::app::{App, InputMode, Tab};

/// The main eframe application that holds the App state and event bridge.
pub struct BustedApp {
    pub app: App,
    rx: Option<mpsc::Receiver<BustedEvent>>,
    last_tick: Instant,
    /// For WASM demo mode: cycle counter and per-event timing
    #[cfg(target_arch = "wasm32")]
    wasm_cycle: usize,
    #[cfg(target_arch = "wasm32")]
    wasm_batch: Vec<(BustedEvent, u64)>,
    #[cfg(target_arch = "wasm32")]
    wasm_batch_idx: usize,
    #[cfg(target_arch = "wasm32")]
    wasm_last_event: f64,
}

impl BustedApp {
    /// Create a new BustedApp. On native, pass the mpsc receiver from bridge.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(app: App, rx: mpsc::Receiver<BustedEvent>) -> Self {
        Self {
            app,
            rx: Some(rx),
            last_tick: Instant::now(),
        }
    }

    /// Create a new BustedApp for WASM (demo-only, no receiver).
    #[cfg(target_arch = "wasm32")]
    pub fn new_wasm(app: App) -> Self {
        Self {
            app,
            rx: None,
            last_tick: Instant::now(),
            wasm_cycle: 0,
            wasm_batch: Vec::new(),
            wasm_batch_idx: 0,
            wasm_last_event: 0.0,
        }
    }

    fn drain_events(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(event) = rx.try_recv() {
                self.app.push_event(event);
            }
        }
    }

    fn tick_if_needed(&mut self) {
        if self.last_tick.elapsed() >= Duration::from_secs(1) {
            self.app.tick();
            self.last_tick = Instant::now();
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn wasm_demo_tick(&mut self, time: f64) {
        if self.wasm_batch.is_empty() || self.wasm_batch_idx >= self.wasm_batch.len() {
            self.wasm_batch = crate::demo::generate_batch(self.wasm_cycle);
            self.wasm_batch_idx = 0;
            self.wasm_cycle += 1;
            self.wasm_last_event = time;
        }

        while self.wasm_batch_idx < self.wasm_batch.len() {
            let (_, delay_ms) = &self.wasm_batch[self.wasm_batch_idx];
            let elapsed_ms = (time - self.wasm_last_event) * 1000.0;
            if elapsed_ms >= *delay_ms as f64 {
                let (event, _) = self.wasm_batch[self.wasm_batch_idx].clone();
                self.app.push_event(event);
                self.wasm_last_event = time;
                self.wasm_batch_idx += 1;
            } else {
                break;
            }
        }
    }
}

impl eframe::App for BustedApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain events from bridge
        self.drain_events();
        self.tick_if_needed();

        // WASM demo mode
        #[cfg(target_arch = "wasm32")]
        {
            let time = ctx.input(|i| i.time);
            self.wasm_demo_tick(time);
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        // Handle keyboard input
        handle_keyboard(ctx, &mut self.app);

        // Apply modern dark theme
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = style::BG_COLOR;
        visuals.window_fill = style::SURFACE;
        visuals.override_text_color = Some(style::NORMAL_TEXT);
        visuals.selection.bg_fill = style::ACCENT_DIM;
        visuals.selection.stroke = egui::Stroke::new(1.0, style::ACCENT_COLOR);
        // Rounded widgets
        let rounding = egui::CornerRadius::same(style::ROUNDING);
        visuals.widgets.noninteractive.corner_radius = rounding;
        visuals.widgets.inactive.corner_radius = rounding;
        visuals.widgets.hovered.corner_radius = rounding;
        visuals.widgets.active.corner_radius = rounding;
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, style::BORDER_COLOR);
        ctx.set_visuals(visuals);

        // Layout panels
        egui::TopBottomPanel::top("header")
            .exact_height(40.0)
            .frame(
                egui::Frame::NONE
                    .fill(style::SURFACE)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ctx, |ui| {
                header::draw(ui, &self.app);
            });

        egui::TopBottomPanel::top("stats")
            .exact_height(44.0)
            .frame(
                egui::Frame::NONE
                    .fill(style::BG_COLOR)
                    .inner_margin(egui::Margin::symmetric(16, 4)),
            )
            .show(ctx, |ui| {
                stats::draw(ui, &self.app);
            });

        egui::TopBottomPanel::top("tabs")
            .exact_height(36.0)
            .frame(
                egui::Frame::NONE
                    .fill(style::BG_COLOR)
                    .inner_margin(egui::Margin::symmetric(16, 6)),
            )
            .show(ctx, |ui| {
                tabs::draw(ui, &self.app);
            });

        egui::TopBottomPanel::top("filter")
            .exact_height(36.0)
            .frame(
                egui::Frame::NONE
                    .fill(style::BG_COLOR)
                    .inner_margin(egui::Margin::symmetric(16, 4)),
            )
            .show(ctx, |ui| {
                filter::draw(ui, &mut self.app);
            });

        egui::TopBottomPanel::bottom("footer")
            .exact_height(28.0)
            .frame(
                egui::Frame::NONE
                    .fill(style::SURFACE)
                    .inner_margin(egui::Margin::symmetric(16, 4)),
            )
            .show(ctx, |ui| {
                draw_footer(ui, &self.app);
            });

        // Detail side panel (right) — must be shown before CentralPanel
        if self.app.show_detail && self.app.active_tab == Tab::Events {
            egui::SidePanel::right("detail")
                .default_width(400.0)
                .min_width(300.0)
                .frame(
                    egui::Frame::NONE
                        .fill(style::BG_COLOR)
                        .inner_margin(egui::Margin::symmetric(12, 8))
                        .stroke(egui::Stroke::new(2.0, style::ACCENT_COLOR)),
                )
                .show(ctx, |ui| {
                    detail::draw(ui, &self.app);
                });
        }

        // Content area
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(style::BG_COLOR)
                    .inner_margin(egui::Margin::symmetric(16, 4)),
            )
            .show(ctx, |ui| {
                self.app.content_height = ui.available_height();
                draw_content(ui, &mut self.app);
            });

        // Help popup overlay
        if self.app.show_help {
            help::draw(ctx);
        }
    }
}

fn draw_content(ui: &mut egui::Ui, app: &mut App) {
    match app.active_tab {
        Tab::Events => events::draw(ui, app),
        Tab::Processes => processes::draw(ui, app),
        Tab::Providers => providers::draw(ui, app),
    }
}

fn draw_footer(ui: &mut egui::Ui, app: &App) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;

        if app.show_detail {
            footer_hint(ui, "Esc", "Close");
            footer_hint(ui, "j/k", "Scroll");
            footer_hint(ui, "C-d/u", "HalfPg");
            footer_hint(ui, "n/N", "Next/Prev");
            footer_hint(ui, "?", "Help");
        } else if app.input_mode == InputMode::Search {
            footer_hint(ui, "Enter", "Search");
            footer_hint(ui, "Esc", "Cancel");
        } else {
            footer_hint(ui, "q", "Quit");
            footer_hint(ui, "j/k", "Nav");
            footer_hint(ui, "C-d/u", "HalfPg");
            footer_hint(ui, "/", "Search");
            footer_hint(ui, "Enter", "Detail");
            footer_hint(ui, "Tab", "Tabs");
            footer_hint(ui, "Space", "Pause");
            footer_hint(ui, "?", "Help");
        }
    });
}

fn footer_hint(ui: &mut egui::Ui, key: &str, desc: &str) {
    style::pill(ui, key, style::ACCENT_COLOR, style::ACCENT_DIM);
    ui.colored_label(style::DIM_TEXT, desc);
    ui.add_space(4.0);
}

fn handle_keyboard(ctx: &egui::Context, app: &mut App) {
    ctx.input(|input| {
        let ctrl = input.modifiers.ctrl;

        // Help popup intercepts all keys
        if app.show_help {
            if input.key_pressed(egui::Key::Escape) || input.key_pressed(egui::Key::Q) {
                app.show_help = false;
            }
            // Check for '?' via events
            for event in &input.events {
                if let egui::Event::Text(t) = event {
                    if t == "?" {
                        app.show_help = false;
                    }
                }
            }
            return;
        }

        // Search mode
        if app.input_mode == InputMode::Search {
            if input.key_pressed(egui::Key::Escape) {
                app.input_mode = InputMode::Normal;
                return;
            }
            if input.key_pressed(egui::Key::Enter) {
                app.input_mode = InputMode::Normal;
                return;
            }
            if input.key_pressed(egui::Key::Backspace) {
                app.search_query.pop();
                return;
            }
            // Capture text input
            for event in &input.events {
                if let egui::Event::Text(t) = event {
                    app.search_query.push_str(t);
                }
            }
            return;
        }

        // Detail panel mode
        if app.show_detail && app.active_tab == Tab::Events {
            if input.key_pressed(egui::Key::Escape) {
                app.show_detail = false;
                return;
            }
            // Scroll detail content
            if input.key_pressed(egui::Key::ArrowDown) {
                app.detail_scroll_down();
                return;
            }
            if input.key_pressed(egui::Key::ArrowUp) {
                app.detail_scroll_up();
                return;
            }
            if ctrl && input.key_pressed(egui::Key::D) {
                app.detail_half_page_down();
                return;
            }
            if ctrl && input.key_pressed(egui::Key::U) {
                app.detail_half_page_up();
                return;
            }
            if ctrl && input.key_pressed(egui::Key::F) {
                app.detail_full_page_down();
                return;
            }
            if ctrl && input.key_pressed(egui::Key::B) {
                app.detail_full_page_up();
                return;
            }
            if input.key_pressed(egui::Key::PageDown) {
                app.detail_full_page_down();
                return;
            }
            if input.key_pressed(egui::Key::PageUp) {
                app.detail_full_page_up();
                return;
            }
            if input.key_pressed(egui::Key::Home) {
                app.detail_scroll = 0.0;
                return;
            }
            if input.key_pressed(egui::Key::End) {
                app.detail_scroll = f32::MAX / 2.0;
                return;
            }

            // Text events for j/k/n/N/g/G/q/?
            for event in &input.events {
                if let egui::Event::Text(t) = event {
                    match t.as_str() {
                        "j" => {
                            app.detail_scroll_down();
                            return;
                        }
                        "k" => {
                            app.detail_scroll_up();
                            return;
                        }
                        "g" => {
                            app.detail_scroll = 0.0;
                            return;
                        }
                        "G" => {
                            app.detail_scroll = f32::MAX / 2.0;
                            return;
                        }
                        "n" => {
                            app.select_next_event_in_detail();
                            return;
                        }
                        "N" => {
                            app.select_prev_event_in_detail();
                            return;
                        }
                        "q" => { /* handled below as quit */ }
                        "?" => {
                            app.show_help = true;
                            return;
                        }
                        _ => {}
                    }
                }
            }
            // Fall through for other keys
        }

        // Normal mode key presses
        if ctrl && input.key_pressed(egui::Key::D) {
            app.half_page_down();
            return;
        }
        if ctrl && input.key_pressed(egui::Key::U) {
            app.half_page_up();
            return;
        }
        if ctrl && input.key_pressed(egui::Key::F) {
            app.full_page_down();
            return;
        }
        if ctrl && input.key_pressed(egui::Key::B) {
            app.full_page_up();
            return;
        }
        if input.key_pressed(egui::Key::ArrowDown) {
            app.select_next();
            return;
        }
        if input.key_pressed(egui::Key::ArrowUp) {
            app.select_prev();
            return;
        }
        if input.key_pressed(egui::Key::Home) {
            app.select_first();
            return;
        }
        if input.key_pressed(egui::Key::End) {
            app.select_last();
            return;
        }
        if input.key_pressed(egui::Key::PageDown) {
            app.full_page_down();
            return;
        }
        if input.key_pressed(egui::Key::PageUp) {
            app.full_page_up();
            return;
        }
        if input.key_pressed(egui::Key::Enter) {
            app.toggle_detail();
            return;
        }
        if input.key_pressed(egui::Key::Escape) {
            if !app.search_query.is_empty() {
                app.search_query.clear();
            } else if app.show_detail {
                app.show_detail = false;
            }
            return;
        }
        if input.key_pressed(egui::Key::Tab) {
            if input.modifiers.shift {
                app.active_tab = app.active_tab.prev();
            } else {
                app.active_tab = app.active_tab.next();
            }
            return;
        }

        // Handle text events for vim-style keys
        for event in &input.events {
            if let egui::Event::Text(t) = event {
                match t.as_str() {
                    "q" => {
                        #[cfg(not(target_arch = "wasm32"))]
                        std::process::exit(0);
                    }
                    "j" => {
                        app.select_next();
                        return;
                    }
                    "k" => {
                        app.select_prev();
                        return;
                    }
                    "g" => {
                        app.select_first();
                        return;
                    }
                    "G" => {
                        app.select_last();
                        return;
                    }
                    "H" => {
                        app.select_high();
                        return;
                    }
                    "M" => {
                        app.select_mid();
                        return;
                    }
                    "L" => {
                        app.select_low();
                        return;
                    }
                    " " => {
                        app.toggle_pause();
                        return;
                    }
                    "/" => {
                        app.input_mode = InputMode::Search;
                        return;
                    }
                    "1" => {
                        app.active_tab = Tab::Events;
                        return;
                    }
                    "2" => {
                        app.active_tab = Tab::Processes;
                        return;
                    }
                    "3" => {
                        app.active_tab = Tab::Providers;
                        return;
                    }
                    "c" => {
                        app.clear_events();
                        return;
                    }
                    "C" => {
                        app.clear_filters();
                        return;
                    }
                    "p" => {
                        app.cycle_provider_filter();
                        return;
                    }
                    "t" => {
                        app.cycle_type_filter();
                        return;
                    }
                    "?" => {
                        app.show_help = true;
                        return;
                    }
                    _ => {}
                }
            }
        }
    });
}
