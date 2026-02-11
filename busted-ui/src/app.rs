use crate::views;
use busted_types::processed::ProcessedEvent;
use std::collections::HashMap;
use std::sync::mpsc;

#[derive(Clone, Debug)]
pub struct ProviderStats {
    pub event_count: u64,
    pub bytes_total: u64,
    pub processes: std::collections::HashSet<u32>,
}

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub uid: u32,
    pub event_count: u64,
    pub bytes_total: u64,
    pub providers: std::collections::HashSet<String>,
}

#[derive(PartialEq)]
pub enum Tab {
    LiveEvents,
    Providers,
    Processes,
    Policy,
}

pub struct BustedApp {
    rx: mpsc::Receiver<ProcessedEvent>,
    pub events: Vec<ProcessedEvent>,
    pub tab: Tab,
    pub paused: bool,
    pub connected: bool,
    pub demo_mode: bool,
    pub filter_provider: String,
    pub filter_process: String,
    pub filter_action: String,
    pub show_network_events: bool,
    pub provider_stats: HashMap<String, ProviderStats>,
    pub process_info: HashMap<u32, ProcessInfo>,
    pub auto_scroll: bool,
    pub selected_event_idx: Option<usize>,
    // Policy editor state
    pub policy_rules: Vec<PolicyRule>,
    pub new_rule_pattern: String,
    pub new_rule_action: String,
}

#[derive(Clone, Debug)]
pub struct PolicyRule {
    pub pattern: String,
    pub action: String,
    pub enabled: bool,
}

impl BustedApp {
    pub fn new(rx: mpsc::Receiver<ProcessedEvent>, demo_mode: bool) -> Self {
        Self {
            rx,
            events: Vec::new(),
            tab: Tab::LiveEvents,
            paused: false,
            connected: false,
            demo_mode,
            filter_provider: String::new(),
            filter_process: String::new(),
            filter_action: String::new(),
            show_network_events: false,
            provider_stats: HashMap::new(),
            process_info: HashMap::new(),
            auto_scroll: true,
            selected_event_idx: None,
            policy_rules: Vec::new(),
            new_rule_pattern: String::new(),
            new_rule_action: "audit".to_string(),
        }
    }

    fn poll_events(&mut self) {
        let mut received_any = false;
        while let Ok(event) = self.rx.try_recv() {
            received_any = true;

            // Update provider stats
            if let Some(ref provider) = event.provider {
                let stats = self
                    .provider_stats
                    .entry(provider.clone())
                    .or_insert_with(|| ProviderStats {
                        event_count: 0,
                        bytes_total: 0,
                        processes: std::collections::HashSet::new(),
                    });
                stats.event_count += 1;
                stats.bytes_total += event.bytes;
                stats.processes.insert(event.pid);
            }

            // Update process info
            let pinfo = self
                .process_info
                .entry(event.pid)
                .or_insert_with(|| ProcessInfo {
                    pid: event.pid,
                    name: event.process_name.clone(),
                    uid: event.uid,
                    event_count: 0,
                    bytes_total: 0,
                    providers: std::collections::HashSet::new(),
                });
            pinfo.event_count += 1;
            pinfo.bytes_total += event.bytes;
            if let Some(ref provider) = event.provider {
                pinfo.providers.insert(provider.clone());
            }

            if !self.paused {
                self.events.push(event);
            }
        }
        if received_any {
            self.connected = true;
        }
        // Cap stored events
        if self.events.len() > 10_000 {
            // Adjust selected_event_idx when draining
            if let Some(idx) = self.selected_event_idx {
                if idx < 5_000 {
                    self.selected_event_idx = None;
                } else {
                    self.selected_event_idx = Some(idx - 5_000);
                }
            }
            self.events.drain(0..5_000);
        }
    }
}

impl eframe::App for BustedApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        // Request repaint for live updates
        ctx.request_repaint_after(std::time::Duration::from_millis(100));

        // Top panel - status bar
        egui::TopBottomPanel::top("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let status = if self.demo_mode {
                    "Demo Mode"
                } else if self.connected {
                    "Connected"
                } else {
                    "Disconnected"
                };
                ui.label(format!("Status: {}", status));
                ui.separator();
                ui.label(format!("Events: {}", self.events.len()));
                ui.separator();
                ui.label(format!("Providers: {}", self.provider_stats.len()));
                ui.separator();

                if ui
                    .button(if self.paused { "Resume" } else { "Pause" })
                    .clicked()
                {
                    self.paused = !self.paused;
                }
            });
        });

        // Tab bar
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::LiveEvents, "Live Events");
                ui.selectable_value(&mut self.tab, Tab::Providers, "Providers");
                ui.selectable_value(&mut self.tab, Tab::Processes, "Processes");
                ui.selectable_value(&mut self.tab, Tab::Policy, "Policy");
            });
        });

        // Detail panel (bottom) — only when Live Events tab and an event is selected
        if self.tab == Tab::LiveEvents {
            if let Some(sel_idx) = self.selected_event_idx {
                if sel_idx < self.events.len() {
                    egui::TopBottomPanel::bottom("detail_panel")
                        .resizable(true)
                        .min_height(120.0)
                        .default_height(250.0)
                        .show(ctx, |ui| {
                            let event = &self.events[sel_idx];
                            views::events::show_detail_panel(ui, event);
                        });
                }
            }
        }

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::LiveEvents => views::events::show(ui, self),
            Tab::Providers => views::providers::show(ui, self),
            Tab::Processes => views::processes::show(ui, self),
            Tab::Policy => views::policy::show(ui, self),
        });
    }
}
