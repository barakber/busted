use crate::views;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::mpsc;

#[derive(Clone, Debug, Deserialize)]
pub struct ProcessedEvent {
    pub event_type: String,
    pub timestamp: String,
    pub pid: u32,
    pub uid: u32,
    pub process_name: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub bytes: u64,
    pub provider: Option<String>,
    pub policy: Option<String>,
    pub container_id: String,
    #[serde(default)]
    pub cgroup_id: u64,
    #[serde(default)]
    pub request_rate: Option<f64>,
    #[serde(default)]
    pub session_bytes: Option<u64>,
}

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
    pub filter_provider: String,
    pub filter_process: String,
    pub filter_event_type: String,
    pub provider_stats: HashMap<String, ProviderStats>,
    pub process_info: HashMap<u32, ProcessInfo>,
    pub auto_scroll: bool,
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
    pub fn new(rx: mpsc::Receiver<ProcessedEvent>) -> Self {
        Self {
            rx,
            events: Vec::new(),
            tab: Tab::LiveEvents,
            paused: false,
            connected: false,
            filter_provider: String::new(),
            filter_process: String::new(),
            filter_event_type: String::new(),
            provider_stats: HashMap::new(),
            process_info: HashMap::new(),
            auto_scroll: true,
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
                let status = if self.connected {
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

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::LiveEvents => views::events::show(ui, self),
            Tab::Providers => views::providers::show(ui, self),
            Tab::Processes => views::processes::show(ui, self),
            Tab::Policy => views::policy::show(ui, self),
        });
    }
}
