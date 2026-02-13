use std::collections::{HashMap, VecDeque};

use busted_types::agentic::{AgenticAction, BustedEvent};

const MAX_EVENTS: usize = 5000;
const SPARKLINE_BUCKETS: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Events,
    Processes,
    Providers,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Events, Tab::Processes, Tab::Providers];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Events => "Events",
            Tab::Processes => "Processes",
            Tab::Providers => "Providers",
        }
    }

    pub fn next(&self) -> Tab {
        match self {
            Tab::Events => Tab::Processes,
            Tab::Processes => Tab::Providers,
            Tab::Providers => Tab::Events,
        }
    }

    pub fn prev(&self) -> Tab {
        match self {
            Tab::Events => Tab::Providers,
            Tab::Processes => Tab::Events,
            Tab::Providers => Tab::Processes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Connecting,
    Demo,
}

#[derive(Clone)]
pub struct ProcessStat {
    pub name: String,
    pub pid: u32,
    pub event_count: u64,
    pub bytes: u64,
    pub pii_count: u64,
    pub providers: Vec<String>,
}

#[derive(Clone)]
pub struct ProviderStat {
    pub name: String,
    pub event_count: u64,
    pub bytes: u64,
    pub pii_count: u64,
    pub processes: Vec<String>,
}

pub struct App {
    pub demo_mode: bool,
    pub connection_state: ConnectionState,
    pub events: VecDeque<BustedEvent>,
    pub total_event_count: u64,
    pub active_tab: Tab,
    pub selected_index: Option<usize>,
    pub process_selected: Option<usize>,
    pub provider_selected: Option<usize>,
    pub detail_scroll: f32,
    pub search_query: String,
    pub provider_filter: Option<String>,
    pub process_filter: Option<String>,
    pub type_filter: Option<String>,
    pub policy_filter: Option<String>,
    pub input_mode: InputMode,
    pub paused: bool,
    pub show_detail: bool,
    pub show_help: bool,
    pub auto_scroll: bool,
    pub sparkline_buckets: VecDeque<u64>,
    pub events_this_tick: u64,
    pub content_height: f32,
}

impl App {
    pub fn new(demo_mode: bool) -> Self {
        let connection_state = if demo_mode {
            ConnectionState::Demo
        } else {
            ConnectionState::Connecting
        };
        let mut sparkline_buckets = VecDeque::with_capacity(SPARKLINE_BUCKETS);
        sparkline_buckets.resize(SPARKLINE_BUCKETS, 0);
        Self {
            demo_mode,
            connection_state,
            events: VecDeque::with_capacity(MAX_EVENTS),
            total_event_count: 0,
            active_tab: Tab::Events,
            selected_index: Some(0),
            process_selected: None,
            provider_selected: None,
            detail_scroll: 0.0,
            search_query: String::new(),
            provider_filter: None,
            process_filter: None,
            type_filter: None,
            policy_filter: None,
            input_mode: InputMode::Normal,
            paused: false,
            show_detail: false,
            show_help: false,
            auto_scroll: true,
            sparkline_buckets,
            events_this_tick: 0,
            content_height: 400.0,
        }
    }

    pub fn push_event(&mut self, event: BustedEvent) {
        if self.paused {
            return;
        }
        self.total_event_count += 1;
        self.events_this_tick += 1;
        self.events.push_front(event);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }
        if self.auto_scroll {
            self.selected_index = Some(0);
        }
    }

    pub fn tick(&mut self) {
        self.sparkline_buckets.push_back(self.events_this_tick);
        if self.sparkline_buckets.len() > SPARKLINE_BUCKETS {
            self.sparkline_buckets.pop_front();
        }
        self.events_this_tick = 0;
    }

    pub fn events_per_second(&self) -> f64 {
        let recent: u64 = self.sparkline_buckets.iter().rev().take(5).sum();
        recent as f64 / 5.0
    }

    pub fn sparkline_data(&self) -> Vec<u64> {
        self.sparkline_buckets.iter().copied().collect()
    }

    pub fn filtered_events(&self) -> Vec<&BustedEvent> {
        self.events
            .iter()
            .filter(|ev| {
                if let Some(ref pf) = self.provider_filter {
                    if ev.provider() != Some(pf.as_str()) {
                        return false;
                    }
                }
                if let Some(ref procf) = self.process_filter {
                    if ev.process.name != *procf {
                        return false;
                    }
                }
                if let Some(ref tf) = self.type_filter {
                    if ev.action_type() != tf.as_str() {
                        return false;
                    }
                }
                if let Some(ref polif) = self.policy_filter {
                    if ev.policy.as_deref() != Some(polif.as_str()) {
                        return false;
                    }
                }
                if !self.search_query.is_empty() {
                    let q = self.search_query.to_lowercase();
                    let matches = ev.process.name.to_lowercase().contains(&q)
                        || ev.sni().is_some_and(|s| s.to_lowercase().contains(&q))
                        || ev.model().is_some_and(|m| m.to_lowercase().contains(&q))
                        || ev.provider().is_some_and(|p| p.to_lowercase().contains(&q))
                        || ev.sdk().is_some_and(|s| s.to_lowercase().contains(&q))
                        || ev
                            .user_message()
                            .is_some_and(|m| m.to_lowercase().contains(&q));
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    pub fn selected_event(&self) -> Option<&BustedEvent> {
        let filtered = self.filtered_events();
        self.selected_index.and_then(|i| filtered.get(i).copied())
    }

    pub fn available_providers(&self) -> Vec<String> {
        let mut set: Vec<String> = self
            .events
            .iter()
            .filter_map(|ev| ev.provider().map(String::from))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        set.sort();
        set
    }

    pub fn available_types(&self) -> Vec<&'static str> {
        let mut set: Vec<&'static str> = self
            .events
            .iter()
            .map(|ev| ev.action_type())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        set.sort();
        set
    }

    pub fn process_stats(&self) -> Vec<ProcessStat> {
        let mut map: HashMap<(String, u32), ProcessStat> = HashMap::new();
        for ev in &self.events {
            let key = (ev.process.name.clone(), ev.process.pid);
            let stat = map.entry(key).or_insert_with(|| ProcessStat {
                name: ev.process.name.clone(),
                pid: ev.process.pid,
                event_count: 0,
                bytes: 0,
                pii_count: 0,
                providers: Vec::new(),
            });
            stat.event_count += 1;
            stat.bytes += ev.bytes();
            if ev.pii_detected() {
                stat.pii_count += 1;
            }
            if let Some(p) = ev.provider() {
                if !stat.providers.contains(&p.to_string()) {
                    stat.providers.push(p.to_string());
                }
            }
        }
        let mut stats: Vec<ProcessStat> = map.into_values().collect();
        stats.sort_by_key(|b| std::cmp::Reverse(b.event_count));
        stats
    }

    pub fn provider_stats(&self) -> Vec<ProviderStat> {
        let mut map: HashMap<String, ProviderStat> = HashMap::new();
        for ev in &self.events {
            let name = ev.provider().unwrap_or("Unknown").to_string();
            let stat = map.entry(name.clone()).or_insert_with(|| ProviderStat {
                name,
                event_count: 0,
                bytes: 0,
                pii_count: 0,
                processes: Vec::new(),
            });
            stat.event_count += 1;
            stat.bytes += ev.bytes();
            if ev.pii_detected() {
                stat.pii_count += 1;
            }
            let proc_name = &ev.process.name;
            if !stat.processes.contains(proc_name) {
                stat.processes.push(proc_name.clone());
            }
        }
        let mut stats: Vec<ProviderStat> = map.into_values().collect();
        stats.sort_by_key(|b| std::cmp::Reverse(b.event_count));
        stats
    }

    pub fn total_bytes(&self) -> u64 {
        self.events.iter().map(|ev| ev.bytes()).sum()
    }

    pub fn pii_count(&self) -> u64 {
        self.events.iter().filter(|ev| ev.pii_detected()).count() as u64
    }

    pub fn unique_processes(&self) -> usize {
        self.events
            .iter()
            .map(|ev| (&ev.process.name, ev.process.pid))
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    pub fn policy_breakdown(&self) -> (u64, u64, u64) {
        let mut allow = 0u64;
        let mut audit = 0u64;
        let mut deny = 0u64;
        for ev in &self.events {
            match ev.policy.as_deref() {
                Some("allow") => allow += 1,
                Some("audit") => audit += 1,
                Some("deny") => deny += 1,
                _ => {}
            }
        }
        (allow, audit, deny)
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
        self.total_event_count = 0;
        self.selected_index = None;
    }

    pub fn clear_filters(&mut self) {
        self.search_query.clear();
        self.provider_filter = None;
        self.process_filter = None;
        self.type_filter = None;
        self.policy_filter = None;
    }

    pub fn has_active_filters(&self) -> bool {
        !self.search_query.is_empty()
            || self.provider_filter.is_some()
            || self.process_filter.is_some()
            || self.type_filter.is_some()
            || self.policy_filter.is_some()
    }

    // Navigation helpers

    pub fn select_next(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let i = self
            .selected_index
            .map_or(0, |i| if i + 1 >= len { i } else { i + 1 });
        self.selected_index = Some(i);
        self.auto_scroll = false;
    }

    pub fn select_prev(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let i = self.selected_index.map_or(0, |i| i.saturating_sub(1));
        self.selected_index = Some(i);
        if i == 0 {
            self.auto_scroll = true;
        }
    }

    pub fn select_first(&mut self) {
        if !self.filtered_events().is_empty() {
            self.selected_index = Some(0);
            self.auto_scroll = true;
        }
    }

    pub fn select_last(&mut self) {
        let len = self.filtered_events().len();
        if len > 0 {
            self.selected_index = Some(len - 1);
            self.auto_scroll = false;
        }
    }

    fn visible_rows(&self) -> usize {
        (self.content_height / 20.0).max(1.0) as usize
    }

    pub fn half_page_down(&mut self) {
        let half = self.visible_rows() / 2;
        self.page_down(half.max(1));
    }

    pub fn half_page_up(&mut self) {
        let half = self.visible_rows() / 2;
        self.page_up(half.max(1));
    }

    pub fn full_page_down(&mut self) {
        self.page_down(self.visible_rows());
    }

    pub fn full_page_up(&mut self) {
        self.page_up(self.visible_rows());
    }

    pub fn page_down(&mut self, page_size: usize) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let i = self
            .selected_index
            .map_or(0, |i| (i + page_size).min(len - 1));
        self.selected_index = Some(i);
        self.auto_scroll = false;
    }

    pub fn page_up(&mut self, page_size: usize) {
        if self.filtered_events().is_empty() {
            return;
        }
        let i = self
            .selected_index
            .map_or(0, |i| i.saturating_sub(page_size));
        self.selected_index = Some(i);
        if i == 0 {
            self.auto_scroll = true;
        }
    }

    pub fn select_high(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let visible = self.visible_rows();
        let sel = self.selected_index.unwrap_or(0);
        let top = sel.saturating_sub(visible / 2);
        self.selected_index = Some(top.min(len - 1));
        self.auto_scroll = top == 0;
    }

    pub fn select_mid(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let mid = len / 2;
        self.selected_index = Some(mid);
        self.auto_scroll = false;
    }

    pub fn select_low(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let visible = self.visible_rows();
        let sel = self.selected_index.unwrap_or(0);
        let bottom = (sel + visible / 2).min(len - 1);
        self.selected_index = Some(bottom);
        self.auto_scroll = false;
    }

    pub fn detail_half_page_down(&mut self) {
        let half = (self.content_height / 2.0).max(1.0);
        self.detail_scroll += half;
    }

    pub fn detail_half_page_up(&mut self) {
        let half = (self.content_height / 2.0).max(1.0);
        self.detail_scroll = (self.detail_scroll - half).max(0.0);
    }

    pub fn detail_full_page_down(&mut self) {
        let page = self.content_height.max(1.0);
        self.detail_scroll += page;
    }

    pub fn detail_full_page_up(&mut self) {
        let page = self.content_height.max(1.0);
        self.detail_scroll = (self.detail_scroll - page).max(0.0);
    }

    pub fn cycle_provider_filter(&mut self) {
        let providers = self.available_providers();
        if providers.is_empty() {
            self.provider_filter = None;
            return;
        }
        self.provider_filter = match &self.provider_filter {
            None => Some(providers[0].clone()),
            Some(current) => {
                let idx = providers.iter().position(|p| p == current);
                match idx {
                    Some(i) if i + 1 < providers.len() => Some(providers[i + 1].clone()),
                    _ => None,
                }
            }
        };
    }

    pub fn cycle_type_filter(&mut self) {
        let types = self.available_types();
        if types.is_empty() {
            self.type_filter = None;
            return;
        }
        self.type_filter = match &self.type_filter {
            None => Some(types[0].to_string()),
            Some(current) => {
                let idx = types.iter().position(|t| *t == current.as_str());
                match idx {
                    Some(i) if i + 1 < types.len() => Some(types[i + 1].to_string()),
                    _ => None,
                }
            }
        };
    }

    pub fn toggle_detail(&mut self) {
        self.show_detail = !self.show_detail;
        self.detail_scroll = 0.0;
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn detail_scroll_down(&mut self) {
        self.detail_scroll += 20.0;
    }

    pub fn detail_scroll_up(&mut self) {
        self.detail_scroll = (self.detail_scroll - 20.0).max(0.0);
    }

    pub fn select_next_event_in_detail(&mut self) {
        self.select_next();
        self.detail_scroll = 0.0;
    }

    pub fn select_prev_event_in_detail(&mut self) {
        self.select_prev();
        self.detail_scroll = 0.0;
    }
}

pub fn format_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    }
}

pub fn action_arrow(action: &AgenticAction) -> &'static str {
    match action {
        AgenticAction::Prompt { .. } => ">>>",
        AgenticAction::Response { .. } => "<<<",
        AgenticAction::ToolCall { .. } => "<~>",
        AgenticAction::ToolResult { .. } => "~>",
        AgenticAction::McpRequest { .. } => "-->",
        AgenticAction::McpResponse { .. } => "<--",
        AgenticAction::PiiDetected { .. } => "!!!",
        AgenticAction::Network { .. } => "---",
    }
}
