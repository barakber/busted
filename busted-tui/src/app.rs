use std::collections::{HashMap, VecDeque};

use busted_types::agentic::{AgenticAction, BustedEvent};
use ratatui::widgets::TableState;

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
    pub running: bool,
    pub demo_mode: bool,
    pub connection_state: ConnectionState,
    pub events: VecDeque<BustedEvent>,
    pub total_event_count: u64,
    pub active_tab: Tab,
    pub table_state: TableState,
    pub process_table_state: TableState,
    pub provider_table_state: TableState,
    pub detail_scroll: usize,
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
    /// Visible rows in the content area (set by draw, used for page scroll).
    pub content_height: u16,
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
            running: true,
            demo_mode,
            connection_state,
            events: VecDeque::with_capacity(MAX_EVENTS),
            total_event_count: 0,
            active_tab: Tab::Events,
            table_state: TableState::default(),
            process_table_state: TableState::default(),
            provider_table_state: TableState::default(),
            detail_scroll: 0,
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
            content_height: 20,
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
            self.table_state.select(Some(0));
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
                            .is_some_and(|m| m.to_lowercase().contains(&q))
                        || ev
                            .file_path()
                            .is_some_and(|p| p.to_lowercase().contains(&q));
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
        self.table_state
            .selected()
            .and_then(|i| filtered.get(i).copied())
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
        stats.sort_by_key(|s| std::cmp::Reverse(s.event_count));
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
        stats.sort_by_key(|s| std::cmp::Reverse(s.event_count));
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
        self.table_state.select(None);
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
            .table_state
            .selected()
            .map_or(0, |i| if i + 1 >= len { i } else { i + 1 });
        self.table_state.select(Some(i));
        self.auto_scroll = false;
    }

    pub fn select_prev(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| i.saturating_sub(1));
        self.table_state.select(Some(i));
        if i == 0 {
            self.auto_scroll = true;
        }
    }

    pub fn select_first(&mut self) {
        if !self.filtered_events().is_empty() {
            self.table_state.select(Some(0));
            self.auto_scroll = true;
        }
    }

    pub fn select_last(&mut self) {
        let len = self.filtered_events().len();
        if len > 0 {
            self.table_state.select(Some(len - 1));
            self.auto_scroll = false;
        }
    }

    /// Visible rows in the table (content_height minus header row).
    fn visible_rows(&self) -> usize {
        self.content_height.saturating_sub(1).max(1) as usize
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
            .table_state
            .selected()
            .map_or(0, |i| (i + page_size).min(len - 1));
        self.table_state.select(Some(i));
        self.auto_scroll = false;
    }

    pub fn page_up(&mut self, page_size: usize) {
        if self.filtered_events().is_empty() {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map_or(0, |i| i.saturating_sub(page_size));
        self.table_state.select(Some(i));
        if i == 0 {
            self.auto_scroll = true;
        }
    }

    /// Select top of visible page (vim H).
    pub fn select_high(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let visible = self.visible_rows();
        // The "top" of the visible page is approximately selected - offset_from_top.
        // Since ratatui centers the selection, estimate the top of the viewport.
        let sel = self.table_state.selected().unwrap_or(0);
        let top = sel.saturating_sub(visible / 2);
        self.table_state.select(Some(top.min(len - 1)));
        self.auto_scroll = top == 0;
    }

    /// Select middle of visible page (vim M).
    pub fn select_mid(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        // Middle of the list if small, or keep current position roughly centered.
        let mid = len / 2;
        self.table_state.select(Some(mid));
        self.auto_scroll = false;
    }

    /// Select bottom of visible page (vim L).
    pub fn select_low(&mut self) {
        let len = self.filtered_events().len();
        if len == 0 {
            return;
        }
        let visible = self.visible_rows();
        let sel = self.table_state.selected().unwrap_or(0);
        let bottom = (sel + visible / 2).min(len - 1);
        self.table_state.select(Some(bottom));
        self.auto_scroll = false;
    }

    /// Half-page scroll for the detail panel.
    pub fn detail_half_page_down(&mut self) {
        let half = (self.content_height / 2).max(1) as usize;
        self.detail_scroll = self.detail_scroll.saturating_add(half);
    }

    pub fn detail_half_page_up(&mut self) {
        let half = (self.content_height / 2).max(1) as usize;
        self.detail_scroll = self.detail_scroll.saturating_sub(half);
    }

    pub fn detail_full_page_down(&mut self) {
        let page = self.content_height.max(1) as usize;
        self.detail_scroll = self.detail_scroll.saturating_add(page);
    }

    pub fn detail_full_page_up(&mut self) {
        let page = self.content_height.max(1) as usize;
        self.detail_scroll = self.detail_scroll.saturating_sub(page);
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
        self.detail_scroll = 0;
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn handle_search_input(&mut self, c: char) {
        self.search_query.push(c);
    }

    pub fn handle_search_backspace(&mut self) {
        self.search_query.pop();
    }

    pub fn detail_scroll_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    pub fn detail_scroll_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }

    pub fn select_next_event_in_detail(&mut self) {
        self.select_next();
        self.detail_scroll = 0;
    }

    pub fn select_prev_event_in_detail(&mut self) {
        self.select_prev();
        self.detail_scroll = 0;
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
        AgenticAction::FileAccess { .. } => "[o]",
        AgenticAction::FileData { direction, .. } => {
            if direction == "read" {
                "<-["
            } else {
                "]->"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busted_types::agentic::{NetworkEventKind, ProcessInfo};

    fn make_event(action_type: &str, provider: &str, policy: &str) -> BustedEvent {
        let action = match action_type {
            "Prompt" => AgenticAction::Prompt {
                provider: provider.into(),
                model: Some("gpt-4o".into()),
                user_message: Some("hello".into()),
                system_prompt: None,
                stream: false,
                sdk: Some("openai-python/1.40".into()),
                bytes: 256,
                sni: Some("api.openai.com".into()),
                endpoint: None,
                fingerprint: None,
                pii_detected: None,
                confidence: None,
                sdk_hash: None,
                model_hash: None,
            },
            "Response" => AgenticAction::Response {
                provider: provider.into(),
                model: Some("gpt-4o".into()),
                bytes: 1024,
                sni: Some("api.openai.com".into()),
                confidence: None,
            },
            "PiiDetected" => AgenticAction::PiiDetected {
                direction: "write".into(),
                pii_types: Some(vec!["ssn".into()]),
            },
            "Network" => AgenticAction::Network {
                kind: NetworkEventKind::Connect,
                src_ip: "127.0.0.1".into(),
                src_port: 1234,
                dst_ip: "1.2.3.4".into(),
                dst_port: 443,
                bytes: 0,
                sni: None,
                provider: Some(provider.into()),
            },
            _ => panic!("unknown type"),
        };
        BustedEvent {
            timestamp: "12:00:00.000".into(),
            process: ProcessInfo {
                pid: 1234,
                uid: 1000,
                name: "python3".into(),
                container_id: String::new(),
                cgroup_id: 0,
                pod_name: None,
                pod_namespace: None,
                service_account: None,
            },
            session_id: "1234:beef".into(),
            identity: None,
            policy: Some(policy.into()),
            action,
        }
    }

    #[test]
    fn new_app_defaults() {
        let app = App::new(true);
        assert!(app.running);
        assert!(app.demo_mode);
        assert_eq!(app.connection_state, ConnectionState::Demo);
        assert_eq!(app.events.len(), 0);
        assert_eq!(app.total_event_count, 0);
        assert_eq!(app.active_tab, Tab::Events);
        assert!(!app.paused);
        assert!(!app.show_detail);
        assert!(app.auto_scroll);
    }

    #[test]
    fn push_event_increments_count() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        assert_eq!(app.events.len(), 1);
        assert_eq!(app.total_event_count, 1);
        assert_eq!(app.events_this_tick, 1);
    }

    #[test]
    fn push_event_respects_pause() {
        let mut app = App::new(true);
        app.paused = true;
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        assert_eq!(app.events.len(), 0);
        assert_eq!(app.total_event_count, 0);
    }

    #[test]
    fn tick_advances_sparkline() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.push_event(make_event("Response", "OpenAI", "allow"));
        assert_eq!(app.events_this_tick, 2);
        app.tick();
        assert_eq!(app.events_this_tick, 0);
        assert_eq!(*app.sparkline_buckets.back().unwrap(), 2);
    }

    #[test]
    fn filter_by_provider() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.push_event(make_event("Prompt", "Anthropic", "allow"));
        app.provider_filter = Some("OpenAI".into());
        let filtered = app.filtered_events();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].provider(), Some("OpenAI"));
    }

    #[test]
    fn filter_by_search() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.push_event(make_event("Prompt", "Anthropic", "audit"));
        app.search_query = "anthropic".into();
        let filtered = app.filtered_events();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn policy_breakdown_counts() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.push_event(make_event("Prompt", "OpenAI", "audit"));
        app.push_event(make_event("Prompt", "OpenAI", "deny"));
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        let (a, u, d) = app.policy_breakdown();
        assert_eq!(a, 2);
        assert_eq!(u, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn pii_count() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.push_event(make_event("PiiDetected", "", "deny"));
        assert_eq!(app.pii_count(), 1);
    }

    #[test]
    fn total_bytes_sums() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow")); // 256
        app.push_event(make_event("Response", "OpenAI", "allow")); // 1024
        assert_eq!(app.total_bytes(), 1280);
    }

    #[test]
    fn clear_events_resets() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.clear_events();
        assert_eq!(app.events.len(), 0);
        assert_eq!(app.total_event_count, 0);
    }

    #[test]
    fn clear_filters_resets() {
        let mut app = App::new(true);
        app.provider_filter = Some("OpenAI".into());
        app.search_query = "test".into();
        assert!(app.has_active_filters());
        app.clear_filters();
        assert!(!app.has_active_filters());
    }

    #[test]
    fn navigation_select_next_prev() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "A", "allow"));
        app.push_event(make_event("Prompt", "B", "allow"));
        app.push_event(make_event("Prompt", "C", "allow"));
        app.table_state.select(Some(0));
        app.select_next();
        assert_eq!(app.table_state.selected(), Some(1));
        app.select_prev();
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn tab_cycling() {
        assert_eq!(Tab::Events.next(), Tab::Processes);
        assert_eq!(Tab::Processes.next(), Tab::Providers);
        assert_eq!(Tab::Providers.next(), Tab::Events);
        assert_eq!(Tab::Events.prev(), Tab::Providers);
    }

    #[test]
    fn format_bytes_formats() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn toggle_detail() {
        let mut app = App::new(true);
        assert!(!app.show_detail);
        app.toggle_detail();
        assert!(app.show_detail);
        app.toggle_detail();
        assert!(!app.show_detail);
    }

    #[test]
    fn toggle_pause() {
        let mut app = App::new(true);
        assert!(!app.paused);
        app.toggle_pause();
        assert!(app.paused);
    }

    #[test]
    fn cycle_provider_filter_cycles() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "Anthropic", "allow"));
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        // No filter initially
        assert!(app.provider_filter.is_none());
        app.cycle_provider_filter();
        // First provider alphabetically
        assert_eq!(app.provider_filter.as_deref(), Some("Anthropic"));
        app.cycle_provider_filter();
        assert_eq!(app.provider_filter.as_deref(), Some("OpenAI"));
        app.cycle_provider_filter();
        // Wraps back to None
        assert!(app.provider_filter.is_none());
    }

    #[test]
    fn half_page_uses_content_height() {
        let mut app = App::new(true);
        for i in 0..50 {
            app.push_event(make_event("Prompt", &format!("P{i}"), "allow"));
        }
        app.content_height = 20; // 19 visible rows after header
        app.table_state.select(Some(0));
        app.half_page_down(); // should move ~9 rows
        let sel = app.table_state.selected().unwrap();
        assert!(sel >= 8 && sel <= 10, "expected ~9, got {sel}");
    }

    #[test]
    fn full_page_uses_content_height() {
        let mut app = App::new(true);
        for i in 0..50 {
            app.push_event(make_event("Prompt", &format!("P{i}"), "allow"));
        }
        app.content_height = 20;
        app.table_state.select(Some(0));
        app.full_page_down();
        let sel = app.table_state.selected().unwrap();
        assert!(sel >= 18 && sel <= 20, "expected ~19, got {sel}");
    }

    #[test]
    fn detail_half_page_scroll() {
        let mut app = App::new(true);
        app.content_height = 30;
        app.detail_scroll = 0;
        app.detail_half_page_down();
        assert_eq!(app.detail_scroll, 15);
        app.detail_half_page_up();
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn select_high_mid_low() {
        let mut app = App::new(true);
        for i in 0..100 {
            app.push_event(make_event("Prompt", &format!("P{i}"), "allow"));
        }
        app.content_height = 20;
        app.table_state.select(Some(50));

        app.select_high();
        let h = app.table_state.selected().unwrap();
        assert!(h < 50, "high should be above 50, got {h}");

        app.table_state.select(Some(50));
        app.select_low();
        let l = app.table_state.selected().unwrap();
        assert!(l > 50, "low should be below 50, got {l}");

        app.select_mid();
        assert_eq!(app.table_state.selected().unwrap(), 50); // middle of 100 items
    }

    #[test]
    fn process_stats_aggregation() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.push_event(make_event("Response", "OpenAI", "allow"));
        let stats = app.process_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].event_count, 2);
        assert_eq!(stats[0].bytes, 1280); // 256 + 1024
    }

    #[test]
    fn provider_stats_aggregation() {
        let mut app = App::new(true);
        app.push_event(make_event("Prompt", "OpenAI", "allow"));
        app.push_event(make_event("Prompt", "Anthropic", "allow"));
        let stats = app.provider_stats();
        assert_eq!(stats.len(), 2);
    }
}
