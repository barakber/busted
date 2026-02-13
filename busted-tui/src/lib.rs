pub mod app;
pub mod demo;
pub mod event;
pub mod socket;
pub mod ui;

use app::{App, InputMode, Tab};
use event::{AppEvent, EventHandler};
use ratatui::crossterm::event::{KeyCode, KeyModifiers};

/// Configuration for the TUI dashboard.
pub struct TuiConfig {
    pub demo_mode: bool,
}

/// Launch the terminal dashboard.
pub async fn run_tui(config: TuiConfig) -> anyhow::Result<()> {
    // Setup terminal
    ratatui::crossterm::terminal::enable_raw_mode()?;
    ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::terminal::EnterAlternateScreen,
        ratatui::crossterm::event::EnableMouseCapture,
    )?;

    let backend = ratatui::backend::CrosstermBackend::new(std::io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = run_app(&mut terminal, config).await;

    // Restore terminal
    ratatui::crossterm::terminal::disable_raw_mode()?;
    ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::terminal::LeaveAlternateScreen,
        ratatui::crossterm::event::DisableMouseCapture,
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_app(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    config: TuiConfig,
) -> anyhow::Result<()> {
    let mut app = App::new(config.demo_mode);
    let (mut events, busted_tx) = EventHandler::new_with_busted_tx(1000);

    // Spawn data source
    if config.demo_mode {
        tokio::spawn(demo::start(busted_tx));
    } else {
        tokio::spawn(socket::unix_socket_bridge(busted_tx));
    }

    // Initial draw
    terminal.draw(|f| ui::draw(f, &mut app))?;

    while app.running {
        if let Some(event) = events.next().await {
            match event {
                AppEvent::Key(key) => handle_key(&mut app, key),
                AppEvent::Busted(ev) => app.push_event(*ev),
                AppEvent::Tick => app.tick(),
                AppEvent::Resize(_, _) => {} // redraw handles this
            }
            terminal.draw(|f| ui::draw(f, &mut app))?;
        }
    }

    Ok(())
}

fn handle_key(app: &mut App, key: ratatui::crossterm::event::KeyEvent) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    // Ctrl-C always quits
    if ctrl && key.code == KeyCode::Char('c') {
        app.running = false;
        return;
    }

    // Help popup intercepts all keys
    if app.show_help {
        match key.code {
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                app.show_help = false;
            }
            _ => {}
        }
        return;
    }

    // Search mode — only text input keys
    if app.input_mode == InputMode::Search {
        match key.code {
            KeyCode::Esc => app.input_mode = InputMode::Normal,
            KeyCode::Enter => app.input_mode = InputMode::Normal,
            KeyCode::Backspace => app.handle_search_backspace(),
            KeyCode::Char(c) => app.handle_search_input(c),
            _ => {}
        }
        return;
    }

    // Detail panel mode — j/k scroll detail, n/N navigate events
    if app.show_detail && app.active_tab == Tab::Events {
        match key.code {
            KeyCode::Char('q') => {
                app.running = false;
                return;
            }
            KeyCode::Esc => {
                app.show_detail = false;
                return;
            }
            KeyCode::Char('?') => {
                app.show_help = true;
                return;
            }
            // Scroll detail content
            KeyCode::Char('j') | KeyCode::Down => {
                app.detail_scroll_down();
                return;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                app.detail_scroll_up();
                return;
            }
            KeyCode::Char('d') if ctrl => {
                app.detail_half_page_down();
                return;
            }
            KeyCode::Char('u') if ctrl => {
                app.detail_half_page_up();
                return;
            }
            KeyCode::Char('f') if ctrl => {
                app.detail_full_page_down();
                return;
            }
            KeyCode::Char('b') if ctrl => {
                app.detail_full_page_up();
                return;
            }
            KeyCode::PageDown => {
                app.detail_full_page_down();
                return;
            }
            KeyCode::PageUp => {
                app.detail_full_page_up();
                return;
            }
            KeyCode::Char('g') | KeyCode::Home => {
                app.detail_scroll = 0;
                return;
            }
            KeyCode::Char('G') | KeyCode::End => {
                // Scroll to a large value; the Paragraph widget clamps internally.
                app.detail_scroll = usize::MAX / 2;
                return;
            }
            // Navigate events while detail is open
            KeyCode::Char('n') => {
                app.select_next_event_in_detail();
                return;
            }
            KeyCode::Char('N') => {
                app.select_prev_event_in_detail();
                return;
            }
            // Let through keys that make sense globally: tabs, pause, etc.
            _ => {} // fall through
        }
    }

    // Normal mode
    match key.code {
        KeyCode::Char('q') => app.running = false,

        // Vim movement
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('g') | KeyCode::Home => app.select_first(),
        KeyCode::Char('G') | KeyCode::End => app.select_last(),

        // Vim page scroll
        KeyCode::Char('d') if ctrl => app.half_page_down(),
        KeyCode::Char('u') if ctrl => app.half_page_up(),
        KeyCode::Char('f') if ctrl => app.full_page_down(),
        KeyCode::Char('b') if ctrl => app.full_page_up(),
        KeyCode::PageDown => app.full_page_down(),
        KeyCode::PageUp => app.full_page_up(),

        // Vim viewport jumps
        KeyCode::Char('H') => app.select_high(),
        KeyCode::Char('M') => app.select_mid(),
        KeyCode::Char('L') => app.select_low(),

        // Actions
        KeyCode::Enter => app.toggle_detail(),
        KeyCode::Esc => {
            if !app.search_query.is_empty() {
                app.search_query.clear();
            } else if app.show_detail {
                app.show_detail = false;
            }
        }
        KeyCode::Char(' ') => app.toggle_pause(),
        KeyCode::Char('/') => {
            app.input_mode = InputMode::Search;
        }

        // Tabs
        KeyCode::Tab => app.active_tab = app.active_tab.next(),
        KeyCode::BackTab => app.active_tab = app.active_tab.prev(),
        KeyCode::Char('1') => app.active_tab = Tab::Events,
        KeyCode::Char('2') => app.active_tab = Tab::Processes,
        KeyCode::Char('3') => app.active_tab = Tab::Providers,

        // Filters & actions
        KeyCode::Char('c') => app.clear_events(),
        KeyCode::Char('C') => app.clear_filters(),
        KeyCode::Char('p') => app.cycle_provider_filter(),
        KeyCode::Char('t') => app.cycle_type_filter(),
        KeyCode::Char('?') => app.show_help = true,
        _ => {}
    }
}
