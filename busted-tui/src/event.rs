use busted_types::agentic::BustedEvent;
use ratatui::crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};
use tokio::sync::mpsc;

/// Application-level event.
pub enum AppEvent {
    /// Terminal input event (key press)
    Key(KeyEvent),
    /// Resize event
    Resize(u16, u16),
    /// A BustedEvent from the socket or demo generator
    Busted(Box<BustedEvent>),
    /// 1-second tick for sparkline updates
    Tick,
}

/// Spawns async tasks that produce AppEvents into a single channel.
pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
}

impl EventHandler {
    /// Create handler and return a sender for BustedEvents.
    pub fn new_with_busted_tx(tick_rate_ms: u64) -> (Self, mpsc::UnboundedSender<AppEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();

        // Terminal event reader — uses blocking poll in a dedicated thread
        let term_tx = tx.clone();
        let poll_timeout = std::time::Duration::from_millis(50);
        std::thread::spawn(move || loop {
            if event::poll(poll_timeout).unwrap_or(false) {
                if let Ok(ev) = event::read() {
                    let app_event = match ev {
                        CrosstermEvent::Key(key) if key.kind == KeyEventKind::Press => {
                            Some(AppEvent::Key(key))
                        }
                        CrosstermEvent::Resize(w, h) => Some(AppEvent::Resize(w, h)),
                        _ => None,
                    };
                    if let Some(ev) = app_event {
                        if term_tx.send(ev).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // Tick timer
        let tick_tx = tx.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_millis(tick_rate_ms));
            loop {
                interval.tick().await;
                if tick_tx.send(AppEvent::Tick).is_err() {
                    break;
                }
            }
        });

        (Self { rx }, tx)
    }

    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }
}
