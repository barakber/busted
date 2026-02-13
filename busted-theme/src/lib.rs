//! Shared color theme for busted dashboards (TUI + GUI).
//!
//! All colors are defined as `(u8, u8, u8)` RGB tuples so that
//! framework-specific crates (`ratatui`, `egui`) can convert them
//! to their own color types without pulling in either dependency.

use busted_types::agentic::AgenticAction;

pub type Rgb = (u8, u8, u8);

// ── Background / surface ────────────────────────────────────────────
pub const BG: Rgb = (15, 17, 23); // #0f1117
pub const SURFACE: Rgb = (22, 27, 34); // #161b22
pub const SURFACE_2: Rgb = (28, 33, 48); // #1c2130
pub const BORDER: Rgb = (45, 51, 59); // #2d333b

// ── Text hierarchy ──────────────────────────────────────────────────
pub const DIM_TEXT: Rgb = (125, 133, 144); // #7d8590
pub const NORMAL_TEXT: Rgb = (201, 209, 217); // #c9d1d9
pub const BRIGHT_TEXT: Rgb = (230, 237, 243); // #e6edf3

// ── Accent ──────────────────────────────────────────────────────────
pub const ACCENT: Rgb = (88, 166, 255); // #58a6ff
pub const ACCENT_DIM: Rgb = (31, 58, 95); // #1f3a5f

// ── Action type colors ──────────────────────────────────────────────
pub const PROMPT: Rgb = (210, 166, 65); // #d2a641  warm amber
pub const RESPONSE: Rgb = (63, 185, 80); // #3fb950  muted green
pub const TOOL: Rgb = (188, 140, 255); // #bc8cff  soft purple
pub const MCP: Rgb = (86, 212, 221); // #56d4dd  teal
pub const PII: Rgb = (248, 81, 73); // #f85149  muted red
pub const NETWORK: Rgb = (88, 166, 255); // #58a6ff  same as accent

// ── Policy decision colors ──────────────────────────────────────────
pub const ALLOW: Rgb = (63, 185, 80); // #3fb950
pub const AUDIT: Rgb = (210, 153, 34); // #d29922
pub const DENY: Rgb = (248, 81, 73); // #f85149

// ── Specialty backgrounds ───────────────────────────────────────────
pub const PII_ROW_BG: Rgb = (45, 21, 24); // #2d1518
pub const SELECTED_BG: Rgb = (31, 58, 95); // #1f3a5f  same as ACCENT_DIM
pub const HOVER_BG: Rgb = (28, 33, 48); // #1c2130  same as SURFACE_2

// ── Layout constants ────────────────────────────────────────────────
pub const ROUNDING: u8 = 6;

/// Map an action variant to its theme RGB color.
pub fn action_color(action: &AgenticAction) -> Rgb {
    match action {
        AgenticAction::Prompt { .. } => PROMPT,
        AgenticAction::Response { .. } => RESPONSE,
        AgenticAction::ToolCall { .. } | AgenticAction::ToolResult { .. } => TOOL,
        AgenticAction::McpRequest { .. } | AgenticAction::McpResponse { .. } => MCP,
        AgenticAction::PiiDetected { .. } => PII,
        AgenticAction::Network { .. } => NETWORK,
    }
}

/// Map a policy decision string to its theme RGB color.
pub fn policy_color(policy: Option<&str>) -> Rgb {
    match policy {
        Some("allow") => ALLOW,
        Some("audit") => AUDIT,
        Some("deny") => DENY,
        _ => DIM_TEXT,
    }
}

/// Tint a color toward a background: blend `ratio` of `bg` into `fg`.
/// `ratio` 0.0 = pure fg, 1.0 = pure bg.
pub fn tint(fg: Rgb, bg: Rgb, ratio: f32) -> Rgb {
    let r = ratio.clamp(0.0, 1.0);
    let mix = |a: u8, b: u8| -> u8 { ((a as f32 * (1.0 - r)) + (b as f32 * r)) as u8 };
    (mix(fg.0, bg.0), mix(fg.1, bg.1), mix(fg.2, bg.2))
}

/// Create a subtle background tint for pill badges: mostly `bg` with a hint of `fg`.
pub fn pill_bg(fg: Rgb, bg: Rgb) -> Rgb {
    tint(fg, bg, 0.85)
}
