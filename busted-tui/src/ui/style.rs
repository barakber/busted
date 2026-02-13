use ratatui::style::{Color, Modifier, Style};

use busted_theme as theme;
use busted_types::agentic::AgenticAction;

const fn c(rgb: theme::Rgb) -> Color {
    Color::Rgb(rgb.0, rgb.1, rgb.2)
}

// Action type colors
pub const PROMPT_COLOR: Color = c(theme::PROMPT);
pub const RESPONSE_COLOR: Color = c(theme::RESPONSE);
pub const TOOL_COLOR: Color = c(theme::TOOL);
pub const MCP_COLOR: Color = c(theme::MCP);
pub const PII_COLOR: Color = c(theme::PII);
pub const NETWORK_COLOR: Color = c(theme::NETWORK);

// Policy colors
pub const POLICY_ALLOW_COLOR: Color = c(theme::ALLOW);
pub const POLICY_AUDIT_COLOR: Color = c(theme::AUDIT);
pub const POLICY_DENY_COLOR: Color = c(theme::DENY);

// UI element colors
pub const HEADER_BG: Color = c(theme::SURFACE);
pub const SELECTED_BG: Color = c(theme::SELECTED_BG);
pub const BORDER_COLOR: Color = c(theme::BORDER);
pub const DIM_TEXT: Color = c(theme::DIM_TEXT);
pub const NORMAL_TEXT: Color = c(theme::NORMAL_TEXT);
pub const BRIGHT_TEXT: Color = c(theme::BRIGHT_TEXT);
pub const ACCENT_COLOR: Color = c(theme::ACCENT);

pub fn action_color(action: &AgenticAction) -> Color {
    c(theme::action_color(action))
}

pub fn policy_color(policy: Option<&str>) -> Color {
    c(theme::policy_color(policy))
}

pub fn action_style(action: &AgenticAction) -> Style {
    Style::default().fg(action_color(action))
}

pub fn selected_style() -> Style {
    Style::default()
        .bg(SELECTED_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn header_style() -> Style {
    Style::default().fg(BRIGHT_TEXT).bg(HEADER_BG)
}

pub fn dim_style() -> Style {
    Style::default().fg(DIM_TEXT)
}

pub fn normal_style() -> Style {
    Style::default().fg(NORMAL_TEXT)
}

pub fn accent_style() -> Style {
    Style::default().fg(ACCENT_COLOR)
}

pub fn pii_row_style() -> Style {
    Style::default().bg(c(theme::PII_ROW_BG))
}
