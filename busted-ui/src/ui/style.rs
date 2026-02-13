use eframe::egui::{self, Color32, CornerRadius, Stroke};

use busted_theme as theme;
use busted_types::agentic::AgenticAction;

const fn c(rgb: theme::Rgb) -> Color32 {
    Color32::from_rgb(rgb.0, rgb.1, rgb.2)
}

// ── Background / surface ────────────────────────────────────────────
pub const BG_COLOR: Color32 = c(theme::BG);
pub const SURFACE: Color32 = c(theme::SURFACE);
pub const SURFACE_2: Color32 = c(theme::SURFACE_2);
pub const BORDER_COLOR: Color32 = c(theme::BORDER);

// ── Text hierarchy ──────────────────────────────────────────────────
pub const DIM_TEXT: Color32 = c(theme::DIM_TEXT);
pub const NORMAL_TEXT: Color32 = c(theme::NORMAL_TEXT);
pub const BRIGHT_TEXT: Color32 = c(theme::BRIGHT_TEXT);

// ── Accent ──────────────────────────────────────────────────────────
pub const ACCENT_COLOR: Color32 = c(theme::ACCENT);
pub const ACCENT_DIM: Color32 = c(theme::ACCENT_DIM);

// ── Action type colors ──────────────────────────────────────────────
pub const PROMPT_COLOR: Color32 = c(theme::PROMPT);
pub const RESPONSE_COLOR: Color32 = c(theme::RESPONSE);
pub const TOOL_COLOR: Color32 = c(theme::TOOL);
pub const MCP_COLOR: Color32 = c(theme::MCP);
pub const PII_COLOR: Color32 = c(theme::PII);
pub const NETWORK_COLOR: Color32 = c(theme::NETWORK);

// ── Policy colors ───────────────────────────────────────────────────
pub const POLICY_ALLOW_COLOR: Color32 = c(theme::ALLOW);
pub const POLICY_AUDIT_COLOR: Color32 = c(theme::AUDIT);
pub const POLICY_DENY_COLOR: Color32 = c(theme::DENY);

// ── Specialty backgrounds ───────────────────────────────────────────
pub const PII_ROW_BG: Color32 = c(theme::PII_ROW_BG);
pub const SELECTED_BG: Color32 = c(theme::SELECTED_BG);
pub const HOVER_BG: Color32 = c(theme::HOVER_BG);

// ── Layout ──────────────────────────────────────────────────────────
pub const ROUNDING: u8 = theme::ROUNDING;

pub fn action_color(action: &AgenticAction) -> Color32 {
    c(theme::action_color(action))
}

pub fn policy_color(policy: Option<&str>) -> Color32 {
    c(theme::policy_color(policy))
}

fn pill_bg_color(fg: Color32) -> Color32 {
    let rgb = theme::pill_bg((fg.r(), fg.g(), fg.b()), theme::BG);
    c(rgb)
}

/// Draw a rounded pill badge. Returns the Response for interaction.
pub fn pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) -> egui::Response {
    let galley =
        ui.fonts_mut(|f| f.layout_no_wrap(text.to_string(), egui::FontId::proportional(11.0), fg));
    let text_size = galley.size();
    let padding = egui::vec2(6.0, 2.0);
    let desired = text_size + padding * 2.0;
    let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(ROUNDING), bg);
        ui.painter().galley(rect.min + padding, galley, fg);
    }
    response
}

/// Draw an action-type pill: fg = action color, bg = tinted version.
pub fn action_pill(ui: &mut egui::Ui, text: &str, action_fg: Color32) -> egui::Response {
    pill(ui, text, action_fg, pill_bg_color(action_fg))
}

/// Draw a policy pill badge.
pub fn policy_pill(ui: &mut egui::Ui, text: &str, policy: Option<&str>) -> egui::Response {
    let fg = policy_color(policy);
    pill(ui, text, fg, pill_bg_color(fg))
}

/// A card-style frame: SURFACE fill, BORDER stroke, rounded.
pub fn card_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER_COLOR))
        .corner_radius(CornerRadius::same(ROUNDING))
        .inner_margin(egui::Margin::same(8))
}
