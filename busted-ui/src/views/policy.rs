use crate::app::BustedApp;

pub fn show(ui: &mut egui::Ui, app: &mut BustedApp) {
    ui.heading("Policy Configuration");
    ui.separator();

    ui.label(
        "Configure allow/deny/audit rules for LLM API access. \
         Note: Enforcement requires the agent to be running with --enforce flag. \
         Kprobe-based enforcement is audit-only; full blocking requires TC/XDP/LSM (future work).",
    );

    ui.separator();

    // Existing rules
    if app.policy_rules.is_empty() {
        ui.label("No policy rules configured.");
    } else {
        let mut to_remove = None;

        egui::Grid::new("policy_rules_grid")
            .num_columns(4)
            .spacing([20.0, 8.0])
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Pattern");
                ui.strong("Action");
                ui.strong("Enabled");
                ui.strong("");
                ui.end_row();

                for (i, rule) in app.policy_rules.iter_mut().enumerate() {
                    ui.label(&rule.pattern);
                    ui.label(&rule.action);
                    ui.checkbox(&mut rule.enabled, "");
                    if ui.button("Remove").clicked() {
                        to_remove = Some(i);
                    }
                    ui.end_row();
                }
            });

        if let Some(idx) = to_remove {
            app.policy_rules.remove(idx);
        }
    }

    ui.separator();
    ui.heading("Add Rule");

    ui.horizontal(|ui| {
        ui.label("Pattern (process name or provider):");
        ui.text_edit_singleline(&mut app.new_rule_pattern);
    });

    ui.horizontal(|ui| {
        ui.label("Action:");
        egui::ComboBox::from_id_salt("new_rule_action")
            .selected_text(&app.new_rule_action)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.new_rule_action, "allow".to_string(), "Allow");
                ui.selectable_value(&mut app.new_rule_action, "deny".to_string(), "Deny");
                ui.selectable_value(&mut app.new_rule_action, "audit".to_string(), "Audit");
            });
    });

    if ui.button("Add Rule").clicked() && !app.new_rule_pattern.is_empty() {
        app.policy_rules.push(crate::app::PolicyRule {
            pattern: app.new_rule_pattern.clone(),
            action: app.new_rule_action.clone(),
            enabled: true,
        });
        app.new_rule_pattern.clear();
    }
}
