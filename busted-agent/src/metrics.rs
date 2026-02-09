use anyhow::{Context, Result};
use log::info;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Initialize the Prometheus metrics exporter and register metric descriptions.
pub fn init(port: u16) -> Result<()> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .context("Failed to install Prometheus metrics exporter")?;

    // Register metric descriptions
    describe_counter!("busted_events_total", "Total number of events processed");
    describe_counter!(
        "busted_events_bytes_total",
        "Total bytes observed across events"
    );
    describe_gauge!(
        "busted_providers_detected",
        "Number of unique LLM providers detected"
    );
    describe_gauge!("busted_active_pids", "Number of PIDs with LLM traffic");
    describe_gauge!("busted_dns_resolutions", "Number of resolved provider IPs");
    describe_counter!(
        "busted_policy_decisions_total",
        "Total policy decisions by type"
    );
    describe_gauge!(
        "busted_tls_connections_tracked",
        "Number of active TLS connections being tracked"
    );
    describe_counter!("busted_tls_verdicts_total", "TLS connection verdicts");
    describe_histogram!(
        "busted_classifier_confidence",
        "Classifier confidence scores"
    );
    describe_counter!(
        "busted_ml_classifications_total",
        "ML behavioral classifications"
    );
    describe_histogram!(
        "busted_opa_eval_duration_seconds",
        "OPA policy evaluation latency in seconds"
    );

    info!("Prometheus metrics listening on {}", addr);
    Ok(())
}

/// Record a processed event (counter + bytes).
pub fn record_event(event_type: &str, provider: Option<&str>, bytes: u64) {
    let provider_label = provider.unwrap_or("none");
    counter!("busted_events_total", "event_type" => event_type.to_string(), "provider" => provider_label.to_string()).increment(1);
    counter!("busted_events_bytes_total", "event_type" => event_type.to_string(), "provider" => provider_label.to_string()).increment(bytes);
}

/// Record a policy decision (audit/deny).
pub fn record_policy_decision(decision: &str) {
    counter!("busted_policy_decisions_total", "decision" => decision.to_string()).increment(1);
}

/// Set the gauge for active PIDs with LLM traffic.
pub fn set_active_pids(count: usize) {
    gauge!("busted_active_pids").set(count as f64);
}

/// Set the gauge for unique providers detected.
pub fn set_providers_detected(count: usize) {
    gauge!("busted_providers_detected").set(count as f64);
}

/// Set the gauge for resolved DNS entries.
pub fn set_dns_resolutions(count: usize) {
    gauge!("busted_dns_resolutions").set(count as f64);
}

/// Record a TLS verdict (interesting/boring).
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub fn record_tls_verdict(verdict: &str) {
    counter!("busted_tls_verdicts_total", "verdict" => verdict.to_string()).increment(1);
}

/// Set the gauge for tracked TLS connections.
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub fn set_tls_connections_tracked(count: usize) {
    gauge!("busted_tls_connections_tracked").set(count as f64);
}

/// Record a classifier confidence score.
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub fn record_classifier_confidence(confidence: f32) {
    histogram!("busted_classifier_confidence").record(confidence as f64);
}

/// Record an ML behavioral classification.
#[cfg_attr(not(feature = "ml"), allow(dead_code))]
pub fn record_ml_classification(behavior_class: &str) {
    counter!("busted_ml_classifications_total", "behavior_class" => behavior_class.to_string())
        .increment(1);
}

/// Record OPA policy evaluation duration.
#[cfg_attr(not(feature = "opa"), allow(dead_code))]
pub fn record_opa_eval_duration(duration: std::time::Duration, decision: &str) {
    histogram!("busted_opa_eval_duration_seconds", "decision" => decision.to_string())
        .record(duration.as_secs_f64());
}
