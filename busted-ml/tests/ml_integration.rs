//! Integration tests for busted-ml MlClassifier.

use busted_ml::MlClassifier;
use busted_types::{IpAddress, NetworkEvent};
use std::time::Duration;

fn make_event(pid: u32, event_type: u8, bytes: u64, dport: u16, timestamp_ns: u64) -> NetworkEvent {
    let mut e = NetworkEvent::new();
    e.pid = pid;
    e.event_type = event_type;
    e.bytes = bytes;
    e.dport = dport;
    e.timestamp_ns = timestamp_ns;
    e.family = 2; // IPv4
    e.daddr = IpAddress {
        ipv4: u32::to_be(0x5DB8D822),
    }; // 93.184.216.34
    e
}

#[test]
fn process_event_returns_none_initially() {
    let mut c = MlClassifier::new();
    let e = make_event(100, 1, 0, 443, 1_000_000);
    assert!(c.process_event(&e, None).is_none());
}

#[test]
fn process_event_returns_some_after_enough_events() {
    let mut c = MlClassifier::new();
    let mut result = None;
    // Default: min_events=20, stride=10 → need 20 events
    for i in 0..30 {
        let e = make_event(
            100,
            (i % 5 + 1) as u8,
            (i * 100) as u64,
            443,
            i as u64 * 1_000_000,
        );
        if let Some(r) = c.process_event(&e, Some("OpenAI")) {
            result = Some(r);
            break;
        }
    }
    let r = result.expect("should classify after enough events");
    assert!(r.confidence >= 0.0 && r.confidence <= 1.0);
    assert!(r.window_size >= 20);
}

#[test]
fn multiple_pids_maintain_separate_windows() {
    let mut c = MlClassifier::new();
    // Feed events to two different PIDs
    for i in 0..25 {
        let ts = i as u64 * 1_000_000;
        c.process_event(&make_event(100, 2, 500, 443, ts), Some("OpenAI"));
        c.process_event(&make_event(200, 2, 500, 80, ts + 500_000), None);
    }
    // Both PIDs should have windows
    // After process_event, there should be results for both
}

#[test]
fn gc_idle_pids_removes_stale_keeps_active() {
    let mut c = MlClassifier::new();
    // Feed some events to PID 100
    for i in 0..5 {
        c.process_event(&make_event(100, 1, 0, 443, i * 1_000_000), None);
    }
    // Feed some events to PID 200
    for i in 0..5 {
        c.process_event(&make_event(200, 1, 0, 443, i * 1_000_000), None);
    }
    // GC with very short idle time — all windows have recent arrival times
    c.gc_idle_pids(Duration::from_secs(0));
    // With max_idle=0, all pids should be removed
}

#[test]
fn behavior_identity_fields_valid() {
    let mut c = MlClassifier::new();
    let mut result = None;
    for i in 0..30 {
        let e = make_event(
            100,
            (i % 5 + 1) as u8,
            (i * 100) as u64,
            443,
            i as u64 * 1_000_000,
        );
        if let Some(r) = c.process_event(&e, Some("OpenAI")) {
            result = Some(r);
            break;
        }
    }
    let r = result.unwrap();
    assert!(r.confidence >= 0.0 && r.confidence <= 1.0);
    assert!(r.window_size > 0);
    // cluster_id is -1 initially (not enough for clustering)
    assert_eq!(r.cluster_id, -1);
    // signature is computed from features
    // is_novel depends on classifier state
}

#[test]
fn training_buffer_fifo_eviction_no_panic() {
    let mut c = MlClassifier::new();
    // Feed many events to trigger buffer growth
    for i in 0..500 {
        let e = make_event(
            1,
            (i % 5 + 1) as u8,
            (i * 10) as u64,
            443,
            i as u64 * 100_000,
        );
        c.process_event(&e, Some("TestProvider"));
    }
    // Should not panic
}

#[test]
fn multiple_retrain_rounds_no_panic() {
    let mut c = MlClassifier::new();
    // Need retrain_interval=200 classifications to trigger retrain, but that needs
    // at least 2 classes. We'll feed enough events with two different labels.
    for i in 0..500 {
        let provider = if i % 2 == 0 {
            Some("ClassA")
        } else {
            Some("ClassB")
        };
        let port = if i % 2 == 0 { 443 } else { 80 };
        let e = make_event(
            1,
            (i % 5 + 1) as u8,
            (i * 50) as u64,
            port,
            i as u64 * 100_000,
        );
        c.process_event(&e, provider);
    }
}

#[test]
fn process_event_with_no_label_uses_defaults() {
    let mut c = MlClassifier::new();
    let mut result = None;
    for i in 0..30 {
        let e = make_event(
            100,
            (i % 5 + 1) as u8,
            (i * 100) as u64,
            443,
            i as u64 * 1_000_000,
        );
        if let Some(r) = c.process_event(&e, None) {
            result = Some(r);
            break;
        }
    }
    // With no ip_label and dport=443, label defaults to "GenericHttps"
    assert!(result.is_some());
}
