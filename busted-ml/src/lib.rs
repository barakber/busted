//! Identifies LLM API traffic from network behavior alone — no payload inspection
//! required.
//!
//! # Why behavioral classification?
//!
//! Content-based classification (`busted-classifier`) works
//! beautifully when you can read the payload: intercept TLS via eBPF uprobes, parse
//! the HTTP, match the endpoint, done. But sometimes you *can't* read the payload.
//! The application uses certificate pinning. The traffic is multiplexed over HTTP/2
//! and you only see opaque frames. The process links a TLS library you don't have
//! uprobes for. In all of these cases, content classification is blind.
//!
//! `busted-ml` takes a completely different approach. Instead of looking at *what* a
//! process says, it watches *how* it talks to the network — timing between packets,
//! sizes, bursts, port diversity — and learns to recognize LLM traffic from its
//! behavioral signature.
//!
//! # The insight
//!
//! LLM API calls have a distinctive network fingerprint. A typical interaction looks
//! like: large POST request (the prompt), long pause (model inference), then a burst
//! of small chunked responses (token streaming). This pattern — big-send, wait,
//! trickle-back — is very different from web browsing (many small GETs, fast
//! responses), file downloads (one request, sustained transfer), or database traffic
//! (rapid small round-trips). The ML model learns these signatures automatically from
//! labeled examples.
//!
//! # How it works
//!
//! Each network event arriving from the eBPF layer gets compressed into one of 180
//! discrete symbols — encoding the event type (connect, send, receive, close), a
//! byte-size bucket, and a port class. These symbols accumulate in a per-process
//! sliding window.
//!
//! When the window fills, a 352-dimensional feature vector is extracted: unigram,
//! bigram, and trigram frequency histograms capture *what* happened; timing statistics
//! and burst analysis capture *when*; connection diversity and entropy measures capture
//! *where*. This feature vector is the input to two parallel classifiers.
//!
//! The **supervised path** feeds the features into a bagged ensemble of 100 decision
//! trees (a random forest built on [`linfa`]). The forest is trained online — as new
//! events arrive with IP-based ground truth labels from the agent, the model
//! incrementally improves. It outputs a provider label and confidence score.
//!
//! The **unsupervised path** feeds the same features into [`hdbscan`] density-based
//! clustering. This catches novel traffic patterns that the supervised model hasn't
//! seen — a new LLM provider, an unusual SDK, or a tool using AI in an unexpected
//! way. Novel clusters surface as `is_novel: true` in the result.
//!
//! # Architecture
//!
//! The classifier operates on a per-PID sliding window of [`busted_types::NetworkEvent`]s:
//!
//! 1. **Symbolization** — Each event is mapped to a compact symbol encoding event type,
//!    byte-size bucket, and port class (180 possible symbols).
//! 2. **Feature extraction** — A 352-dimensional feature vector is computed from unigram,
//!    bigram, and trigram histograms, timing statistics, byte patterns, connection
//!    diversity, burst analysis, and entropy measures.
//! 3. **Supervised classification** — A bagged ensemble of 100 decision trees (random
//!    forest via [`linfa`]) is trained online from IP-labeled ground truth.
//! 4. **Unsupervised discovery** — [`hdbscan`] clustering detects novel traffic patterns
//!    not captured by the supervised model.
//!
//! # Integration with Busted
//!
//! In the Busted agent, `busted-ml` sits behind the `ml` feature flag. The agent feeds
//! every [`NetworkEvent`] to [`MlClassifier::process_event`],
//! along with any IP-based provider label it already has. The returned
//! [`BehaviorIdentity`] is folded into the
//! `ProcessedEvent` as `ml_confidence`,
//! `ml_provider`, `behavior_class`, and `cluster_id` fields. This means the UI and SIEM
//! sinks get both content-based *and* behavioral classifications for every connection.
//!
//! # Usage
//!
//! ```no_run
//! use busted_ml::MlClassifier;
//! use std::time::Duration;
//!
//! let mut classifier = MlClassifier::new();
//!
//! // Feed network events as they arrive:
//! // let result = classifier.process_event(&event, Some("OpenAI"));
//! // if let Some(identity) = result {
//! //     println!("class={}, confidence={}", identity.class, identity.confidence);
//! // }
//!
//! // Periodically garbage-collect idle PID windows:
//! classifier.gc_idle_pids(Duration::from_secs(300));
//! ```
//!
//! # Key Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`MlClassifier`] | Top-level coordinator — owns windows, classifier, and discovery |
//! | [`BehaviorClass`] | Classification result enum (`LlmApi`, `GenericHttps`, `DnsHeavy`, `Unknown`) |
//! | [`BehaviorIdentity`] | Full result with class, confidence, cluster ID, and signature |

mod classifier;
mod discovery;
mod features;
mod symbol;
mod window;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use busted_types::NetworkEvent;
use ndarray::Array1;
use serde::Serialize;

use classifier::TrainedClassifier;
use discovery::PatternDiscovery;
use features::FeatureExtractor;
use symbol::Symbol;
use window::{EventWindow, TimedSymbol, WindowConfig};

/// High-level behavioral classification result.
#[derive(Clone, Debug, Serialize)]
#[allow(dead_code)]
pub enum BehaviorClass {
    /// Traffic pattern matches a known LLM API provider.
    LlmApi(String),
    /// Generic HTTPS traffic (port 443, no LLM indicators).
    GenericHttps,
    /// DNS-heavy traffic pattern.
    DnsHeavy,
    /// Could not classify the traffic pattern.
    Unknown,
}

impl std::fmt::Display for BehaviorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BehaviorClass::LlmApi(provider) => write!(f, "LlmApi({})", provider),
            BehaviorClass::GenericHttps => write!(f, "GenericHttps"),
            BehaviorClass::DnsHeavy => write!(f, "DnsHeavy"),
            BehaviorClass::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Full behavioral identity for a traffic window.
#[derive(Clone, Debug, Serialize)]
pub struct BehaviorIdentity {
    /// Predicted traffic class.
    pub class: BehaviorClass,
    /// Classifier confidence (0.0–1.0).
    pub confidence: f64,
    /// HDBSCAN cluster ID (-1 = noise / not yet clustered).
    pub cluster_id: i32,
    /// Hash of top-5 bigrams as a behavioral signature.
    pub signature: u64,
    /// Number of events in the window when classified.
    pub window_size: usize,
    /// True if the pattern doesn't match any known provider.
    pub is_novel: bool,
}

/// Top-level ML classifier coordinator.
pub struct MlClassifier {
    windows: HashMap<u32, EventWindow>,
    extractor: FeatureExtractor,
    classifier: TrainedClassifier,
    discovery: PatternDiscovery,
    training_buffer: Vec<(Array1<f64>, String)>,
    config: WindowConfig,
    samples_since_train: usize,
    retrain_interval: usize,
    max_training_buffer: usize,
}

impl Default for MlClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MlClassifier {
    pub fn new() -> Self {
        MlClassifier {
            windows: HashMap::new(),
            extractor: FeatureExtractor::new(),
            classifier: TrainedClassifier::new(),
            discovery: PatternDiscovery::new(),
            training_buffer: Vec::new(),
            config: WindowConfig::default(),
            samples_since_train: 0,
            retrain_interval: 200,
            max_training_buffer: 10_000,
        }
    }

    /// Process a single network event. `ip_label` is the provider string from
    /// IP-based classification (e.g. "OpenAI"), or None if unclassified.
    /// Returns a BehaviorIdentity when the window is ready for classification.
    pub fn process_event(
        &mut self,
        event: &NetworkEvent,
        ip_label: Option<&str>,
    ) -> Option<BehaviorIdentity> {
        let symbol = Symbol::from_network_event(event);

        // FNV-1a hash of destination IP bytes for diversity tracking
        let dst_ip_hash = {
            let bytes = unsafe { event.daddr.ipv6 };
            let mut h: u32 = 0x811c9dc5;
            for &b in &bytes {
                h ^= b as u32;
                h = h.wrapping_mul(0x01000193);
            }
            h
        };

        let timed = TimedSymbol {
            symbol,
            timestamp_ns: event.timestamp_ns,
            bytes: event.bytes,
            arrived_at: Instant::now(),
            dst_ip_hash,
            dst_port: event.dport,
        };

        let window = self
            .windows
            .entry(event.pid)
            .or_insert_with(|| EventWindow::new(event.pid));

        let ready = window.push(timed, &self.config);
        if !ready {
            return None;
        }

        // Extract features
        let features = self.extractor.extract(window);
        let window_size = window.len();
        window.mark_classified();

        // Feed training buffer if we have a ground truth label
        let label = if let Some(provider) = ip_label {
            provider.to_string()
        } else if event.dport == 443 {
            "GenericHttps".to_string()
        } else {
            "Unknown".to_string()
        };

        self.training_buffer.push((features.clone(), label.clone()));
        self.samples_since_train += 1;

        // FIFO eviction
        if self.training_buffer.len() > self.max_training_buffer {
            let excess = self.training_buffer.len() - self.max_training_buffer;
            self.training_buffer.drain(0..excess);
        }

        // Retrain periodically
        if self.samples_since_train >= self.retrain_interval {
            self.samples_since_train = 0;
            match self.classifier.train(&self.training_buffer) {
                Ok(()) => {
                    log::info!("ML model trained on {} samples", self.training_buffer.len());
                }
                Err(e) => {
                    log::debug!("ML training skipped: {}", e);
                }
            }
        }

        // Classify
        let (class, confidence, is_novel) =
            if let Some((pred_label, conf)) = self.classifier.predict(&features) {
                let class = match pred_label.as_str() {
                    "GenericHttps" => BehaviorClass::GenericHttps,
                    "Unknown" => BehaviorClass::Unknown,
                    provider => BehaviorClass::LlmApi(provider.to_string()),
                };
                let is_novel = ip_label.is_none() && matches!(&class, BehaviorClass::LlmApi(_));
                (class, conf, is_novel)
            } else {
                (BehaviorClass::Unknown, 0.0, false)
            };

        // Unsupervised discovery
        let cluster_id = self.discovery.ingest(features.as_slice().unwrap());

        // Compute behavioral signature from top-5 bigram bins
        let signature = compute_signature(features.as_slice().unwrap());

        Some(BehaviorIdentity {
            class,
            confidence,
            cluster_id,
            signature,
            window_size,
            is_novel,
        })
    }

    /// Remove windows for PIDs that have been idle longer than `max_idle`.
    pub fn gc_idle_pids(&mut self, max_idle: Duration) {
        let now = Instant::now();
        self.windows.retain(|_, w| {
            w.last_arrival()
                .is_some_and(|t| now.duration_since(t) < max_idle)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ml_classifier_new_default() {
        let c = MlClassifier::new();
        assert!(c.windows.is_empty());
        assert!(c.training_buffer.is_empty());
    }

    #[test]
    fn ml_classifier_default_trait() {
        let c = MlClassifier::default();
        assert!(c.windows.is_empty());
    }

    #[test]
    fn compute_signature_short_features_returns_zero() {
        assert_eq!(compute_signature(&[1.0; 10]), 0);
    }

    #[test]
    fn compute_signature_deterministic() {
        let features = vec![0.1; 352];
        let h1 = compute_signature(&features);
        let h2 = compute_signature(&features);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_signature_different_inputs_different_hashes() {
        let mut f1 = vec![0.0; 352];
        f1[180] = 1.0; // first bigram bin
        let mut f2 = vec![0.0; 352];
        f2[181] = 1.0; // second bigram bin
        assert_ne!(compute_signature(&f1), compute_signature(&f2));
    }

    #[test]
    fn behavior_class_display() {
        assert_eq!(
            BehaviorClass::LlmApi("OpenAI".into()).to_string(),
            "LlmApi(OpenAI)"
        );
        assert_eq!(BehaviorClass::GenericHttps.to_string(), "GenericHttps");
        assert_eq!(BehaviorClass::DnsHeavy.to_string(), "DnsHeavy");
        assert_eq!(BehaviorClass::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn gc_idle_pids_removes_stale() {
        let mut c = MlClassifier::new();
        // Insert a window manually
        c.windows.insert(1, window::EventWindow::new(1));
        c.windows.insert(2, window::EventWindow::new(2));
        // Both windows have no events → last_arrival() is None → removed
        c.gc_idle_pids(Duration::from_secs(60));
        assert!(c.windows.is_empty());
    }
}

/// Hash the top-5 bigram bin values as a behavioral signature.
fn compute_signature(features: &[f64]) -> u64 {
    let bigram_start = symbol::SYMBOL_SPACE;
    let bigram_end = bigram_start + 100;

    if features.len() < bigram_end {
        return 0;
    }

    // Find top-5 bigram bins by value
    let mut indexed: Vec<(usize, f64)> = features[bigram_start..bigram_end]
        .iter()
        .enumerate()
        .map(|(i, &v)| (i, v))
        .collect();
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut h: u64 = 0xcbf29ce484222325;
    for &(idx, _) in indexed.iter().take(5) {
        h ^= idx as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
