//! ML behavioral traffic classifier for LLM communication patterns.
//!
//! `busted-ml` uses online machine learning to identify LLM API traffic from network
//! behavior patterns, complementing the content-based classification in `busted-classifier`.
//! It can detect LLM traffic even when payload inspection is unavailable (e.g., certificate
//! pinning, HTTP/2 multiplexing) by learning from temporal and statistical features of
//! network event sequences.
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
