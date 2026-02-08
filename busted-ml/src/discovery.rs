/// Unsupervised pattern discovery via HDBSCAN clustering.
/// Buffers feature vectors and periodically reclusters to discover
/// novel traffic patterns not captured by the supervised classifier.
pub struct PatternDiscovery {
    feature_buffer: Vec<Vec<f32>>,
    cluster_labels: Vec<i32>,
    max_buffer_size: usize,
    min_cluster_size: usize,
}

impl PatternDiscovery {
    pub fn new() -> Self {
        PatternDiscovery {
            feature_buffer: Vec::new(),
            cluster_labels: Vec::new(),
            max_buffer_size: 2000,
            min_cluster_size: 10,
        }
    }

    /// Ingest a feature vector and return its cluster assignment.
    /// Returns -1 (noise) until enough data accumulates for clustering.
    pub fn ingest(&mut self, features: &[f64]) -> i32 {
        // Convert f64 features to f32 for hdbscan
        let f32_features: Vec<f32> = features.iter().map(|&v| v as f32).collect();
        self.feature_buffer.push(f32_features);

        let idx = self.feature_buffer.len() - 1;

        // Recluster when buffer is full
        if self.feature_buffer.len() >= self.max_buffer_size {
            self.recluster();
        }

        // Return label if available
        if idx < self.cluster_labels.len() {
            self.cluster_labels[idx]
        } else {
            -1 // Not yet clustered
        }
    }

    /// Run HDBSCAN on the buffered features.
    fn recluster(&mut self) {
        if self.feature_buffer.len() < self.min_cluster_size * 2 {
            return;
        }

        let hyper_params = hdbscan::HdbscanHyperParams::builder()
            .min_cluster_size(self.min_cluster_size)
            .build();

        let clusterer = hdbscan::Hdbscan::new(&self.feature_buffer, hyper_params);
        match clusterer.cluster() {
            Ok(labels) => {
                let n_clusters = labels.iter().filter(|&&l| l >= 0).max().map_or(0, |m| m + 1);
                log::info!(
                    "HDBSCAN: {} clusters found in {} samples ({} noise)",
                    n_clusters,
                    labels.len(),
                    labels.iter().filter(|&&l| l < 0).count()
                );
                self.cluster_labels = labels;
            }
            Err(e) => {
                log::warn!("HDBSCAN clustering failed: {:?}", e);
            }
        }

        // FIFO eviction: keep the most recent half
        if self.feature_buffer.len() >= self.max_buffer_size {
            let half = self.feature_buffer.len() / 2;
            self.feature_buffer.drain(0..half);
            self.cluster_labels.clear(); // invalidate labels until next recluster
        }
    }

    #[allow(dead_code)]
    pub fn last_cluster_label(&self) -> i32 {
        self.cluster_labels.last().copied().unwrap_or(-1)
    }

    #[allow(dead_code)]
    pub fn num_clusters(&self) -> usize {
        if self.cluster_labels.is_empty() {
            return 0;
        }
        self.cluster_labels
            .iter()
            .filter(|&&l| l >= 0)
            .max()
            .map_or(0, |&m| (m + 1) as usize)
    }
}
