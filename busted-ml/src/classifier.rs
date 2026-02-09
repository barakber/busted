use std::collections::HashMap;

use linfa::prelude::*;
use linfa_trees::DecisionTree;
use ndarray::{Array1, Array2, Axis};
use rand::seq::SliceRandom;
use rand::thread_rng;

use crate::features::FEATURE_DIM;

/// Maps string labels <-> integer indices for the classifier.
pub struct LabelEncoder {
    label_to_idx: HashMap<String, usize>,
    idx_to_label: Vec<String>,
}

impl LabelEncoder {
    pub fn new() -> Self {
        LabelEncoder {
            label_to_idx: HashMap::new(),
            idx_to_label: Vec::new(),
        }
    }

    pub fn encode(&mut self, label: &str) -> usize {
        if let Some(&idx) = self.label_to_idx.get(label) {
            return idx;
        }
        let idx = self.idx_to_label.len();
        self.idx_to_label.push(label.to_string());
        self.label_to_idx.insert(label.to_string(), idx);
        idx
    }

    pub fn decode(&self, idx: usize) -> Option<&str> {
        self.idx_to_label.get(idx).map(|s| s.as_str())
    }

    pub fn num_classes(&self) -> usize {
        self.idx_to_label.len()
    }
}

/// Bagged ensemble of decision trees (Random Forest).
pub struct TrainedClassifier {
    trees: Vec<DecisionTree<f64, usize>>,
    label_encoder: LabelEncoder,
    n_trees: usize,
    min_training_samples: usize,
    bootstrap_fraction: f64,
}

impl TrainedClassifier {
    pub fn new() -> Self {
        TrainedClassifier {
            trees: Vec::new(),
            label_encoder: LabelEncoder::new(),
            n_trees: 100,
            min_training_samples: 50,
            bootstrap_fraction: 0.7,
        }
    }

    #[allow(dead_code)]
    pub fn is_trained(&self) -> bool {
        !self.trees.is_empty()
    }

    /// Train the ensemble from labeled feature vectors.
    pub fn train(&mut self, samples: &[(Array1<f64>, String)]) -> Result<(), String> {
        if samples.len() < self.min_training_samples {
            return Err(format!(
                "Need at least {} samples, got {}",
                self.min_training_samples,
                samples.len()
            ));
        }

        // Re-build label encoder from scratch each training round
        self.label_encoder = LabelEncoder::new();

        // Encode labels
        let mut encoded_labels = Vec::with_capacity(samples.len());
        for (_, label) in samples {
            encoded_labels.push(self.label_encoder.encode(label));
        }

        if self.label_encoder.num_classes() < 2 {
            return Err("Need at least 2 classes to train".to_string());
        }

        // Build feature matrix
        let n_samples = samples.len();
        let mut features = Array2::<f64>::zeros((n_samples, FEATURE_DIM));
        let mut targets = Array1::<usize>::zeros(n_samples);

        for (i, (feat, _)) in samples.iter().enumerate() {
            features.row_mut(i).assign(feat);
            targets[i] = encoded_labels[i];
        }

        // Train N trees on bootstrap samples
        let mut rng = thread_rng();
        let indices: Vec<usize> = (0..n_samples).collect();
        let sample_size = ((n_samples as f64) * self.bootstrap_fraction) as usize;

        let mut new_trees = Vec::with_capacity(self.n_trees);

        for _ in 0..self.n_trees {
            // Bootstrap sample
            let boot_indices: Vec<usize> = (0..sample_size)
                .map(|_| *indices.choose(&mut rng).unwrap())
                .collect();

            let boot_features = Array2::from_shape_fn((sample_size, FEATURE_DIM), |(r, c)| {
                features[[boot_indices[r], c]]
            });
            let boot_targets = Array1::from_shape_fn(sample_size, |r| targets[boot_indices[r]]);

            let dataset = DatasetBase::new(boot_features, boot_targets);

            match DecisionTree::params()
                .max_depth(Some(10))
                .min_weight_split(4.0)
                .min_weight_leaf(2.0)
                .fit(&dataset)
            {
                Ok(tree) => new_trees.push(tree),
                Err(e) => {
                    log::warn!("Failed to train tree: {:?}", e);
                }
            }
        }

        if new_trees.is_empty() {
            return Err("All trees failed to train".to_string());
        }

        self.trees = new_trees;
        Ok(())
    }

    /// Predict class and confidence for a feature vector.
    /// Returns (label, confidence) where confidence is the fraction of trees agreeing.
    pub fn predict(&self, features: &Array1<f64>) -> Option<(String, f64)> {
        if self.trees.is_empty() {
            return None;
        }

        // Each tree votes on the class
        let mut votes: HashMap<usize, usize> = HashMap::new();
        let input = features.clone().insert_axis(Axis(0));

        for tree in &self.trees {
            let pred = tree.predict(&input);
            if let Some(&class) = pred.first() {
                *votes.entry(class).or_insert(0) += 1;
            }
        }

        // Find majority vote
        let total = votes.values().sum::<usize>() as f64;
        votes
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .and_then(|(class, count)| {
                let confidence = count as f64 / total;
                self.label_encoder
                    .decode(class)
                    .map(|label| (label.to_string(), confidence))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- LabelEncoder tests --

    #[test]
    fn label_encoder_new_empty() {
        let enc = LabelEncoder::new();
        assert_eq!(enc.num_classes(), 0);
    }

    #[test]
    fn label_encoder_encode_new_label() {
        let mut enc = LabelEncoder::new();
        assert_eq!(enc.encode("OpenAI"), 0);
        assert_eq!(enc.encode("Anthropic"), 1);
        assert_eq!(enc.num_classes(), 2);
    }

    #[test]
    fn label_encoder_encode_existing_label() {
        let mut enc = LabelEncoder::new();
        enc.encode("OpenAI");
        assert_eq!(enc.encode("OpenAI"), 0); // same index
        assert_eq!(enc.num_classes(), 1);
    }

    #[test]
    fn label_encoder_decode() {
        let mut enc = LabelEncoder::new();
        enc.encode("OpenAI");
        enc.encode("Anthropic");
        assert_eq!(enc.decode(0), Some("OpenAI"));
        assert_eq!(enc.decode(1), Some("Anthropic"));
    }

    #[test]
    fn label_encoder_decode_invalid() {
        let enc = LabelEncoder::new();
        assert_eq!(enc.decode(0), None);
        assert_eq!(enc.decode(999), None);
    }

    // -- TrainedClassifier tests --

    #[test]
    fn untrained_returns_none() {
        let c = TrainedClassifier::new();
        assert!(!c.is_trained());
        let features = Array1::zeros(FEATURE_DIM);
        assert!(c.predict(&features).is_none());
    }

    #[test]
    fn too_few_samples_returns_err() {
        let mut c = TrainedClassifier::new();
        let samples: Vec<(Array1<f64>, String)> = (0..10)
            .map(|_| (Array1::zeros(FEATURE_DIM), "ClassA".to_string()))
            .collect();
        let result = c.train(&samples);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least"));
    }

    #[test]
    fn single_class_returns_err() {
        let mut c = TrainedClassifier::new();
        let samples: Vec<(Array1<f64>, String)> = (0..60)
            .map(|_| (Array1::zeros(FEATURE_DIM), "OnlyOne".to_string()))
            .collect();
        let result = c.train(&samples);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("2 classes"));
    }

    #[test]
    fn train_and_predict_two_classes() {
        let mut c = TrainedClassifier::new();
        let mut samples = Vec::new();

        // ClassA: features = 1.0 for first 10 dims
        for _ in 0..50 {
            let mut f = Array1::zeros(FEATURE_DIM);
            for i in 0..10 {
                f[i] = 1.0;
            }
            samples.push((f, "ClassA".to_string()));
        }

        // ClassB: features = 1.0 for dims 100-110
        for _ in 0..50 {
            let mut f = Array1::zeros(FEATURE_DIM);
            for i in 100..110 {
                f[i] = 1.0;
            }
            samples.push((f, "ClassB".to_string()));
        }

        c.train(&samples).unwrap();
        assert!(c.is_trained());

        // Predict a ClassA-like vector
        let mut test_a = Array1::zeros(FEATURE_DIM);
        for i in 0..10 {
            test_a[i] = 1.0;
        }
        let (label, confidence) = c.predict(&test_a).unwrap();
        assert_eq!(label, "ClassA");
        assert!(confidence > 0.5);

        // Predict a ClassB-like vector
        let mut test_b = Array1::zeros(FEATURE_DIM);
        for i in 100..110 {
            test_b[i] = 1.0;
        }
        let (label_b, _) = c.predict(&test_b).unwrap();
        assert_eq!(label_b, "ClassB");
    }

    #[test]
    fn confidence_is_valid_range() {
        let mut c = TrainedClassifier::new();
        let mut samples = Vec::new();
        for _ in 0..30 {
            let mut f = Array1::zeros(FEATURE_DIM);
            f[0] = 1.0;
            samples.push((f, "A".to_string()));
        }
        for _ in 0..30 {
            let mut f = Array1::zeros(FEATURE_DIM);
            f[1] = 1.0;
            samples.push((f, "B".to_string()));
        }
        c.train(&samples).unwrap();

        let f = Array1::zeros(FEATURE_DIM);
        let (_, conf) = c.predict(&f).unwrap();
        assert!(conf >= 0.0 && conf <= 1.0);
    }
}
