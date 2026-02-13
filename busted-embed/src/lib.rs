//! Text embedding for AI agent identity fingerprinting.
//!
//! Provides a simple API for generating text embeddings using
//! `sentence-transformers/all-MiniLM-L6-v2` (384-dimensional output).
//!
//! # Feature Flags
//!
//! - `candle` (default): Uses the candle ML framework (pure Rust, no ONNX).
//!
//! Without the `candle` feature, the crate compiles but `Embedder::new()`
//! returns an error.
//!
//! # Example
//!
//! ```no_run
//! use busted_embed::Embedder;
//!
//! let mut embedder = Embedder::new().expect("Failed to load model");
//! let embedding = embedder.embed("You are a helpful assistant").unwrap();
//! assert_eq!(embedding.len(), 384);
//! ```

/// Embedding dimension for all-MiniLM-L6-v2.
pub const EMBEDDING_DIM: usize = 384;

/// Model identifier on HuggingFace Hub.
pub const MODEL_ID: &str = "sentence-transformers/all-MiniLM-L6-v2";

/// Revision with safetensors weights.
pub const MODEL_REVISION: &str = "refs/pr/21";

#[cfg(feature = "candle")]
mod candle_backend;

/// Text embedder backed by all-MiniLM-L6-v2.
///
/// Downloads the model from HuggingFace Hub on first construction
/// (cached in `~/.cache/huggingface/`). Subsequent calls reuse the
/// cached model files.
pub struct Embedder {
    #[cfg(feature = "candle")]
    inner: candle_backend::CandleEmbedder,
}

impl Embedder {
    /// Create a new embedder, loading the model.
    ///
    /// This downloads model files on first use (~23MB) and loads them
    /// into memory. Subsequent constructions reuse the cached files.
    pub fn new() -> anyhow::Result<Self> {
        #[cfg(feature = "candle")]
        {
            let inner = candle_backend::CandleEmbedder::new()?;
            Ok(Self { inner })
        }
        #[cfg(not(feature = "candle"))]
        {
            anyhow::bail!("No embedding backend available. Enable the `candle` feature.")
        }
    }

    /// Embed a single text, returning a normalized 384-dim vector.
    pub fn embed(&mut self, text: &str) -> anyhow::Result<Vec<f32>> {
        #[cfg(feature = "candle")]
        {
            self.inner.embed(text)
        }
        #[cfg(not(feature = "candle"))]
        {
            let _ = text;
            anyhow::bail!("No embedding backend available.")
        }
    }

    /// Embed multiple texts, returning normalized 384-dim vectors.
    pub fn embed_batch(&mut self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
        #[cfg(feature = "candle")]
        {
            self.inner.embed_batch(texts)
        }
        #[cfg(not(feature = "candle"))]
        {
            let _ = texts;
            anyhow::bail!("No embedding backend available.")
        }
    }

    /// Embedding dimension (384 for all-MiniLM-L6-v2).
    pub fn dim(&self) -> usize {
        EMBEDDING_DIM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(EMBEDDING_DIM, 384);
        assert!(!MODEL_ID.is_empty());
    }

    #[test]
    #[cfg(feature = "candle")]
    fn embed_produces_384_dim_vector() {
        let mut embedder = Embedder::new().expect("Failed to load model");
        let embedding = embedder.embed("You are a helpful assistant").unwrap();
        assert_eq!(embedding.len(), EMBEDDING_DIM);

        // Should be L2-normalized (norm ≈ 1.0)
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "norm = {norm}, expected ~1.0");
    }

    #[test]
    #[cfg(feature = "candle")]
    fn similar_texts_have_high_cosine_similarity() {
        let mut embedder = Embedder::new().expect("Failed to load model");
        let a = embedder.embed("You are a helpful AI assistant").unwrap();
        let b = embedder.embed("You are a useful AI helper").unwrap();
        let c = embedder
            .embed("The quick brown fox jumps over the lazy dog")
            .unwrap();

        let sim_ab: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let sim_ac: f32 = a.iter().zip(c.iter()).map(|(x, y)| x * y).sum();

        // Similar prompts should have higher similarity than unrelated ones
        assert!(
            sim_ab > sim_ac,
            "similar texts sim={sim_ab} should be > unrelated sim={sim_ac}"
        );
        assert!(sim_ab > 0.7, "similar texts sim={sim_ab} should be > 0.7");
    }

    #[test]
    #[cfg(feature = "candle")]
    fn embed_batch_matches_individual() {
        let mut embedder = Embedder::new().expect("Failed to load model");
        let texts = &["Hello world", "Goodbye world"];

        let batch = embedder.embed_batch(texts).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].len(), EMBEDDING_DIM);
        assert_eq!(batch[1].len(), EMBEDDING_DIM);

        let single_0 = embedder.embed("Hello world").unwrap();
        let _single_1 = embedder.embed("Goodbye world").unwrap();

        // Batch and individual results should be very close (not exact due to padding)
        let diff_0: f32 = batch[0]
            .iter()
            .zip(single_0.iter())
            .map(|(a, b)| (a - b).abs())
            .sum();
        assert!(diff_0 < 0.1, "batch vs single diff = {diff_0}");
    }
}
