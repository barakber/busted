//! Candle-based embedding backend.
//!
//! Loads `sentence-transformers/all-MiniLM-L6-v2` via HuggingFace Hub,
//! tokenizes input, runs through BertModel, applies mean pooling + L2 norm.

use anyhow::{Context, Result};
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use hf_hub::{api::sync::Api, Repo, RepoType};
use tokenizers::Tokenizer;

use crate::{EMBEDDING_DIM, MODEL_ID, MODEL_REVISION};

pub struct CandleEmbedder {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

impl CandleEmbedder {
    pub fn new() -> Result<Self> {
        log::info!("Loading embedding model: {MODEL_ID}");

        let repo = Repo::with_revision(
            MODEL_ID.to_string(),
            RepoType::Model,
            MODEL_REVISION.to_string(),
        );
        let api = Api::new().context("Failed to initialize HuggingFace Hub API")?;
        let api_repo = api.repo(repo);

        let config_path = api_repo
            .get("config.json")
            .context("Failed to download config.json")?;
        let tokenizer_path = api_repo
            .get("tokenizer.json")
            .context("Failed to download tokenizer.json")?;
        let weights_path = api_repo
            .get("model.safetensors")
            .context("Failed to download model.safetensors")?;

        let config: Config = {
            let data =
                std::fs::read_to_string(&config_path).context("Failed to read config.json")?;
            serde_json::from_str(&data).context("Failed to parse config.json")?
        };

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {e}"))?;

        let device = Device::Cpu;

        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DTYPE, &device)
                .context("Failed to load model weights")?
        };

        let model = BertModel::load(vb, &config).context("Failed to build BertModel")?;

        log::info!("Embedding model loaded ({EMBEDDING_DIM}-dim)");

        Ok(Self {
            model,
            tokenizer,
            device,
        })
    }

    pub fn embed(&mut self, text: &str) -> Result<Vec<f32>> {
        let mut batch = self.embed_batch(&[text])?;
        Ok(batch.remove(0))
    }

    pub fn embed_batch(&mut self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        // Tokenize with padding
        let encodings = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {e}"))?;

        let max_len = encodings
            .iter()
            .map(|e| e.get_ids().len())
            .max()
            .unwrap_or(0);

        let mut all_input_ids = Vec::new();
        let mut all_type_ids = Vec::new();
        let mut all_attention_mask = Vec::new();

        for encoding in &encodings {
            let ids = encoding.get_ids();
            let type_ids = encoding.get_type_ids();
            let attention = encoding.get_attention_mask();

            // Pad to max_len
            let mut padded_ids = ids.to_vec();
            let mut padded_types = type_ids.to_vec();
            let mut padded_mask = attention.to_vec();

            padded_ids.resize(max_len, 0);
            padded_types.resize(max_len, 0);
            padded_mask.resize(max_len, 0);

            all_input_ids.extend(padded_ids);
            all_type_ids.extend(padded_types);
            all_attention_mask.extend(padded_mask);
        }

        let batch_size = texts.len();
        let input_ids = Tensor::from_vec(all_input_ids, (batch_size, max_len), &self.device)?;
        let type_ids = Tensor::from_vec(all_type_ids, (batch_size, max_len), &self.device)?;
        let attention_mask_u32 =
            Tensor::from_vec(all_attention_mask, (batch_size, max_len), &self.device)?;

        let input_ids = input_ids.to_dtype(DType::U32)?;
        let type_ids = type_ids.to_dtype(DType::U32)?;
        let attention_mask = attention_mask_u32.to_dtype(DTYPE)?;

        // Forward pass
        let output = self
            .model
            .forward(&input_ids, &type_ids, Some(&attention_mask))?;

        // Mean pooling: sum(output * mask) / sum(mask)
        let mask_expanded = attention_mask.unsqueeze(2)?.broadcast_as(output.shape())?;
        let masked = (output * mask_expanded)?;

        let summed = masked.sum(1)?;
        let mask_sum = attention_mask.sum(1)?.unsqueeze(1)?;
        let mask_sum = mask_sum.broadcast_as(summed.shape())?;
        let pooled = (summed / mask_sum)?;

        // L2 normalize
        let norms = pooled
            .sqr()?
            .sum_keepdim(1)?
            .sqrt()?
            .broadcast_as(pooled.shape())?;
        let normalized = (pooled / norms)?;

        // Extract as Vec<Vec<f32>>
        let normalized = normalized.to_dtype(DType::F32)?;
        let flat: Vec<f32> = normalized.flatten_all()?.to_vec1()?;
        let dim = EMBEDDING_DIM;

        let result: Vec<Vec<f32>> = (0..batch_size)
            .map(|i| flat[i * dim..(i + 1) * dim].to_vec())
            .collect();

        Ok(result)
    }
}
