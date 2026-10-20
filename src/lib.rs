//! Local CPU detection and reversible placeholders with a plaintext vault.
use anyhow::{Context, Result, bail, ensure};
use ort::{
    environment::Environment,
    session::Session,
    value::{Tensor, TensorElementType, ValueType},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::Instant};
use tokenizers::Tokenizer;
pub mod detect;
pub mod installation;
pub mod privacy;
pub mod redact;

#[derive(Debug, Deserialize)]
struct Configuration {
    vocab_size: usize,
    max_position_embeddings: usize,
    type_vocab_size: usize,
    id2label: BTreeMap<String, String>,
}

/// Validated only by Detector::infer; fixtures can deserialize without trusting them.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelInput {
    pub key: String,
    pub input_ids: Vec<i64>,
    pub attention_mask: Vec<i64>,
    pub token_type_ids: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct EncodedText {
    pub input: ModelInput,
    /// UTF-8 byte ranges into the original text, never JS UTF-16 indices.
    pub offsets: Vec<(usize, usize)>,
    pub special_tokens_mask: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct Prediction {
    pub shape: Vec<usize>,
    pub logits: Vec<f32>,
    pub label_ids: Vec<usize>,
    pub confidence: Vec<f32>,
    pub latency_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct LoadTimings {
    pub runtime_init_ms: f64,
    pub tokenizer_load_ms: f64,
    pub session_load_ms: f64,
    pub total_ms: f64,
}

pub struct Detector {
    session: Session,
    tokenizer: Tokenizer,
    config: Configuration,
    pub labels: Vec<String>,
    pub load_timings: LoadTimings,
}

impl Detector {
    /// Explicit runtime path, CPU provider only; no network access or backend retry.
    pub fn load(artifacts: &Path, runtime: &Path, threads: Option<usize>) -> Result<Self> {
        let start = Instant::now();
        let runtime = runtime
            .canonicalize()
            .context("resolve ONNX Runtime library")?;
        let config: Configuration =
            serde_json::from_slice(&fs::read(artifacts.join("config.json"))?)?;
        ensure!(
            config.max_position_embeddings == 512,
            "expected a 512-token model"
        );
        ensure!(config.id2label.len() == 35, "expected 35 labels");
        let labels = (0..config.id2label.len())
            .map(|i| {
                config
                    .id2label
                    .get(&i.to_string())
                    .cloned()
                    .context("missing label id")
            })
            .collect::<Result<Vec<_>>>()?;
        let model_path = artifacts.join("onnx/model_q4.onnx");
        let runtime_start = Instant::now();
        let environment: Environment = ort::init_from(&runtime)?.with_name("veil").build()?;
        let runtime_init_ms = milliseconds(runtime_start);
        let tokenizer_start = Instant::now();
        let mut tokenizer = Tokenizer::from_file(artifacts.join("tokenizer.json"))
            .map_err(|e| anyhow::anyhow!("load tokenizer: {e}"))?;
        // Truncation/padding must be explicit at the detector boundary, not hidden in JSON.
        tokenizer
            .with_truncation(None)
            .map_err(|e| anyhow::anyhow!("disable truncation: {e}"))?;
        tokenizer.with_padding(None);
        let tokenizer_load_ms = milliseconds(tokenizer_start);
        let session_start = Instant::now();
        let mut builder = Session::builder(&environment)?;
        if let Some(n) = threads {
            ensure!(n > 0, "threads must be positive");
            builder = builder
                .with_intra_threads(n)
                .map_err(|e| anyhow::anyhow!("configure inference threads: {e}"))?;
        }
        let session = builder.commit_from_file(&model_path)?;
        ensure!(
            session.inputs().len() == 3 && session.outputs().len() == 1,
            "unexpected model tensor count"
        );
        for name in ["input_ids", "attention_mask", "token_type_ids"] {
            let input = session
                .inputs()
                .iter()
                .find(|i| i.name() == name)
                .context("missing named input")?;
            match input.dtype() {
                ValueType::Tensor {
                    ty: TensorElementType::Int64,
                    shape,
                    ..
                } => ensure!(
                    shape.len() == 2 && shape[0] == -1 && shape[1] == -1,
                    "unexpected input shape for {name}: {shape:?}"
                ),
                other => bail!("unexpected input dtype for {name}: {other:?}"),
            }
        }
        let output = &session.outputs()[0];
        ensure!(output.name() == "logits", "missing logits output");
        match output.dtype() {
            ValueType::Tensor {
                ty: TensorElementType::Float32,
                shape,
                ..
            } => ensure!(
                shape.len() == 3 && shape[2] == 35,
                "unexpected logits shape"
            ),
            _ => bail!("expected float32 logits"),
        }
        let session_load_ms = milliseconds(session_start);
        Ok(Self {
            session,
            tokenizer,
            config,
            labels,
            load_timings: LoadTimings {
                runtime_init_ms,
                tokenizer_load_ms,
                session_load_ms,
                total_ms: milliseconds(start),
            },
        })
    }

    pub fn encode(&self, key: String, text: &str) -> Result<EncodedText> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("tokenization failed: {e}"))?;
        ensure!(
            encoding.len() <= 512,
            "text exceeds the single-window model context (no truncation); use Pipeline::analyze for windowed detection"
        );
        let offsets = encoding.get_offsets().to_vec();
        for &(start, end) in &offsets {
            ensure!(
                start <= end
                    && end <= text.len()
                    && text.is_char_boundary(start)
                    && text.is_char_boundary(end),
                "tokenizer returned an invalid UTF-8 range"
            );
        }
        let input = ModelInput {
            key,
            input_ids: encoding.get_ids().iter().map(|&v| i64::from(v)).collect(),
            attention_mask: encoding
                .get_attention_mask()
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
            token_type_ids: encoding
                .get_type_ids()
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        };
        self.validate(&input)?;
        Ok(EncodedText {
            input,
            offsets,
            special_tokens_mask: encoding.get_special_tokens_mask().to_vec(),
        })
    }

    fn validate(&self, input: &ModelInput) -> Result<()> {
        let n = input.input_ids.len();
        ensure!(
            (2..=self.config.max_position_embeddings).contains(&n),
            "input length must be 2..=512"
        );
        ensure!(
            input.attention_mask.len() == n && input.token_type_ids.len() == n,
            "input tensor lengths differ"
        );
        ensure!(
            input
                .input_ids
                .iter()
                .all(|&v| v >= 0 && v < self.config.vocab_size as i64),
            "input token id out of range"
        );
        ensure!(
            input.attention_mask.iter().all(|&v| v == 0 || v == 1),
            "invalid attention mask"
        );
        ensure!(
            input
                .token_type_ids
                .iter()
                .all(|&v| v >= 0 && v < self.config.type_vocab_size as i64),
            "invalid token type id"
        );
        Ok(())
    }

    pub fn infer(&mut self, input: &ModelInput) -> Result<Prediction> {
        self.validate(input)?;
        let start = Instant::now();
        let n = input.input_ids.len();
        let outputs = self.session.run(ort::inputs![
            "input_ids" => Tensor::from_array(([1, n], input.input_ids.clone()))?,
            "attention_mask" => Tensor::from_array(([1, n], input.attention_mask.clone()))?,
            "token_type_ids" => Tensor::from_array(([1, n], input.token_type_ids.clone()))?
        ])?;
        let (shape, data) = outputs["logits"].try_extract_tensor::<f32>()?;
        ensure!(
            shape[..] == [1, n as i64, self.labels.len() as i64],
            "invalid output shape"
        );
        ensure!(data.iter().all(|v| v.is_finite()), "nonfinite model output");
        let logits = data.to_vec();
        let latency_ms = milliseconds(start);
        let (label_ids, confidence) = decode(&logits, self.labels.len())?;
        Ok(Prediction {
            shape: vec![1, n, self.labels.len()],
            logits,
            label_ids,
            confidence,
            latency_ms,
        })
    }
}

/// Stable softmax, first-index argmax; no confidence threshold or privacy policy here.
pub fn decode(logits: &[f32], classes: usize) -> Result<(Vec<usize>, Vec<f32>)> {
    ensure!(
        classes > 0 && logits.len().is_multiple_of(classes),
        "invalid decoder shape"
    );
    ensure!(logits.iter().all(|v| v.is_finite()), "nonfinite logits");
    let mut ids = Vec::with_capacity(logits.len() / classes);
    let mut scores = Vec::with_capacity(ids.capacity());
    for row in logits.chunks_exact(classes) {
        let mut best = 0;
        for j in 1..classes {
            if row[j] > row[best] {
                best = j;
            }
        }
        let denominator: f32 = row.iter().map(|v| (v - row[best]).exp()).sum();
        ids.push(best);
        scores.push(1.0 / denominator);
    }
    Ok((ids, scores))
}

pub fn hash_file(path: &Path) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(
            fs::read(path).with_context(|| format!("read artifact {}", path.display()))?
        )
    ))
}
pub fn milliseconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_maximum_wins() {
        assert_eq!(decode(&[1., 1., 0., 0., 2., 2.], 3).unwrap().0, vec![0, 1]);
    }
    #[test]
    fn extreme_finite_logits_are_stable() {
        let (_, p) = decode(&[10000., -10000., 10000.], 3).unwrap();
        assert_eq!(p, vec![0.5]);
    }
    #[test]
    fn rejects_invalid_decoder_inputs() {
        assert!(decode(&[f32::NAN], 1).is_err());
        assert!(decode(&[1.], 0).is_err());
        assert!(decode(&[1., 2., 3.], 2).is_err());
    }
}
