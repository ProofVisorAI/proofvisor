//! Local scorer: an ONNX sequence classifier run in-process with tract.
//!
//! The model and tokenizer files are read once; the SHA-256 of those
//! exact bytes is checked against the pin, and the model is built from
//! the same buffer, so the file cannot change between the check and the
//! load. A mismatch refuses to load (the harness then refuses to start).
//! Unlike the loop breaker's embedder, an inference error is reported
//! as an error: there is no fallback scorer, because a judge that
//! silently answers with something else would defeat the pin.
//!
//! Input: the request rendered by [`crate::render::render_request`].
//! Output: one logit per label, in the configured `output_labels` order;
//! the adapter applies softmax.

use crate::adapter::{AdapterKind, BoxFuture, JudgeAdapter, JudgeError};
use crate::model::{sha256_hex, JudgeRequest, ModelPin, RawScores};
use crate::predicate::PredicateDef;
use crate::render::render_request;
use std::path::PathBuf;
use std::sync::Arc;
use tract_onnx::prelude::*;

type Runnable = Arc<TypedRunnableModel>;

/// Upper bound on model file size read into memory (2 GiB).
pub const MAX_MODEL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Upper bound on tokenizer file size (64 MiB).
pub const MAX_TOKENIZER_BYTES: u64 = 64 * 1024 * 1024;

/// Local scorer settings.
#[derive(Debug, Clone)]
pub struct LocalOnnxConfig {
    /// Path of the `.onnx` file.
    pub model_path: PathBuf,
    /// Path of the Hugging Face `tokenizer.json`.
    pub tokenizer_path: PathBuf,
    /// Expected pin; `weights_sha256` is the SHA-256 of the model file.
    pub pin: ModelPin,
    /// Expected SHA-256 of the tokenizer file.
    pub tokenizer_sha256: String,
    /// Label of each output logit, in output order.
    pub output_labels: Vec<String>,
    /// Token limit; a longer input is not scored, it fails as malformed.
    pub max_input_tokens: usize,
}

/// The local ONNX judge.
pub struct LocalOnnxJudge {
    model: Runnable,
    tokenizer: Arc<tokenizers::Tokenizer>,
    pin: ModelPin,
    input_order: Vec<usize>,
    output_labels: Vec<String>,
    max_input_tokens: usize,
}

impl LocalOnnxJudge {
    /// Read, verify, and load the files named in `config`.
    pub fn load(config: &LocalOnnxConfig) -> Result<Self, String> {
        let model_bytes = read_capped(&config.model_path, MAX_MODEL_BYTES)?;
        let tokenizer_bytes = read_capped(&config.tokenizer_path, MAX_TOKENIZER_BYTES)?;
        Self::from_bytes(config, &model_bytes, &tokenizer_bytes)
    }

    /// Verify and load from bytes already in memory.
    pub fn from_bytes(
        config: &LocalOnnxConfig,
        model_bytes: &[u8],
        tokenizer_bytes: &[u8],
    ) -> Result<Self, String> {
        config.pin.validate()?;
        if config.output_labels.len() < 2 {
            return Err("local judge needs at least two output labels".to_owned());
        }
        if config.max_input_tokens == 0 {
            return Err("local judge max_input_tokens must be at least 1".to_owned());
        }
        let model_hash = sha256_hex(model_bytes);
        if model_hash != config.pin.weights_sha256 {
            return Err(format!(
                "judge model hash mismatch for {}: file {} has sha256 {model_hash}; refusing to load",
                config.pin,
                config.model_path.display()
            ));
        }
        let tokenizer_hash = sha256_hex(tokenizer_bytes);
        if tokenizer_hash != config.tokenizer_sha256 {
            return Err(format!(
                "judge tokenizer hash mismatch: file {} has sha256 {tokenizer_hash}, expected {}; refusing to load",
                config.tokenizer_path.display(),
                config.tokenizer_sha256
            ));
        }
        let model = tract_onnx::onnx()
            .model_for_read(&mut &model_bytes[..])
            .map_err(|error| format!("judge model does not parse as ONNX: {error}"))?;
        let input_outlets = model.input_outlets().map_err(|error| error.to_string())?.to_vec();
        let input_names: Vec<String> = input_outlets
            .iter()
            .map(|outlet| model.node(outlet.node).name.clone())
            .collect();
        let input_order = resolve_input_order(&input_names)?;
        let model = model
            .into_optimized()
            .map_err(|error| format!("judge model does not optimize: {error}"))?
            .into_runnable()
            .map_err(|error| format!("judge model does not load: {error}"))?;
        // No truncation: a request longer than the model reads is refused
        // (see `infer`), never scored on its first part.
        let mut tokenizer = tokenizers::Tokenizer::from_bytes(tokenizer_bytes)
            .map_err(|error| format!("judge tokenizer does not parse: {error}"))?;
        tokenizer
            .with_truncation(None)
            .map_err(|error| format!("judge tokenizer truncation: {error}"))?;
        Ok(Self {
            model,
            tokenizer: Arc::new(tokenizer),
            pin: config.pin.clone(),
            input_order,
            output_labels: config.output_labels.clone(),
            max_input_tokens: config.max_input_tokens,
        })
    }

    /// Run the classifier on rendered text and return label probabilities.
    pub fn classify(&self, text: &str) -> Result<Vec<(String, f64)>, JudgeError> {
        infer(
            &self.model,
            &self.tokenizer,
            &self.input_order,
            &self.output_labels,
            self.max_input_tokens,
            text,
        )
    }
}

impl JudgeAdapter for LocalOnnxJudge {
    fn id(&self) -> &ModelPin {
        &self.pin
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Local
    }

    fn score<'a>(
        &'a self,
        request: &'a JudgeRequest,
        predicate: &'a PredicateDef,
    ) -> BoxFuture<'a, Result<RawScores, JudgeError>> {
        let too_long = crate::render::request_too_long(request);
        let text = render_request(request);
        let model = Arc::clone(&self.model);
        let tokenizer = Arc::clone(&self.tokenizer);
        let order = self.input_order.clone();
        let labels = self.output_labels.clone();
        let pin = self.pin.clone();
        let max_tokens = self.max_input_tokens;
        let mismatch =
            labels.len() != predicate.labels.len() || labels.iter().any(|l| !predicate.has_label(l));
        Box::pin(async move {
            if let Some(error) = too_long {
                return Err(error);
            }
            if mismatch {
                return Err(JudgeError::Malformed(format!(
                    "local model labels {labels:?} do not match predicate {}",
                    predicate.id
                )));
            }
            // CPU-bound: keep it off the async workers.
            let probs = tokio::task::spawn_blocking(move || {
                infer(&model, &tokenizer, &order, &labels, max_tokens, &text)
            })
            .await
            .map_err(|_| JudgeError::Unavailable("local judge inference task failed".to_owned()))??;
            Ok(RawScores { probs, model: pin })
        })
    }
}

fn infer(
    model: &Runnable,
    tokenizer: &tokenizers::Tokenizer,
    input_order: &[usize],
    labels: &[String],
    max_tokens: usize,
    text: &str,
) -> Result<Vec<(String, f64)>, JudgeError> {
    let encoding = tokenizer
        .encode(text, true)
        .map_err(|error| JudgeError::Unavailable(format!("tokenization failed: {error}")))?;
    // A request longer than the model reads would be scored on its first
    // part only, which the caller can shape: it is not judged at all.
    if encoding.get_ids().len() > max_tokens {
        return Err(JudgeError::TooLong(format!(
            "the request is {} tokens, longer than the model reads ({max_tokens}); the call cannot \
             be judged in full",
            encoding.get_ids().len()
        )));
    }
    let ids: Vec<i64> = encoding.get_ids().iter().map(|id| i64::from(*id)).collect();
    if ids.is_empty() {
        return Err(JudgeError::Unavailable("tokenizer produced no tokens".to_owned()));
    }
    let len = ids.len();
    let mask: Vec<i64> = encoding
        .get_attention_mask()
        .iter()
        .map(|v| i64::from(*v))
        .collect();
    let types: Vec<i64> = encoding.get_type_ids().iter().map(|v| i64::from(*v)).collect();
    if mask.len() != len || types.len() != len {
        return Err(JudgeError::Unavailable(
            "tokenizer returned inconsistent lengths".to_owned(),
        ));
    }
    let tensor = |values: Vec<i64>| -> Result<TValue, JudgeError> {
        tract_ndarray::Array2::from_shape_vec((1, len), values)
            .map(|array| Tensor::from(array).into())
            .map_err(|error| JudgeError::Unavailable(error.to_string()))
    };
    let semantic = [tensor(ids)?, tensor(mask)?, tensor(types)?];
    let inputs = input_order
        .iter()
        .map(|slot| {
            semantic
                .get(*slot)
                .cloned()
                .ok_or_else(|| JudgeError::Unavailable(format!("input slot {slot} out of range")))
        })
        .collect::<Result<TVec<TValue>, JudgeError>>()?;
    let outputs = model
        .run(inputs)
        .map_err(|error| JudgeError::Unavailable(format!("inference failed: {error}")))?;
    let output = outputs
        .first()
        .ok_or_else(|| JudgeError::Malformed("model returned no output".to_owned()))?;
    let view = output
        .to_plain_array_view::<f32>()
        .map_err(|error| JudgeError::Malformed(format!("output is not f32: {error}")))?;
    let logits: Vec<f64> = match view.shape() {
        [n] | [1, n] if *n == labels.len() => view.iter().map(|v| f64::from(*v)).collect(),
        shape => {
            return Err(JudgeError::Malformed(format!(
                "output shape {shape:?} does not hold {} logits",
                labels.len()
            )))
        }
    };
    let probs = softmax(&logits)?;
    Ok(labels.iter().cloned().zip(probs).collect())
}

/// Numerically stable softmax; refuses non-finite logits.
pub fn softmax(logits: &[f64]) -> Result<Vec<f64>, JudgeError> {
    if logits.iter().any(|v| !v.is_finite()) {
        return Err(JudgeError::Malformed(
            "model returned non-finite logits".to_owned(),
        ));
    }
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let exps: Vec<f64> = logits.iter().map(|v| (v - max).exp()).collect();
    let sum: f64 = exps.iter().sum();
    if !(sum.is_finite() && sum > 0.0) {
        return Err(JudgeError::Malformed("softmax did not normalize".to_owned()));
    }
    Ok(exps.into_iter().map(|v| v / sum).collect())
}

/// Bind graph inputs to `input_ids` / `attention_mask` / `token_type_ids`
/// by name when every name is recognizable, by position when none is,
/// and refuse a partially recognizable set (an ambiguous binding would
/// silently swap tensors).
fn resolve_input_order(names: &[String]) -> Result<Vec<usize>, String> {
    if names.is_empty() || names.len() > 3 {
        return Err(format!(
            "judge model must have 1 to 3 inputs, found {}",
            names.len()
        ));
    }
    let classified: Vec<Option<usize>> = names.iter().map(|name| classify_input(name)).collect();
    if classified.iter().all(Option::is_none) {
        return Ok((0..names.len()).collect());
    }
    let order: Vec<usize> = classified.into_iter().collect::<Option<Vec<usize>>>().ok_or_else(|| {
        format!("judge model input names {names:?} are only partially recognizable; refusing an ambiguous binding")
    })?;
    let mut sorted = order.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != order.len() || !order.contains(&0) {
        return Err(format!(
            "judge model input names {names:?} must include input_ids once and each other input at most once"
        ));
    }
    Ok(order)
}

fn classify_input(name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("input_id") {
        Some(0)
    } else if lower.contains("attention") || lower.contains("mask") {
        Some(1)
    } else if lower.contains("token_type") || lower.contains("segment") {
        Some(2)
    } else {
        None
    }
}

fn read_capped(path: &std::path::Path, cap: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > cap {
        return Err(format!("{} is larger than {cap} bytes", path.display()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn softmax_is_stable_and_refuses_nan() {
        let probs = softmax(&[1000.0, 1000.0]).unwrap();
        assert!((probs[0] - 0.5).abs() < 1e-12);
        assert!(softmax(&[f64::NAN, 0.0]).is_err());
        assert!(softmax(&[f64::INFINITY, 0.0]).is_err());
    }

    #[test]
    fn inputs_bind_by_name_or_position() {
        let names = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            resolve_input_order(&names(&["attention_mask", "input_ids"])).unwrap(),
            vec![1, 0]
        );
        assert_eq!(resolve_input_order(&names(&["a", "b"])).unwrap(), vec![0, 1]);
        assert!(resolve_input_order(&names(&["input_ids", "b"])).is_err());
        assert!(resolve_input_order(&names(&["attention_mask"])).is_err());
        assert!(resolve_input_order(&names(&["input_ids", "input_ids2"])).is_err());
        assert!(resolve_input_order(&[]).is_err());
    }
}
