//! The judge interface, its errors, and output validation.

use crate::model::{LabelProb, ModelPin, RawScores, Verdict, PPM_ONE};
use crate::predicate::PredicateDef;
use crate::JudgeRequest;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// A boxed, sendable future (keeps [`JudgeAdapter`] object-safe).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How far the probabilities may sum away from 1 before the output
/// counts as malformed (softmax rounding stays far below this).
pub const SUM_TOLERANCE: f64 = 1e-3;

/// Which kind of backend scores the predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    /// Model runs inside the harness process.
    Local,
    /// Model runs at a remote service (a second egress path).
    Cloud,
    /// Deterministic test double.
    Mock,
}

impl AdapterKind {
    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cloud => "cloud",
            Self::Mock => "mock",
        }
    }
}

/// A judge backend. Implementations score; they never decide. Policy
/// thresholds turn verdicts into allow, ask, or deny.
pub trait JudgeAdapter: Send + Sync {
    /// The pinned model this adapter must answer with.
    fn id(&self) -> &ModelPin;

    /// What kind of backend this is.
    fn kind(&self) -> AdapterKind;

    /// Score one predicate. The runner applies the deadline, the
    /// concurrency limit, and output validation around this call.
    fn score<'a>(
        &'a self,
        request: &'a JudgeRequest,
        predicate: &'a PredicateDef,
    ) -> BoxFuture<'a, Result<RawScores, JudgeError>>;
}

/// Why a judge call produced no usable verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JudgeError {
    /// The deadline passed before the judge answered.
    #[error("judge deadline expired")]
    Timeout,
    /// The concurrency limit was reached; the call was not attempted.
    #[error("judge is saturated")]
    Saturated,
    /// The backend failed (crash, transport error, inference error).
    #[error("judge unavailable: {0}")]
    Unavailable(String),
    /// The backend answered with output that does not fit the predicate.
    #[error("judge output malformed: {0}")]
    Malformed(String),
    /// The backend answered with a model other than the pinned one.
    #[error("judge model mismatch: expected {expected}, got {got}")]
    ModelMismatch {
        /// The pinned model.
        expected: String,
        /// The model that answered.
        got: String,
    },
}

impl JudgeError {
    /// The failure class used by policy and records.
    pub fn kind(&self) -> FailureKind {
        match self {
            Self::Timeout => FailureKind::Timeout,
            Self::Saturated => FailureKind::Saturated,
            Self::Unavailable(_) => FailureKind::Unavailable,
            Self::Malformed(_) => FailureKind::Malformed,
            Self::ModelMismatch { .. } => FailureKind::ModelMismatch,
        }
    }
}

/// Failure classes, each with its own configured policy behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// Deadline expired.
    Timeout,
    /// Concurrency limit reached.
    Saturated,
    /// Backend crashed or could not be reached.
    Unavailable,
    /// Output did not fit the predicate's label set or was not a distribution.
    Malformed,
    /// Backend answered with an unpinned model.
    ModelMismatch,
}

impl FailureKind {
    /// Every failure class.
    pub const ALL: [Self; 5] = [
        Self::Timeout,
        Self::Saturated,
        Self::Unavailable,
        Self::Malformed,
        Self::ModelMismatch,
    ];

    /// The class a wire string names, if any.
    pub fn from_wire(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Saturated => "saturated",
            Self::Unavailable => "unavailable",
            Self::Malformed => "malformed",
            Self::ModelMismatch => "model_mismatch",
        }
    }
}

/// A predicate the judge could not score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeFailure {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// The pinned model the call was made against.
    pub model: ModelPin,
    /// Failure class.
    pub kind: FailureKind,
    /// Operator-facing detail (never sent to the agent).
    pub detail: String,
    /// Time spent before the failure, microseconds.
    pub latency_us: u64,
}

/// The result of asking the judge about one predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JudgeOutcome {
    /// A validated verdict.
    Scored(Verdict),
    /// No usable verdict.
    Failed(JudgeFailure),
}

impl JudgeOutcome {
    /// The predicate this outcome is about.
    pub fn predicate_id(&self) -> &str {
        match self {
            Self::Scored(verdict) => &verdict.predicate_id,
            Self::Failed(failure) => &failure.predicate_id,
        }
    }

    /// The pinned model involved.
    pub fn model(&self) -> &ModelPin {
        match self {
            Self::Scored(verdict) => &verdict.model,
            Self::Failed(failure) => &failure.model,
        }
    }

    /// Latency in microseconds.
    pub fn latency_us(&self) -> u64 {
        match self {
            Self::Scored(verdict) => verdict.latency_us,
            Self::Failed(failure) => failure.latency_us,
        }
    }

    /// `scored` or the failure class.
    pub fn status_str(&self) -> &'static str {
        match self {
            Self::Scored(_) => "scored",
            Self::Failed(failure) => failure.kind.as_str(),
        }
    }
}

/// A label from a backend as shown in an error: at most 64 characters,
/// since the backend chooses it.
fn shown_label(label: &str) -> String {
    label.chars().take(64).collect()
}

/// Check raw adapter output against the predicate and the pin, and
/// convert it to a [`Verdict`] in the predicate's label order.
///
/// Rejected: an unpinned model, a missing, unknown or repeated label,
/// a probability that is not finite or outside `[0, 1]`, and a set of
/// probabilities that does not sum to 1 within [`SUM_TOLERANCE`].
pub fn validate_scores(
    predicate: &PredicateDef,
    pin: &ModelPin,
    raw: RawScores,
    latency_us: u64,
) -> Result<Verdict, JudgeError> {
    if &raw.model != pin {
        return Err(JudgeError::ModelMismatch {
            expected: pin.to_string(),
            got: raw.model.to_string(),
        });
    }
    if raw.probs.len() != predicate.labels.len() {
        return Err(JudgeError::Malformed(format!(
            "expected {} labels for {}, got {}",
            predicate.labels.len(),
            predicate.id,
            raw.probs.len()
        )));
    }
    let mut sum = 0.0f64;
    for (index, (label, p)) in raw.probs.iter().enumerate() {
        if !predicate.has_label(label) {
            return Err(JudgeError::Malformed(format!(
                "label {:?} is not a label of {}",
                shown_label(label),
                predicate.id
            )));
        }
        if raw.probs.iter().take(index).any(|(earlier, _)| earlier == label) {
            return Err(JudgeError::Malformed(format!(
                "label {:?} appears twice",
                shown_label(label)
            )));
        }
        if !p.is_finite() || *p < 0.0 || *p > 1.0 {
            return Err(JudgeError::Malformed(format!(
                "probability for {label:?} is not in [0, 1]"
            )));
        }
        sum += p;
    }
    if (sum - 1.0).abs() > SUM_TOLERANCE {
        return Err(JudgeError::Malformed(format!(
            "probabilities sum to {sum}, not 1"
        )));
    }
    let probs = predicate
        .labels
        .iter()
        .map(|label| {
            let p = raw
                .probs
                .iter()
                .find(|(l, _)| l == label)
                .map_or(0.0, |(_, p)| *p);
            LabelProb {
                label: label.clone(),
                ppm: prob_to_ppm(p),
            }
        })
        .collect();
    Ok(Verdict {
        predicate_id: predicate.id.clone(),
        probs,
        model: raw.model,
        latency_us,
    })
}

/// Round a probability in `[0, 1]` to parts per million.
pub fn prob_to_ppm(p: f64) -> u32 {
    let scaled = (p.clamp(0.0, 1.0) * f64::from(PPM_ONE)).round();
    // In range by the clamp above; the conversion cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ppm = scaled as u32;
    ppm.min(PPM_ONE)
}

/// Convert a threshold written as a probability (`0.7`) to parts per million.
pub fn threshold_to_ppm(p: f64) -> Result<u32, String> {
    if !p.is_finite() || !(0.0..=1.0).contains(&p) {
        return Err(format!("threshold {p} must be a probability in [0, 1]"));
    }
    Ok(prob_to_ppm(p))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::predicate::{PredicateRegistry, ARG_MATCHES_TASK};

    fn pin() -> ModelPin {
        ModelPin::new("m", "1", "b".repeat(64)).unwrap()
    }

    fn raw(probs: &[(&str, f64)]) -> RawScores {
        RawScores {
            probs: probs.iter().map(|(l, p)| ((*l).to_owned(), *p)).collect(),
            model: pin(),
        }
    }

    fn validate(probs: &[(&str, f64)]) -> Result<Verdict, JudgeError> {
        let registry = PredicateRegistry::builtin();
        validate_scores(registry.get(ARG_MATCHES_TASK).unwrap(), &pin(), raw(probs), 5)
    }

    #[test]
    fn valid_scores_come_back_in_label_order_as_ppm() {
        let verdict = validate(&[("mismatch", 0.82), ("match", 0.18)]).unwrap();
        assert_eq!(verdict.probs[0].label, "match");
        assert_eq!(verdict.probs[0].ppm, 180_000);
        assert_eq!(verdict.probs[1].ppm, 820_000);
        assert_eq!(verdict.latency_us, 5);
    }

    #[test]
    fn malformed_output_is_rejected() {
        for probs in [
            vec![("match", 1.0)],
            vec![("match", 0.5), ("other", 0.5)],
            vec![("match", 0.5), ("match", 0.5)],
            vec![("match", 0.7), ("mismatch", 0.7)],
            vec![("match", f64::NAN), ("mismatch", 0.5)],
            vec![("match", -0.1), ("mismatch", 1.1)],
            vec![("match", 0.2), ("mismatch", 0.2), ("x", 0.6)],
        ] {
            let error = validate(&probs).unwrap_err();
            assert_eq!(error.kind(), FailureKind::Malformed, "{probs:?}");
        }
    }

    #[test]
    fn an_unpinned_model_is_a_mismatch() {
        let registry = PredicateRegistry::builtin();
        let mut scores = raw(&[("match", 0.5), ("mismatch", 0.5)]);
        scores.model = ModelPin::new("m", "2", "b".repeat(64)).unwrap();
        let error = validate_scores(registry.get(ARG_MATCHES_TASK).unwrap(), &pin(), scores, 1).unwrap_err();
        assert_eq!(error.kind(), FailureKind::ModelMismatch);
    }

    #[test]
    fn ppm_conversion_rounds_and_clamps() {
        assert_eq!(prob_to_ppm(0.7), 700_000);
        assert_eq!(prob_to_ppm(0.000_000_4), 0);
        assert_eq!(prob_to_ppm(0.000_000_6), 1);
        assert_eq!(prob_to_ppm(2.0), PPM_ONE);
        assert_eq!(prob_to_ppm(-1.0), 0);
        assert_eq!(threshold_to_ppm(0.3).unwrap(), 300_000);
        assert!(threshold_to_ppm(1.5).is_err());
        assert!(threshold_to_ppm(f64::NAN).is_err());
    }
}
