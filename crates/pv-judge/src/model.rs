//! The judge's data model: model pins, requests, and verdicts.
//!
//! Probabilities leave the judge as integer parts per million
//! ([`PPM_ONE`] = 1.0). Verdicts are written into OCSF events that the
//! session event chain hashes in JCS form, and the signed records in
//! this codebase stay integer-only: a float such as `0.82f32` renders
//! as `0.8199999928474426` and float formatting is where independent
//! JCS implementations disagree. Thresholds use the same unit, so the
//! value an auditor reads in the record is the value the policy compared.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// One probability unit: parts per million.
pub const PPM_ONE: u32 = 1_000_000;

/// Identity of the model behind a judge: name, version, and the SHA-256
/// of its weights. A weights change is therefore visible in every record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPin {
    /// Model name.
    pub name: String,
    /// Model version.
    pub version: String,
    /// Lowercase hex SHA-256 of the weights file bytes.
    pub weights_sha256: String,
}

impl ModelPin {
    /// Build a pin, validating every field.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        weights_sha256: impl Into<String>,
    ) -> Result<Self, String> {
        let pin = Self {
            name: name.into(),
            version: version.into(),
            weights_sha256: weights_sha256.into(),
        };
        pin.validate()?;
        Ok(pin)
    }

    /// Check the field formats.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err("model pin name must be 1..=128 characters".to_owned());
        }
        if self.version.trim().is_empty() || self.version.len() > 128 {
            return Err("model pin version must be 1..=128 characters".to_owned());
        }
        if !is_sha256_hex(&self.weights_sha256) {
            return Err(format!(
                "model pin weights_sha256 for {:?} must be 64 lowercase hex characters",
                self.name
            ));
        }
        Ok(())
    }
}

impl fmt::Display for ModelPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{} (sha256:{})",
            self.name, self.version, self.weights_sha256
        )
    }
}

/// True for a 64-character lowercase hex string.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Where a prior denial was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialSource {
    /// Earlier in the calling agent's own session.
    Session,
    /// By an agent above the caller in its delegation chain.
    Parent,
}

/// A refused tool call the judge may take into account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorDenial {
    /// The refused tool.
    pub tool: String,
    /// The stable denial code, e.g. `POLICY_DENIED`.
    pub denial_code: String,
    /// The predicate behind the refusal, when the judge caused it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_id: Option<String>,
    /// When it was refused, epoch milliseconds.
    pub at_ms: u64,
    /// Whose refusal this was.
    pub source: DenialSource,
    /// The refusing agent's `instance_uid`.
    pub instance_uid: String,
}

/// What the judge may know about the call's context. It never carries
/// the raw prompt: only operator-controlled facts (intent, mission,
/// task statement, charter) and refusals the harness itself recorded.
/// That bounds both judge injection and what a cloud judge can see.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContext {
    /// Business intent the tool maps to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// Operator-written task statement of the applicable mission(s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Ids of the applicable missions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mission_ids: Vec<String>,
    /// Intents the applicable missions allow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_intents: Vec<String>,
    /// The calling agent's charter.
    pub charter: String,
    /// Delegation links above the calling agent (0 = root token).
    pub delegation_depth: u32,
    /// Recent refusals: the caller's own session first, then parents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prior_denials: Vec<PriorDenial>,
}

/// One scoring request: one predicate over one validated tool call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeRequest {
    /// Versioned predicate id, e.g. `arg_matches_task@1`.
    pub predicate_id: String,
    /// Tool name.
    pub tool: String,
    /// Arguments that passed the schema gate (and any pushed transforms).
    pub validated_args: Value,
    /// Context the judge may see.
    pub context: SessionContext,
}

/// One label's probability, in parts per million.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelProb {
    /// Label from the predicate's fixed label set.
    pub label: String,
    /// Probability in parts per million (0..=1_000_000).
    pub ppm: u32,
}

/// A validated judge verdict: the full distribution over the predicate's
/// labels, the pinned model that produced it, and its latency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// One entry per label, in the predicate's label order.
    pub probs: Vec<LabelProb>,
    /// Model that produced it.
    pub model: ModelPin,
    /// Scoring latency in microseconds.
    pub latency_us: u64,
}

impl Verdict {
    /// Probability of `label`, in parts per million.
    pub fn ppm(&self, label: &str) -> Option<u32> {
        self.probs.iter().find(|p| p.label == label).map(|p| p.ppm)
    }

    /// The most probable label (first in label order on a tie).
    pub fn top(&self) -> Option<&LabelProb> {
        self.probs
            .iter()
            .reduce(|best, p| if p.ppm > best.ppm { p } else { best })
    }
}

/// Raw output of an adapter, before validation against the predicate.
#[derive(Debug, Clone, PartialEq)]
pub struct RawScores {
    /// `(label, probability)` pairs; probabilities in `[0, 1]`.
    pub probs: Vec<(String, f64)>,
    /// The model that actually answered, as the backend reports it.
    pub model: ModelPin,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn pin() -> ModelPin {
        ModelPin::new("m", "1", "a".repeat(64)).unwrap()
    }

    #[test]
    fn pin_rejects_bad_hashes() {
        assert!(ModelPin::new("m", "1", "A".repeat(64)).is_err());
        assert!(ModelPin::new("m", "1", "a".repeat(63)).is_err());
        assert!(ModelPin::new("", "1", "a".repeat(64)).is_err());
        assert!(ModelPin::new("m", " ", "a".repeat(64)).is_err());
        assert!(ModelPin::new("m", "1", "0123456789abcdef".repeat(4)).is_ok());
    }

    #[test]
    fn sha256_of_empty_input_is_the_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn top_prefers_the_first_label_on_ties() {
        let verdict = Verdict {
            predicate_id: "p@1".into(),
            probs: vec![
                LabelProb {
                    label: "a".into(),
                    ppm: 500_000,
                },
                LabelProb {
                    label: "b".into(),
                    ppm: 500_000,
                },
            ],
            model: pin(),
            latency_us: 1,
        };
        assert_eq!(verdict.top().unwrap().label, "a");
        assert_eq!(verdict.ppm("b"), Some(500_000));
        assert_eq!(verdict.ppm("c"), None);
    }

    #[test]
    fn verdict_serializes_without_floats() {
        let verdict = Verdict {
            predicate_id: "p@1".into(),
            probs: vec![LabelProb {
                label: "a".into(),
                ppm: 820_000,
            }],
            model: pin(),
            latency_us: 7,
        };
        let text = serde_json::to_string(&verdict).unwrap();
        assert!(!text.contains('.'), "{text}");
    }
}
