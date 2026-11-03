//! The judge record written into the tool-call OCSF event payload and
//! the ATIF tool call's `extra`.
//!
//! For signed workflows the session receipt signs the head of the event
//! chain, which hashes every event in JCS form; for unsigned workflows
//! a retroactive receipt signs the digest of the ATIF trajectory file.
//! Writing this record into both places means every verdict is covered
//! by whichever signature the session ends up with, without changing
//! the receipt format. Every number in it is an integer.

use crate::adapter::{AdapterKind, JudgeOutcome};
use crate::model::{LabelProb, ModelPin};
use crate::thresholds::{DecisionCause, JudgeAction, JudgeDecision};
use serde::{Deserialize, Serialize};

/// Longest failure detail kept in a record.
pub const MAX_DETAIL_CHARS: usize = 256;

/// Whether the judge can block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeMode {
    /// Score and record; never block.
    Shadow,
    /// Score, record, and let policy act on the verdicts.
    Enforce,
}

impl JudgeMode {
    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

/// One predicate's result as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeRecord {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// Configured adapter name.
    pub adapter: String,
    /// Adapter kind.
    pub adapter_kind: AdapterKind,
    /// The pinned model.
    pub model: ModelPin,
    /// `scored` or the failure class.
    pub status: String,
    /// The full distribution (empty when not scored), ppm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probs: Vec<LabelProb>,
    /// Operator-facing failure detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Scoring latency, microseconds.
    pub latency_us: u64,
    /// Present when this verdict was sampled for human review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_id: Option<String>,
}

impl OutcomeRecord {
    /// Record an outcome produced by `adapter`.
    pub fn from_outcome(outcome: &JudgeOutcome, adapter: &str, adapter_kind: AdapterKind) -> Self {
        let (probs, detail) = match outcome {
            JudgeOutcome::Scored(verdict) => (verdict.probs.clone(), None),
            JudgeOutcome::Failed(failure) => (
                Vec::new(),
                Some(truncate_chars(&failure.detail, MAX_DETAIL_CHARS)),
            ),
        };
        Self {
            predicate_id: outcome.predicate_id().to_owned(),
            adapter: adapter.to_owned(),
            adapter_kind,
            model: outcome.model().clone(),
            status: outcome.status_str().to_owned(),
            probs,
            detail,
            latency_us: outcome.latency_us(),
            review_id: None,
        }
    }
}
/// The request a judged call put to the judge, kept when the operator
/// records it. The arguments are kept as JSON text: the event chain is
/// hashed in canonical JSON, where floating-point numbers are a known
/// source of disagreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeInputs {
    /// The tool called.
    pub tool: String,
    /// The validated arguments, as JSON text.
    pub arguments_json: String,
    /// The context the judge saw.
    pub context: crate::model::SessionContext,
}

/// Everything an auditor needs to replay a judged decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeRecord {
    /// Shadow or enforce.
    pub mode: JudgeMode,
    /// Wall time spent waiting for the judge, microseconds. Kept apart
    /// from the sandbox's own decision latency.
    pub judge_us: u64,
    /// One entry per evaluated predicate.
    pub verdicts: Vec<OutcomeRecord>,
    /// What the configured thresholds decided over the verdicts (the
    /// replayable part: probability, threshold, action). In shadow mode,
    /// or after the pilot cap, this is what they WOULD have done.
    pub decision: JudgeAction,
    /// True when judge evidence was applied to the call.
    pub enforced: bool,
    /// True when judge-aware policy (the thresholds and any policy that
    /// reads verdicts) blocks a call the rest of policy allows. In
    /// shadow mode this is the "would have blocked" signal to compare
    /// against what actually happened.
    pub would_block: bool,
    /// What the whole policy stage decided with the verdicts in hand:
    /// the thresholds, every policy that reads verdicts (WASM interface
    /// version 2), and the rules that ignore them. In shadow mode this is
    /// what it would have decided.
    pub policy_decision: JudgeAction,
    /// The policy that blocked or held the call, when `policy_decision`
    /// is not `allow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// The predicate that drove the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_predicate: Option<String>,
    /// Why.
    pub cause: DecisionCause,
    /// True when the pilot's daily block cap turned an enforced block
    /// into a recorded allow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pilot_cap_reached: bool,
    /// Predicates in ask-by-default mode after a calibration drift check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drift_tripped: Vec<String>,
    /// What the judge was asked, when the operator records it
    /// (`[judge] record_inputs`): the material for a labelled set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<JudgeInputs>,
}

impl JudgeRecord {
    /// Build a record from a decision.
    pub fn new(
        mode: JudgeMode,
        judge_us: u64,
        verdicts: Vec<OutcomeRecord>,
        decision: &JudgeDecision,
        enforced: bool,
    ) -> Self {
        Self {
            mode,
            judge_us,
            verdicts,
            decision: decision.action,
            enforced,
            would_block: false,
            policy_decision: decision.action,
            policy: None,
            decision_predicate: decision.predicate_id.clone(),
            cause: decision.cause.clone(),
            pilot_cap_reached: false,
            drift_tripped: Vec::new(),
            inputs: None,
        }
    }
}

fn truncate_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((cut, _)) => text.get(..cut).unwrap_or(text).to_owned(),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::adapter::{FailureKind, JudgeFailure};
    use crate::model::Verdict;

    fn pin() -> ModelPin {
        ModelPin::new("judge-args", "2026-10-01", "d".repeat(64)).unwrap()
    }

    #[test]
    fn record_round_trips_and_carries_no_floats() {
        let outcome = JudgeOutcome::Scored(Verdict {
            predicate_id: "arg_matches_task@1".into(),
            probs: vec![
                LabelProb {
                    label: "match".into(),
                    ppm: 180_000,
                },
                LabelProb {
                    label: "mismatch".into(),
                    ppm: 820_000,
                },
            ],
            model: ModelPin::new("judge", "7", "d".repeat(64)).unwrap(),
            latency_us: 1_234,
        });
        let decision = JudgeDecision {
            action: JudgeAction::Deny,
            predicate_id: Some("arg_matches_task@1".into()),
            cause: DecisionCause::Threshold {
                label: "mismatch".into(),
                ppm: 820_000,
                threshold_ppm: 700_000,
            },
            reason: "r".into(),
        };
        let record = JudgeRecord::new(
            JudgeMode::Enforce,
            1_500,
            vec![OutcomeRecord::from_outcome(&outcome, "local", AdapterKind::Local)],
            &decision,
            true,
        );
        let text = serde_json::to_string(&record).unwrap();
        assert!(!text.contains('.'), "{text}");
        let back: JudgeRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(back, record);
    }

    /// The record's fields, as the configuration reference documents them.
    /// The receipt signs the record through the event chain, so this list
    /// is the record's own whitelist: a field added, renamed or removed
    /// fails this test until the list and the documentation are updated.
    const RECORD_FIELDS: &[&str] = &[
        "mode",
        "judge_us",
        "verdicts",
        "decision",
        "enforced",
        "would_block",
        "policy_decision",
        "policy",
        "decision_predicate",
        "cause",
        "pilot_cap_reached",
        "drift_tripped",
        "inputs",
    ];
    const VERDICT_FIELDS: &[&str] = &[
        "predicate_id",
        "adapter",
        "adapter_kind",
        "model",
        "status",
        "probs",
        "detail",
        "latency_us",
        "review_id",
    ];

    #[test]
    fn record_fields_are_exactly_the_documented_ones() {
        let scored = JudgeOutcome::Scored(Verdict {
            predicate_id: "arg_matches_task@1".into(),
            probs: vec![LabelProb {
                label: "mismatch".into(),
                ppm: 820_000,
            }],
            model: ModelPin::new("judge", "7", "d".repeat(64)).unwrap(),
            latency_us: 1,
        });
        let failed = JudgeOutcome::Failed(crate::JudgeFailure {
            predicate_id: "arg_matches_task@1".into(),
            model: ModelPin::new("judge", "7", "d".repeat(64)).unwrap(),
            kind: crate::FailureKind::Timeout,
            detail: "late".into(),
            latency_us: 1,
        });
        let decision = JudgeDecision {
            action: JudgeAction::Deny,
            predicate_id: Some("arg_matches_task@1".into()),
            cause: DecisionCause::Threshold {
                label: "mismatch".into(),
                ppm: 820_000,
                threshold_ppm: 700_000,
            },
            reason: "r".into(),
        };
        let mut verdicts = vec![
            OutcomeRecord::from_outcome(&scored, "local", AdapterKind::Local),
            OutcomeRecord::from_outcome(&failed, "local", AdapterKind::Local),
        ];
        if let Some(first) = verdicts.first_mut() {
            first.review_id = Some("r-1".into());
        }
        let mut record = JudgeRecord::new(JudgeMode::Enforce, 1, verdicts, &decision, true);
        record.policy = Some("p".into());
        record.pilot_cap_reached = true;
        record.drift_tripped = vec!["arg_matches_task@1".into()];
        record.inputs = Some(JudgeInputs {
            tool: "t".into(),
            arguments_json: "{}".into(),
            context: crate::model::SessionContext::default(),
        });
        let value = serde_json::to_value(&record).unwrap();
        let keys = |object: &serde_json::Value| -> std::collections::BTreeSet<String> {
            object.as_object().unwrap().keys().cloned().collect()
        };
        let expected = |fields: &[&str]| fields.iter().map(|field| (*field).to_owned()).collect();
        assert_eq!(keys(&value), expected(RECORD_FIELDS));
        let mut seen = std::collections::BTreeSet::new();
        for verdict in value
            .get("verdicts")
            .and_then(serde_json::Value::as_array)
            .unwrap()
        {
            seen.extend(keys(verdict));
        }
        assert_eq!(seen, expected(VERDICT_FIELDS));
        let reference = include_str!("../../../docs/reference/CONFIGURATION.md");
        for field in RECORD_FIELDS {
            assert!(
                reference.contains(&format!("`{field}`")),
                "CONFIGURATION.md does not document `{field}`"
            );
        }
    }

    #[test]
    fn failure_detail_is_bounded() {
        let outcome = JudgeOutcome::Failed(JudgeFailure {
            predicate_id: "p@1".into(),
            model: pin(),
            kind: FailureKind::Unavailable,
            detail: "é".repeat(1_000),
            latency_us: 3,
        });
        let record = OutcomeRecord::from_outcome(&outcome, "cloud", AdapterKind::Cloud);
        assert_eq!(record.detail.unwrap().chars().count(), MAX_DETAIL_CHARS);
        assert_eq!(record.status, "unavailable");
        assert!(record.probs.is_empty());
    }
}
