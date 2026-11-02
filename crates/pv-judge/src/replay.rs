//! Replaying recorded decisions.
//!
//! Every judged tool call carries a [`JudgeRecord`]: the verdicts (the
//! full distribution or the failure class, per predicate), the
//! predicates in ask-by-default mode at the time, and what the
//! thresholds decided. Replaying rebuilds the judge's outcomes from the
//! record, as a mock judge answering with the recorded probabilities,
//! and runs them through [`ThresholdPolicy::decide`], the function the
//! harness itself uses. Two uses:
//!
//! * an auditor checks that each recorded decision follows from its
//!   verdicts under the thresholds that were configured ("the judge said
//!   0.82 mismatch, the threshold was 0.7, so it was denied");
//! * an operator tries other thresholds on shadow-mode or pilot traffic
//!   and sees which calls they would have blocked.
//!
//! Only the thresholds are replayed. What a WASM policy (interface
//! version 2) decided from the verdicts, `policy_decision` in the
//! record, is not reproduced. A replay does not detect tampering
//! either: check the receipt that covers the records first.

use crate::adapter::{FailureKind, JudgeFailure, JudgeOutcome};
use crate::model::Verdict;
use crate::record::{JudgeRecord, OutcomeRecord};
use crate::thresholds::{DecisionCause, JudgeAction, JudgeDecision, ThresholdPolicy};

/// The outcome a recorded verdict stands for.
///
/// # Errors
///
/// When the record's status is neither `scored` nor a known failure
/// class, or a scored record carries no probabilities.
pub fn outcome_from_record(record: &OutcomeRecord) -> Result<JudgeOutcome, String> {
    if record.status == "scored" {
        if record.probs.is_empty() {
            return Err(format!(
                "verdict for {} is scored but has no probabilities",
                record.predicate_id
            ));
        }
        return Ok(JudgeOutcome::Scored(Verdict {
            predicate_id: record.predicate_id.clone(),
            probs: record.probs.clone(),
            model: record.model.clone(),
            latency_us: record.latency_us,
        }));
    }
    let kind = FailureKind::from_wire(&record.status).ok_or_else(|| {
        format!(
            "verdict for {} has an unknown status {:?}",
            record.predicate_id, record.status
        )
    })?;
    Ok(JudgeOutcome::Failed(JudgeFailure {
        predicate_id: record.predicate_id.clone(),
        model: record.model.clone(),
        kind,
        detail: record.detail.clone().unwrap_or_default(),
        latency_us: record.latency_us,
    }))
}

/// What `policy` decides over the verdicts in `record`, with the
/// predicates the record lists in ask-by-default mode.
///
/// # Errors
///
/// When a verdict cannot be rebuilt (see [`outcome_from_record`]).
pub fn replay(record: &JudgeRecord, policy: &ThresholdPolicy) -> Result<JudgeDecision, String> {
    let outcomes = record
        .verdicts
        .iter()
        .map(outcome_from_record)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(policy.decide(&outcomes, &|predicate| {
        record.drift_tripped.iter().any(|tripped| tripped == predicate)
    }))
}

/// The part of a decision a replay compares: action, deciding
/// predicate and cause.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DecisionSummary {
    /// Allow, ask or deny.
    pub action: JudgeAction,
    /// The predicate that drove it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate_id: Option<String>,
    /// Why.
    pub cause: DecisionCause,
}

impl DecisionSummary {
    /// The decision written in `record`.
    pub fn recorded(record: &JudgeRecord) -> Self {
        Self {
            action: record.decision,
            predicate_id: record.decision_predicate.clone(),
            cause: record.cause.clone(),
        }
    }

    /// A decision computed now.
    pub fn of(decision: &JudgeDecision) -> Self {
        Self {
            action: decision.action,
            predicate_id: decision.predicate_id.clone(),
            cause: decision.cause.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::model::{LabelProb, ModelPin};
    use crate::record::JudgeMode;
    use crate::thresholds::{FailurePolicy, ThresholdRule};

    fn pin() -> ModelPin {
        ModelPin::new("m", "1", "ab".repeat(32)).unwrap()
    }

    fn policy(deny_above_ppm: u32) -> ThresholdPolicy {
        ThresholdPolicy::new(
            vec![ThresholdRule {
                predicate_id: "arg_matches_task@1".into(),
                label: "mismatch".into(),
                deny_above_ppm: Some(deny_above_ppm),
                ask_above_ppm: None,
                min_confidence_ppm: None,
            }],
            FailurePolicy::default(),
        )
        .unwrap()
    }

    fn scored(mismatch_ppm: u32) -> JudgeOutcome {
        JudgeOutcome::Scored(Verdict {
            predicate_id: "arg_matches_task@1".into(),
            probs: vec![
                LabelProb {
                    label: "match".into(),
                    ppm: 1_000_000 - mismatch_ppm,
                },
                LabelProb {
                    label: "mismatch".into(),
                    ppm: mismatch_ppm,
                },
            ],
            model: pin(),
            latency_us: 10,
        })
    }

    fn recorded(outcome: &JudgeOutcome, policy: &ThresholdPolicy, drift: &[&str]) -> JudgeRecord {
        let decision = policy.decide(std::slice::from_ref(outcome), &|id| drift.contains(&id));
        let mut record = JudgeRecord::new(
            JudgeMode::Shadow,
            10,
            vec![OutcomeRecord::from_outcome(
                outcome,
                "a",
                crate::AdapterKind::Mock,
            )],
            &decision,
            false,
        );
        record.drift_tripped = drift.iter().map(|id| (*id).to_owned()).collect();
        record
    }

    #[test]
    fn a_replay_reproduces_the_recorded_decision() {
        let policy = policy(700_000);
        for (outcome, drift) in [
            (scored(820_000), vec![]),
            (scored(100_000), vec![]),
            (scored(100_000), vec!["arg_matches_task@1"]),
            (
                JudgeOutcome::Failed(JudgeFailure {
                    predicate_id: "arg_matches_task@1".into(),
                    model: pin(),
                    kind: FailureKind::Malformed,
                    detail: "bad labels".into(),
                    latency_us: 5,
                }),
                vec![],
            ),
        ] {
            let record = recorded(&outcome, &policy, &drift);
            let replayed = replay(&record, &policy).unwrap();
            assert_eq!(DecisionSummary::of(&replayed), DecisionSummary::recorded(&record));
        }
    }

    #[test]
    fn other_thresholds_and_edited_probabilities_change_the_replay() {
        let record = recorded(&scored(820_000), &policy(700_000), &[]);
        assert_eq!(record.decision, JudgeAction::Deny);
        // A laxer threshold would have let it through.
        assert_eq!(
            replay(&record, &policy(900_000)).unwrap().action,
            JudgeAction::Allow
        );
        // An edited probability no longer matches the recorded decision.
        let mut edited = record.clone();
        edited.verdicts[0].probs[1].ppm = 10_000;
        edited.verdicts[0].probs[0].ppm = 990_000;
        let replayed = replay(&edited, &policy(700_000)).unwrap();
        assert_ne!(DecisionSummary::of(&replayed), DecisionSummary::recorded(&edited));
    }

    #[test]
    fn unknown_statuses_are_refused() {
        let mut record = recorded(&scored(100_000), &policy(700_000), &[]);
        record.verdicts[0].status = "exploded".into();
        assert!(replay(&record, &policy(700_000)).is_err());
        record.verdicts[0].status = "scored".into();
        record.verdicts[0].probs.clear();
        assert!(replay(&record, &policy(700_000)).is_err());
        for kind in FailureKind::ALL {
            assert_eq!(FailureKind::from_wire(kind.as_str()), Some(kind));
        }
    }
}
