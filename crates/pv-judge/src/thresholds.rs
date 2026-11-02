//! Policy thresholds: turning verdicts into allow, ask, or deny.
//!
//! The judge only reports probabilities. The thresholds here belong to
//! policy (they are configured with the policy, not with the model), so
//! the model can be swapped without moving a decision boundary, and an
//! auditor can replay a decision from the record: "the judge gave
//! 0.82 for `mismatch`, the deny threshold was 0.7, so the call was
//! denied."

use crate::adapter::{FailureKind, JudgeOutcome};
use crate::model::Verdict;
use serde::{Deserialize, Serialize};

/// What policy does with a judged call, ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeAction {
    /// Let the call through.
    Allow,
    /// Hold the call for human approval (the agent receives
    /// `APPROVAL_REQUIRED`; nothing runs).
    Ask,
    /// Refuse the call.
    Deny,
}

impl JudgeAction {
    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

/// One threshold over one label of one predicate. Comparisons are
/// strict: `deny_above_ppm = 700_000` denies at 700_001 and above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRule {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// The label whose probability is compared.
    pub label: String,
    /// Deny when the label's probability is above this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_above_ppm: Option<u32>,
    /// Ask when the label's probability is above this (and not above
    /// the deny threshold).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_above_ppm: Option<u32>,
    /// Ask when the most probable label is below this: the model is not
    /// confident in any answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence_ppm: Option<u32>,
}

impl ThresholdRule {
    /// Check that the rule can fire and that its bands are ordered.
    pub fn validate(&self) -> Result<(), String> {
        if self.deny_above_ppm.is_none() && self.ask_above_ppm.is_none() && self.min_confidence_ppm.is_none()
        {
            return Err(format!(
                "threshold for {} / {} sets none of deny_above, ask_above, min_confidence",
                self.predicate_id, self.label
            ));
        }
        for value in [self.deny_above_ppm, self.ask_above_ppm, self.min_confidence_ppm]
            .into_iter()
            .flatten()
        {
            if value > crate::PPM_ONE {
                return Err(format!(
                    "threshold for {} / {} is above 1",
                    self.predicate_id, self.label
                ));
            }
        }
        if let (Some(deny), Some(ask)) = (self.deny_above_ppm, self.ask_above_ppm) {
            if ask > deny {
                return Err(format!(
                    "threshold for {} / {}: ask_above must not exceed deny_above",
                    self.predicate_id, self.label
                ));
            }
        }
        Ok(())
    }
}

/// What policy does when the judge produced no usable verdict. `Allow`
/// is never accepted: a judge failure must not let a call through
/// silently. A model mismatch always denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailurePolicy {
    /// Deadline expired.
    pub timeout: JudgeAction,
    /// Backend crashed or could not be reached.
    pub unavailable: JudgeAction,
    /// Concurrency limit reached.
    pub saturated: JudgeAction,
    /// Output did not fit the predicate (the uncertain band).
    pub malformed: JudgeAction,
}

impl Default for FailurePolicy {
    fn default() -> Self {
        Self {
            timeout: JudgeAction::Deny,
            unavailable: JudgeAction::Deny,
            saturated: JudgeAction::Deny,
            malformed: JudgeAction::Ask,
        }
    }
}

impl FailurePolicy {
    /// Refuse a policy that would allow on failure.
    pub fn validate(&self) -> Result<(), String> {
        for (name, action) in [
            ("timeout", self.timeout),
            ("unavailable", self.unavailable),
            ("saturated", self.saturated),
            ("malformed", self.malformed),
        ] {
            if action == JudgeAction::Allow {
                return Err(format!(
                    "judge failure behaviour for {name} must be deny or ask, never allow"
                ));
            }
        }
        Ok(())
    }

    /// The action for a failure class.
    pub fn action_for(&self, kind: FailureKind) -> JudgeAction {
        match kind {
            FailureKind::Timeout => self.timeout,
            FailureKind::Unavailable => self.unavailable,
            FailureKind::Saturated => self.saturated,
            FailureKind::Malformed => self.malformed,
            FailureKind::ModelMismatch => JudgeAction::Deny,
        }
    }
}

/// Why policy reached its decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecisionCause {
    /// No predicate was evaluated for this call.
    NotJudged,
    /// Every verdict stayed below its thresholds.
    WithinThresholds,
    /// A label's probability crossed a threshold.
    Threshold {
        /// The compared label.
        label: String,
        /// Its probability, ppm.
        ppm: u32,
        /// The crossed threshold, ppm.
        threshold_ppm: u32,
    },
    /// The most probable label was below the confidence floor.
    LowConfidence {
        /// The most probable label.
        top_label: String,
        /// Its probability, ppm.
        top_ppm: u32,
        /// The configured floor, ppm.
        min_ppm: u32,
    },
    /// The judge produced no usable verdict.
    Failure {
        /// Failure class.
        failure: FailureKind,
    },
    /// The runtime calibration check found accuracy no longer rises with
    /// confidence, so this predicate asks by default.
    DriftGate,
}

/// A policy decision over a set of judge outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeDecision {
    /// The decided action.
    pub action: JudgeAction,
    /// The predicate that drove the decision (absent for a plain allow).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_id: Option<String>,
    /// Why.
    pub cause: DecisionCause,
    /// Agent-facing explanation. Carries no backend details.
    pub reason: String,
}

impl JudgeDecision {
    fn allow(cause: DecisionCause) -> Self {
        Self {
            action: JudgeAction::Allow,
            predicate_id: None,
            cause,
            reason: String::new(),
        }
    }
}

/// The configured thresholds and failure behaviour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThresholdPolicy {
    rules: Vec<ThresholdRule>,
    failure: FailurePolicy,
}

impl ThresholdPolicy {
    /// Build and validate.
    pub fn new(rules: Vec<ThresholdRule>, failure: FailurePolicy) -> Result<Self, String> {
        failure.validate()?;
        for rule in &rules {
            rule.validate()?;
        }
        Ok(Self { rules, failure })
    }

    /// The rules.
    pub fn rules(&self) -> &[ThresholdRule] {
        &self.rules
    }

    /// The failure behaviour.
    pub fn failure(&self) -> &FailurePolicy {
        &self.failure
    }

    /// True when at least one rule covers `predicate_id`.
    pub fn covers(&self, predicate_id: &str) -> bool {
        self.rules.iter().any(|rule| rule.predicate_id == predicate_id)
    }

    /// Decide over every outcome. The most severe outcome wins; on a tie
    /// the first one (in outcome order) is reported. `drift_tripped`
    /// says which predicates the runtime calibration check has flipped
    /// to ask-by-default.
    pub fn decide(&self, outcomes: &[JudgeOutcome], drift_tripped: &dyn Fn(&str) -> bool) -> JudgeDecision {
        if outcomes.is_empty() {
            return JudgeDecision::allow(DecisionCause::NotJudged);
        }
        let mut best = JudgeDecision::allow(DecisionCause::WithinThresholds);
        for outcome in outcomes {
            let candidate = match outcome {
                JudgeOutcome::Scored(verdict) => {
                    let decided = self.decide_verdict(verdict);
                    if decided.action == JudgeAction::Allow && drift_tripped(&verdict.predicate_id) {
                        JudgeDecision {
                            action: JudgeAction::Ask,
                            predicate_id: Some(verdict.predicate_id.clone()),
                            cause: DecisionCause::DriftGate,
                            reason: format!(
                                "judge predicate {} is in ask-by-default mode after a calibration \
                                 drift check; human approval required",
                                verdict.predicate_id
                            ),
                        }
                    } else {
                        decided
                    }
                }
                JudgeOutcome::Failed(failure) => {
                    let action = self.failure.action_for(failure.kind);
                    JudgeDecision {
                        action,
                        predicate_id: Some(failure.predicate_id.clone()),
                        cause: DecisionCause::Failure {
                            failure: failure.kind,
                        },
                        reason: format!(
                            "judge could not evaluate predicate {} ({}); {}",
                            failure.predicate_id,
                            failure.kind.as_str(),
                            match action {
                                JudgeAction::Ask => "human approval required",
                                _ => "refused",
                            }
                        ),
                    }
                }
            };
            if candidate.action > best.action {
                best = candidate;
            }
        }
        best
    }

    fn decide_verdict(&self, verdict: &Verdict) -> JudgeDecision {
        let mut best = JudgeDecision::allow(DecisionCause::WithinThresholds);
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.predicate_id == verdict.predicate_id)
        {
            let candidate = rule_decision(rule, verdict);
            if candidate.action > best.action {
                best = candidate;
            }
        }
        best
    }
}

fn rule_decision(rule: &ThresholdRule, verdict: &Verdict) -> JudgeDecision {
    let ppm = verdict.ppm(&rule.label).unwrap_or(0);
    if let Some(deny) = rule.deny_above_ppm {
        if ppm > deny {
            return threshold_decision(JudgeAction::Deny, rule, ppm, deny);
        }
    }
    if let Some(ask) = rule.ask_above_ppm {
        if ppm > ask {
            return threshold_decision(JudgeAction::Ask, rule, ppm, ask);
        }
    }
    if let (Some(min), Some(top)) = (rule.min_confidence_ppm, verdict.top()) {
        if top.ppm < min {
            return JudgeDecision {
                action: JudgeAction::Ask,
                predicate_id: Some(verdict.predicate_id.clone()),
                cause: DecisionCause::LowConfidence {
                    top_label: top.label.clone(),
                    top_ppm: top.ppm,
                    min_ppm: min,
                },
                reason: format!(
                    "judge predicate {}: most probable label {} at {} is below the confidence \
                     floor {}; human approval required",
                    verdict.predicate_id,
                    top.label,
                    format_ppm(top.ppm),
                    format_ppm(min)
                ),
            };
        }
    }
    JudgeDecision::allow(DecisionCause::WithinThresholds)
}

fn threshold_decision(action: JudgeAction, rule: &ThresholdRule, ppm: u32, threshold: u32) -> JudgeDecision {
    JudgeDecision {
        action,
        predicate_id: Some(rule.predicate_id.clone()),
        cause: DecisionCause::Threshold {
            label: rule.label.clone(),
            ppm,
            threshold_ppm: threshold,
        },
        reason: format!(
            "judge predicate {}: P({}) = {} is above the {} threshold {}{}",
            rule.predicate_id,
            rule.label,
            format_ppm(ppm),
            action.as_str(),
            format_ppm(threshold),
            if action == JudgeAction::Ask {
                "; human approval required"
            } else {
                ""
            }
        ),
    }
}

/// Render parts per million as a decimal probability (`820000` → `0.82`).
pub fn format_ppm(ppm: u32) -> String {
    let whole = ppm / crate::PPM_ONE;
    let fraction = ppm % crate::PPM_ONE;
    if fraction == 0 {
        return format!("{whole}");
    }
    let digits = format!("{fraction:06}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::adapter::JudgeFailure;
    use crate::model::{LabelProb, ModelPin};

    fn pin() -> ModelPin {
        ModelPin::new("m", "1", "c".repeat(64)).unwrap()
    }

    fn scored(predicate: &str, probs: &[(&str, u32)]) -> JudgeOutcome {
        JudgeOutcome::Scored(Verdict {
            predicate_id: predicate.to_owned(),
            probs: probs
                .iter()
                .map(|(label, ppm)| LabelProb {
                    label: (*label).to_owned(),
                    ppm: *ppm,
                })
                .collect(),
            model: pin(),
            latency_us: 10,
        })
    }

    fn failed(predicate: &str, kind: FailureKind) -> JudgeOutcome {
        JudgeOutcome::Failed(JudgeFailure {
            predicate_id: predicate.to_owned(),
            model: pin(),
            kind,
            detail: "internal detail".to_owned(),
            latency_us: 10,
        })
    }

    fn policy() -> ThresholdPolicy {
        ThresholdPolicy::new(
            vec![ThresholdRule {
                predicate_id: "p@1".into(),
                label: "mismatch".into(),
                deny_above_ppm: Some(700_000),
                ask_above_ppm: Some(300_000),
                min_confidence_ppm: None,
            }],
            FailurePolicy::default(),
        )
        .unwrap()
    }

    const NEVER: &dyn Fn(&str) -> bool = &|_| false;

    #[test]
    fn spec_example_bands() {
        let p = policy();
        let decide = |m: u32| {
            p.decide(
                &[scored("p@1", &[("match", 1_000_000 - m), ("mismatch", m)])],
                NEVER,
            )
        };
        assert_eq!(decide(820_000).action, JudgeAction::Deny);
        assert_eq!(decide(700_001).action, JudgeAction::Deny);
        assert_eq!(decide(700_000).action, JudgeAction::Ask);
        assert_eq!(decide(500_000).action, JudgeAction::Ask);
        assert_eq!(decide(300_000).action, JudgeAction::Allow);
        assert_eq!(decide(100_000).action, JudgeAction::Allow);
        let denied = decide(820_000);
        assert_eq!(denied.predicate_id.as_deref(), Some("p@1"));
        assert_eq!(
            denied.cause,
            DecisionCause::Threshold {
                label: "mismatch".into(),
                ppm: 820_000,
                threshold_ppm: 700_000
            }
        );
        assert!(denied.reason.contains("0.82"), "{}", denied.reason);
        assert!(denied.reason.contains("0.7"), "{}", denied.reason);
    }

    #[test]
    fn failures_follow_the_failure_policy_and_never_allow() {
        let p = policy();
        for (kind, expected) in [
            (FailureKind::Timeout, JudgeAction::Deny),
            (FailureKind::Unavailable, JudgeAction::Deny),
            (FailureKind::Saturated, JudgeAction::Deny),
            (FailureKind::Malformed, JudgeAction::Ask),
            (FailureKind::ModelMismatch, JudgeAction::Deny),
        ] {
            let decision = p.decide(&[failed("p@1", kind)], NEVER);
            assert_eq!(decision.action, expected, "{kind:?}");
            assert!(!decision.reason.contains("internal detail"));
        }
        let all_ask = FailurePolicy {
            timeout: JudgeAction::Ask,
            unavailable: JudgeAction::Ask,
            saturated: JudgeAction::Ask,
            malformed: JudgeAction::Ask,
        };
        let asking = ThresholdPolicy::new(Vec::new(), all_ask).unwrap();
        assert_eq!(
            asking
                .decide(&[failed("p@1", FailureKind::ModelMismatch)], NEVER)
                .action,
            JudgeAction::Deny
        );
        assert_eq!(
            asking
                .decide(&[failed("p@1", FailureKind::Timeout)], NEVER)
                .action,
            JudgeAction::Ask
        );
        let allowing = FailurePolicy {
            timeout: JudgeAction::Allow,
            ..FailurePolicy::default()
        };
        assert!(ThresholdPolicy::new(Vec::new(), allowing).is_err());
    }

    #[test]
    fn the_most_severe_outcome_wins() {
        let p = policy();
        let decision = p.decide(
            &[
                scored("p@1", &[("match", 600_000), ("mismatch", 400_000)]),
                failed("q@1", FailureKind::Timeout),
            ],
            NEVER,
        );
        assert_eq!(decision.action, JudgeAction::Deny);
        assert_eq!(decision.predicate_id.as_deref(), Some("q@1"));
        assert_eq!(p.decide(&[], NEVER).cause, DecisionCause::NotJudged);
    }

    #[test]
    fn low_confidence_asks() {
        let p = ThresholdPolicy::new(
            vec![ThresholdRule {
                predicate_id: "p@1".into(),
                label: "mismatch".into(),
                deny_above_ppm: None,
                ask_above_ppm: None,
                min_confidence_ppm: Some(600_000),
            }],
            FailurePolicy::default(),
        )
        .unwrap();
        let decision = p.decide(
            &[scored("p@1", &[("match", 550_000), ("mismatch", 450_000)])],
            NEVER,
        );
        assert_eq!(decision.action, JudgeAction::Ask);
        assert!(matches!(decision.cause, DecisionCause::LowConfidence { .. }));
        let confident = p.decide(
            &[scored("p@1", &[("match", 900_000), ("mismatch", 100_000)])],
            NEVER,
        );
        assert_eq!(confident.action, JudgeAction::Allow);
    }

    #[test]
    fn drift_gate_turns_allow_into_ask_but_keeps_denies() {
        let p = policy();
        let tripped: &dyn Fn(&str) -> bool = &|id| id == "p@1";
        let allow = p.decide(
            &[scored("p@1", &[("match", 950_000), ("mismatch", 50_000)])],
            tripped,
        );
        assert_eq!(allow.action, JudgeAction::Ask);
        assert_eq!(allow.cause, DecisionCause::DriftGate);
        let deny = p.decide(
            &[scored("p@1", &[("match", 50_000), ("mismatch", 950_000)])],
            tripped,
        );
        assert_eq!(deny.action, JudgeAction::Deny);
    }

    #[test]
    fn rules_are_validated() {
        let mut rule = ThresholdRule {
            predicate_id: "p@1".into(),
            label: "mismatch".into(),
            deny_above_ppm: Some(300_000),
            ask_above_ppm: Some(700_000),
            min_confidence_ppm: None,
        };
        assert!(rule.validate().is_err());
        rule.ask_above_ppm = None;
        assert!(rule.validate().is_ok());
        rule.deny_above_ppm = None;
        assert!(rule.validate().is_err());
        rule.deny_above_ppm = Some(1_000_001);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn ppm_formatting() {
        assert_eq!(format_ppm(820_000), "0.82");
        assert_eq!(format_ppm(700_000), "0.7");
        assert_eq!(format_ppm(1_000_000), "1");
        assert_eq!(format_ppm(0), "0");
        assert_eq!(format_ppm(1), "0.000001");
    }
}
