//! Build-time calibration: score a labelled set and fail when the
//! model's measured separation drops below a recorded floor.
//!
//! The labelled set is JSON Lines, one example per line:
//!
//! ```json
//! {"predicate_id":"arg_matches_task@1","tool":"db_write","arguments":{"table":"orders"},
//!  "context":{"charter":"billing-agent","delegation_depth":0,"task":"Reconcile March invoices"},
//!  "label":"match","source":"shadow-2026-11"}
//! ```
//!
//! Metrics per predicate, all integers (ppm):
//! * accuracy of the most probable label;
//! * AUROC of the positive label's probability (Mann–Whitney, ties
//!   counted as one half);
//! * separation: mean positive-label probability on positive examples
//!   minus the same mean on negative examples;
//! * accuracy by confidence band, and whether it rises with confidence.

use crate::adapter::JudgeOutcome;
use crate::drift::{band_of, is_monotone, BandStats, BAND_LOWER_PPM};
use crate::model::{SessionContext, Verdict};
use crate::runner::{JudgeRunner, JudgeTask};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// One labelled example.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelledExample {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// Tool name.
    pub tool: String,
    /// Validated arguments.
    pub arguments: Value,
    /// Context the judge sees.
    #[serde(default)]
    pub context: SessionContext,
    /// The correct label.
    pub label: String,
    /// Where the example came from (shadow traces, a design-partner
    /// call, a synthetic fixture).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Parse a JSON Lines labelled set. Blank lines are skipped; errors
/// name the line.
pub fn load_jsonl(text: &str) -> Result<Vec<LabelledExample>, String> {
    let mut examples = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let example: LabelledExample = serde_json::from_str(line)
            .map_err(|error| format!("labelled set line {}: {error}", index + 1))?;
        examples.push(example);
    }
    Ok(examples)
}

/// Measured quality for one predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateReport {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// Examples for this predicate.
    pub examples: u64,
    /// Examples whose correct label is the positive label.
    pub positives: u64,
    /// Examples the judge could not score.
    pub failures: u64,
    /// Accuracy of the most probable label over scored examples, ppm.
    pub accuracy_ppm: u32,
    /// AUROC of the positive label's probability, ppm (500_000 = chance).
    pub auroc_ppm: u32,
    /// Mean positive-label ppm on positives minus on negatives.
    pub separation_ppm: i64,
    /// Accuracy by confidence band.
    pub bands: Vec<BandStats>,
}

/// The whole run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationReport {
    /// Adapter name.
    pub adapter: String,
    /// The pinned model that was measured.
    pub model: crate::ModelPin,
    /// One report per predicate in the set.
    pub predicates: Vec<PredicateReport>,
}

/// The minimum a model must reach. Record the measured values (with the
/// date and the set they were measured on) next to the floor, the way
/// `pv-loopdetect/tests/calibrate.rs` does for the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationFloor {
    /// Fewest examples per predicate.
    pub min_examples: u64,
    /// Lowest acceptable AUROC, ppm.
    pub min_auroc_ppm: u32,
    /// Lowest acceptable separation, ppm.
    pub min_separation_ppm: i64,
    /// Most failures tolerated, ppm of examples.
    pub max_failure_ppm: u32,
    /// Require accuracy to rise with confidence.
    pub require_monotone: bool,
    /// Reviews a band needs to count in the monotonicity check.
    pub min_per_band: u64,
    /// Allowed accuracy drop between bands, ppm.
    pub tolerance_ppm: u32,
}

impl PredicateReport {
    /// Every way this report falls short of `floor`.
    pub fn shortfalls(&self, floor: &CalibrationFloor) -> Vec<String> {
        let mut problems = Vec::new();
        if self.examples < floor.min_examples {
            problems.push(format!(
                "{}: {} examples, floor {}",
                self.predicate_id, self.examples, floor.min_examples
            ));
        }
        if self.auroc_ppm < floor.min_auroc_ppm {
            problems.push(format!(
                "{}: AUROC {} ppm, floor {}",
                self.predicate_id, self.auroc_ppm, floor.min_auroc_ppm
            ));
        }
        if self.separation_ppm < floor.min_separation_ppm {
            problems.push(format!(
                "{}: separation {} ppm, floor {}",
                self.predicate_id, self.separation_ppm, floor.min_separation_ppm
            ));
        }
        let failure_ppm = ratio_ppm(self.failures, self.examples);
        if failure_ppm > floor.max_failure_ppm {
            problems.push(format!(
                "{}: {} of {} examples failed to score",
                self.predicate_id, self.failures, self.examples
            ));
        }
        if floor.require_monotone && !is_monotone(&self.bands, floor.min_per_band, floor.tolerance_ppm) {
            problems.push(format!(
                "{}: accuracy does not rise with confidence",
                self.predicate_id
            ));
        }
        problems
    }
}

impl CalibrationReport {
    /// Every shortfall across predicates; empty when the floor holds.
    pub fn shortfalls(&self, floor: &CalibrationFloor) -> Vec<String> {
        self.predicates
            .iter()
            .flat_map(|report| report.shortfalls(floor))
            .collect()
    }
}

/// Score every example with `adapter` and measure.
pub async fn calibrate(
    runner: &JudgeRunner,
    adapter: &str,
    examples: &[LabelledExample],
) -> Result<CalibrationReport, String> {
    let model = runner
        .adapter(adapter)
        .ok_or_else(|| format!("adapter {adapter:?} is not configured"))?
        .adapter
        .id()
        .clone();
    let mut grouped: BTreeMap<String, Vec<(&LabelledExample, JudgeOutcome)>> = BTreeMap::new();
    for example in examples {
        let predicate = runner
            .registry()
            .get(&example.predicate_id)
            .ok_or_else(|| format!("labelled set uses unknown predicate {:?}", example.predicate_id))?;
        if !predicate.has_label(&example.label) {
            return Err(format!(
                "labelled set uses label {:?}, which {} does not have",
                example.label, example.predicate_id
            ));
        }
        let task = JudgeTask {
            predicate_id: example.predicate_id.clone(),
            adapter: adapter.to_owned(),
        };
        let outcome = runner
            .evaluate(
                std::slice::from_ref(&task),
                &example.tool,
                &example.arguments,
                &example.context,
            )
            .await
            .into_iter()
            .next()
            .ok_or_else(|| "runner returned no outcome".to_owned())?;
        grouped
            .entry(example.predicate_id.clone())
            .or_default()
            .push((example, outcome));
    }
    let mut predicates = Vec::new();
    for (predicate_id, results) in grouped {
        let positive = runner
            .registry()
            .get(&predicate_id)
            .map(|def| def.positive_label.clone())
            .unwrap_or_default();
        predicates.push(measure(&predicate_id, &positive, &results));
    }
    Ok(CalibrationReport {
        adapter: adapter.to_owned(),
        model,
        predicates,
    })
}

fn measure(
    predicate_id: &str,
    positive: &str,
    results: &[(&LabelledExample, JudgeOutcome)],
) -> PredicateReport {
    let mut bands: Vec<BandStats> = BAND_LOWER_PPM
        .iter()
        .map(|lower| BandStats {
            lower_ppm: *lower,
            ..BandStats::default()
        })
        .collect();
    let mut failures = 0u64;
    let mut correct = 0u64;
    let mut scored: Vec<(u32, bool)> = Vec::new();
    let mut positives = 0u64;
    for (example, outcome) in results {
        let is_positive = example.label == positive;
        if is_positive {
            positives += 1;
        }
        let JudgeOutcome::Scored(verdict) = outcome else {
            failures += 1;
            continue;
        };
        let right = top_label(verdict) == Some(example.label.as_str());
        if right {
            correct += 1;
        }
        if let Some(top) = verdict.top() {
            if let Some(band) = bands.get_mut(band_of(top.ppm)) {
                band.reviewed += 1;
                if right {
                    band.correct += 1;
                }
            }
        }
        scored.push((verdict.ppm(positive).unwrap_or(0), is_positive));
    }
    let examples = u64::try_from(results.len()).unwrap_or(u64::MAX);
    PredicateReport {
        predicate_id: predicate_id.to_owned(),
        examples,
        positives,
        failures,
        accuracy_ppm: ratio_ppm(correct, u64::try_from(scored.len()).unwrap_or(u64::MAX)),
        auroc_ppm: auroc_ppm(&scored),
        separation_ppm: separation_ppm(&scored),
        bands,
    }
}

fn top_label(verdict: &Verdict) -> Option<&str> {
    verdict.top().map(|top| top.label.as_str())
}

fn ratio_ppm(part: u64, whole: u64) -> u32 {
    if whole == 0 {
        return 0;
    }
    let ppm = u128::from(part) * u128::from(crate::PPM_ONE) / u128::from(whole);
    u32::try_from(ppm).unwrap_or(crate::PPM_ONE)
}

/// Mann–Whitney AUROC over `(score, is_positive)`; 500_000 when either
/// class is empty.
pub fn auroc_ppm(scored: &[(u32, bool)]) -> u32 {
    let positives = scored.iter().filter(|(_, p)| *p).count();
    let negatives = scored.len() - positives;
    if positives == 0 || negatives == 0 {
        return crate::PPM_ONE / 2;
    }
    let mut sorted: Vec<(u32, bool)> = scored.to_vec();
    sorted.sort_by_key(|(score, _)| *score);
    // Sum of (doubled) ranks of positives, with ties at their average rank.
    let mut rank_sum_doubled: u128 = 0;
    let mut start = 0usize;
    while start < sorted.len() {
        let score = sorted.get(start).map_or(0, |(s, _)| *s);
        let mut end = start;
        while sorted.get(end).is_some_and(|(s, _)| *s == score) {
            end += 1;
        }
        // Ranks start + 1 ..= end; doubled average = start + 1 + end.
        let doubled_average = (start + 1 + end) as u128;
        let tied_positives = sorted
            .get(start..end)
            .map_or(0, |slice| slice.iter().filter(|(_, p)| *p).count());
        rank_sum_doubled += doubled_average * tied_positives as u128;
        start = end;
    }
    let p = positives as u128;
    let n = negatives as u128;
    // U = R - P(P+1)/2 ; AUROC = U / (P N). All doubled to stay integral.
    let u_doubled = rank_sum_doubled.saturating_sub(p * (p + 1));
    let ppm = u_doubled * u128::from(crate::PPM_ONE) / (2 * p * n);
    u32::try_from(ppm).unwrap_or(crate::PPM_ONE)
}

fn separation_ppm(scored: &[(u32, bool)]) -> i64 {
    let mean = |positive: bool| -> Option<i64> {
        let values: Vec<i64> = scored
            .iter()
            .filter(|(_, p)| *p == positive)
            .map(|(s, _)| i64::from(*s))
            .collect();
        let count = i64::try_from(values.len()).ok().filter(|count| *count > 0)?;
        Some(values.iter().sum::<i64>() / count)
    };
    match (mean(true), mean(false)) {
        (Some(pos), Some(neg)) => pos - neg,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn auroc_matches_hand_computed_values() {
        assert_eq!(auroc_ppm(&[(900_000, true), (100_000, false)]), 1_000_000);
        assert_eq!(auroc_ppm(&[(100_000, true), (900_000, false)]), 0);
        assert_eq!(auroc_ppm(&[(500_000, true), (500_000, false)]), 500_000);
        // P = {0.8, 0.4}, N = {0.6, 0.2}: pairs won 3 of 4.
        assert_eq!(
            auroc_ppm(&[
                (800_000, true),
                (400_000, true),
                (600_000, false),
                (200_000, false)
            ]),
            750_000
        );
        assert_eq!(auroc_ppm(&[(800_000, true)]), 500_000);
    }

    #[test]
    fn separation_is_the_difference_of_means() {
        assert_eq!(
            separation_ppm(&[(900_000, true), (700_000, true), (100_000, false)]),
            700_000
        );
        assert_eq!(separation_ppm(&[(900_000, true)]), 0);
    }

    #[test]
    fn jsonl_errors_name_the_line() {
        let ok = "{\"predicate_id\":\"p@1\",\"tool\":\"t\",\"arguments\":{},\"label\":\"a\"}\n\n";
        assert_eq!(load_jsonl(ok).unwrap().len(), 1);
        let bad = format!("{ok}{{\"predicate_id\":1}}\n");
        assert!(load_jsonl(&bad).unwrap_err().contains("line 3"));
    }
}
