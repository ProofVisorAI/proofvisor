//! Runtime calibration check ("drift gate").
//!
//! A well-calibrated judge is right more often when it is more
//! confident. The harness samples scored verdicts for human review;
//! reviewers report whether the judge's most probable label was
//! correct. Accuracy is tracked per confidence band. When accuracy
//! stops rising with confidence (a higher band is less accurate than a
//! lower one by more than the tolerance, each with enough reviews), the
//! predicate is flipped to ask-by-default: judged calls that policy
//! would have allowed are held for approval instead. The flip is sticky
//! until an operator resets it.

use crate::model::Verdict;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

/// Lower bounds (ppm) of the confidence bands of the most probable label.
/// The first band catches predicates with more than two labels, whose
/// top label can sit below one half.
pub const BAND_LOWER_PPM: [u32; 6] = [0, 500_000, 600_000, 700_000, 800_000, 900_000];

/// The band index of a top-label probability.
pub fn band_of(top_ppm: u32) -> usize {
    BAND_LOWER_PPM
        .iter()
        .rposition(|lower| top_ppm >= *lower)
        .unwrap_or(0)
}

/// Reviewed and correct counts for one band.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandStats {
    /// Lower bound of the band, ppm.
    pub lower_ppm: u32,
    /// Reviews received.
    pub reviewed: u64,
    /// Reviews that confirmed the judge's top label.
    pub correct: u64,
}

impl BandStats {
    /// Accuracy in ppm, or `None` without reviews.
    pub fn accuracy_ppm(&self) -> Option<u32> {
        if self.reviewed == 0 {
            return None;
        }
        let ppm = u128::from(self.correct) * u128::from(crate::PPM_ONE) / u128::from(self.reviewed);
        Some(u32::try_from(ppm).unwrap_or(crate::PPM_ONE))
    }
}

/// True when accuracy never falls by more than `tolerance_ppm` from one
/// band to a higher one, among bands with at least `min_count` reviews.
pub fn is_monotone(bands: &[BandStats], min_count: u64, tolerance_ppm: u32) -> bool {
    let mut best_lower: Option<u32> = None;
    for band in bands.iter().filter(|band| band.reviewed >= min_count) {
        let Some(accuracy) = band.accuracy_ppm() else {
            continue;
        };
        if let Some(previous) = best_lower {
            if accuracy.saturating_add(tolerance_ppm) < previous {
                return false;
            }
        }
        best_lower = Some(best_lower.map_or(accuracy, |previous| previous.max(accuracy)));
    }
    true
}

fn empty_bands() -> Vec<BandStats> {
    BAND_LOWER_PPM
        .iter()
        .map(|lower| BandStats {
            lower_ppm: *lower,
            ..BandStats::default()
        })
        .collect()
}

/// Drift gate settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftConfig {
    /// Sample one scored verdict in this many for review (at least 1).
    pub sample_every: u64,
    /// Reviews a band needs before it counts in the check (at least 1).
    pub min_reviews_per_band: u64,
    /// Allowed accuracy drop between bands, ppm.
    pub tolerance_ppm: u32,
    /// Sampled verdicts kept waiting for review; the oldest are dropped.
    pub max_pending: usize,
}

impl DriftConfig {
    /// Validate the settings.
    pub fn validate(&self) -> Result<(), String> {
        if self.sample_every == 0 {
            return Err("judge drift sample_every must be at least 1".to_owned());
        }
        if self.min_reviews_per_band == 0 {
            return Err("judge drift min_reviews_per_band must be at least 1".to_owned());
        }
        if self.tolerance_ppm > crate::PPM_ONE {
            return Err("judge drift tolerance must be a probability in [0, 1]".to_owned());
        }
        if self.max_pending == 0 {
            return Err("judge drift max_pending must be at least 1".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Pending {
    predicate_id: String,
    band: usize,
}

/// Why a review was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DriftError {
    /// No sampled verdict has this id (never sampled, already reviewed,
    /// or dropped from the pending queue).
    #[error("unknown or already reviewed review_id")]
    UnknownReview,
}

/// What a review changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewResult {
    /// The reviewed predicate.
    pub predicate_id: String,
    /// True when this review flipped the predicate to ask-by-default.
    pub tripped_now: bool,
    /// True when the predicate is in ask-by-default mode.
    pub tripped: bool,
}

/// Per-predicate state in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateDrift {
    /// Versioned predicate id.
    pub predicate_id: String,
    /// Band statistics, lowest band first.
    pub bands: Vec<BandStats>,
    /// True when in ask-by-default mode.
    pub tripped: bool,
}

/// A point-in-time view of the drift gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftSnapshot {
    /// Settings.
    pub config: DriftConfig,
    /// Sampled verdicts waiting for review.
    pub pending_reviews: usize,
    /// Per-predicate state.
    pub predicates: Vec<PredicateDrift>,
}

/// The durable part of the drift gate: band statistics and which
/// predicates are in ask-by-default mode. Sampled verdicts still waiting
/// for review are not part of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftState {
    /// Band statistics per predicate, lowest band first.
    pub stats: BTreeMap<String, Vec<BandStats>>,
    /// Predicates in ask-by-default mode.
    pub tripped: Vec<String>,
}

/// The drift gate. Each harness instance tracks the reviews it receives
/// for the verdicts it sampled; [`DriftMonitor::export_state`] and
/// [`DriftMonitor::restore`] let the caller keep the statistics and the
/// ask-by-default switches across restarts.
pub struct DriftMonitor {
    config: DriftConfig,
    seen: AtomicU64,
    pending: Mutex<(BTreeMap<String, Pending>, VecDeque<String>)>,
    stats: Mutex<BTreeMap<String, Vec<BandStats>>>,
    tripped: Mutex<BTreeMap<String, bool>>,
}

impl DriftMonitor {
    /// Build a monitor.
    pub fn new(config: DriftConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            seen: AtomicU64::new(0),
            pending: Mutex::new((BTreeMap::new(), VecDeque::new())),
            stats: Mutex::new(BTreeMap::new()),
            tripped: Mutex::new(BTreeMap::new()),
        })
    }

    /// Count a scored verdict and, one time in `sample_every`, register
    /// it for review under the id `make_id` returns.
    pub fn maybe_sample(&self, verdict: &Verdict, make_id: impl FnOnce() -> String) -> Option<String> {
        let index = self.seen.fetch_add(1, Ordering::Relaxed);
        if !index.is_multiple_of(self.config.sample_every) {
            return None;
        }
        let top = verdict.top()?;
        let id = make_id();
        let mut guard = self.pending.lock();
        let (map, order) = &mut *guard;
        map.insert(
            id.clone(),
            Pending {
                predicate_id: verdict.predicate_id.clone(),
                band: band_of(top.ppm),
            },
        );
        order.push_back(id.clone());
        while order.len() > self.config.max_pending {
            if let Some(oldest) = order.pop_front() {
                map.remove(&oldest);
            }
        }
        Some(id)
    }

    /// Record a reviewer's answer: was the judge's top label correct?
    pub fn record_review(&self, review_id: &str, correct: bool) -> Result<ReviewResult, DriftError> {
        let pending = {
            let mut guard = self.pending.lock();
            let (map, order) = &mut *guard;
            let pending = map.remove(review_id).ok_or(DriftError::UnknownReview)?;
            order.retain(|id| id != review_id);
            pending
        };
        let monotone = {
            let mut stats = self.stats.lock();
            let bands = stats
                .entry(pending.predicate_id.clone())
                .or_insert_with(empty_bands);
            if let Some(band) = bands.get_mut(pending.band) {
                band.reviewed += 1;
                if correct {
                    band.correct += 1;
                }
            }
            is_monotone(bands, self.config.min_reviews_per_band, self.config.tolerance_ppm)
        };
        let mut tripped = self.tripped.lock();
        let was = tripped.get(&pending.predicate_id).copied().unwrap_or(false);
        let now = was || !monotone;
        tripped.insert(pending.predicate_id.clone(), now);
        Ok(ReviewResult {
            predicate_id: pending.predicate_id,
            tripped_now: now && !was,
            tripped: now,
        })
    }

    /// True when `predicate_id` is in ask-by-default mode.
    pub fn is_tripped(&self, predicate_id: &str) -> bool {
        self.tripped.lock().get(predicate_id).copied().unwrap_or(false)
    }

    /// Every predicate in ask-by-default mode.
    pub fn tripped(&self) -> Vec<String> {
        self.tripped
            .lock()
            .iter()
            .filter(|(_, tripped)| **tripped)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Operator reset: clear the flip and the statistics for a predicate
    /// (after recalibrating or replacing the model). Returns whether the
    /// predicate was tripped.
    pub fn reset(&self, predicate_id: &str) -> bool {
        self.stats.lock().remove(predicate_id);
        self.tripped.lock().remove(predicate_id).unwrap_or(false)
    }

    /// The statistics and switches to persist.
    pub fn export_state(&self) -> DriftState {
        DriftState {
            stats: self.stats.lock().clone(),
            tripped: self.tripped(),
        }
    }

    /// Load persisted statistics and switches (at startup). Refuses band
    /// lists of the wrong shape rather than guessing.
    pub fn restore(&self, state: DriftState) -> Result<(), String> {
        for (predicate, bands) in &state.stats {
            let shaped = bands.len() == BAND_LOWER_PPM.len()
                && bands
                    .iter()
                    .zip(BAND_LOWER_PPM.iter())
                    .all(|(band, lower)| band.lower_ppm == *lower && band.correct <= band.reviewed);
            if !shaped {
                return Err(format!(
                    "drift state for {predicate:?} has malformed confidence bands"
                ));
            }
        }
        *self.stats.lock() = state.stats;
        *self.tripped.lock() = state.tripped.into_iter().map(|id| (id, true)).collect();
        Ok(())
    }

    /// A snapshot for operators.
    pub fn snapshot(&self) -> DriftSnapshot {
        let stats = self.stats.lock().clone();
        let tripped = self.tripped.lock().clone();
        let mut ids: Vec<String> = stats.keys().chain(tripped.keys()).cloned().collect();
        ids.sort();
        ids.dedup();
        DriftSnapshot {
            config: self.config,
            pending_reviews: self.pending.lock().0.len(),
            predicates: ids
                .into_iter()
                .map(|id| PredicateDrift {
                    bands: stats.get(&id).cloned().unwrap_or_else(empty_bands),
                    tripped: tripped.get(&id).copied().unwrap_or(false),
                    predicate_id: id,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::model::{LabelProb, ModelPin};

    fn verdict(top_ppm: u32) -> Verdict {
        Verdict {
            predicate_id: "p@1".into(),
            probs: vec![
                LabelProb {
                    label: "a".into(),
                    ppm: top_ppm,
                },
                LabelProb {
                    label: "b".into(),
                    ppm: 1_000_000 - top_ppm,
                },
            ],
            model: ModelPin::new("m", "1", "f".repeat(64)).unwrap(),
            latency_us: 1,
        }
    }

    fn config() -> DriftConfig {
        DriftConfig {
            sample_every: 1,
            min_reviews_per_band: 3,
            tolerance_ppm: 50_000,
            max_pending: 100,
        }
    }

    #[test]
    fn bands_cover_the_range() {
        assert_eq!(band_of(0), 0);
        assert_eq!(band_of(499_999), 0);
        assert_eq!(band_of(500_000), 1);
        assert_eq!(band_of(950_000), 5);
        assert_eq!(band_of(1_000_000), 5);
    }

    #[test]
    fn monotone_needs_enough_reviews_and_respects_tolerance() {
        let band = |lower, reviewed, correct| BandStats {
            lower_ppm: lower,
            reviewed,
            correct,
        };
        assert!(is_monotone(&[band(500_000, 10, 6), band(900_000, 10, 9)], 5, 0));
        assert!(!is_monotone(&[band(500_000, 10, 9), band(900_000, 10, 6)], 5, 0));
        assert!(is_monotone(&[band(500_000, 10, 9), band(900_000, 2, 0)], 5, 0));
        assert!(is_monotone(
            &[band(500_000, 100, 90), band(900_000, 100, 86)],
            5,
            50_000
        ));
        assert!(!is_monotone(
            &[band(500_000, 100, 90), band(900_000, 100, 84)],
            5,
            50_000
        ));
    }

    #[test]
    fn non_monotone_accuracy_trips_and_stays_tripped_until_reset() {
        let monitor = DriftMonitor::new(config()).unwrap();
        let mut next = 0u32;
        let mut sample = |top| {
            next += 1;
            let id = format!("r{next}");
            monitor.maybe_sample(&verdict(top), || id).unwrap()
        };
        // Low band: always right. High band: always wrong.
        let low: Vec<String> = (0..3).map(|_| sample(550_000)).collect();
        let high: Vec<String> = (0..3).map(|_| sample(950_000)).collect();
        for id in &low {
            assert!(!monitor.record_review(id, true).unwrap().tripped);
        }
        let mut results = Vec::new();
        for id in &high {
            results.push(monitor.record_review(id, false).unwrap());
        }
        assert!(!results[1].tripped);
        assert!(results[2].tripped_now);
        assert!(monitor.is_tripped("p@1"));
        assert_eq!(monitor.tripped(), vec!["p@1".to_owned()]);
        assert_eq!(
            monitor.record_review(&high[0], true),
            Err(DriftError::UnknownReview)
        );
        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.predicates[0].bands[5].reviewed, 3);
        assert!(monitor.reset("p@1"));
        assert!(!monitor.is_tripped("p@1"));
    }

    #[test]
    fn sampling_rate_and_pending_bound() {
        let monitor = DriftMonitor::new(DriftConfig {
            sample_every: 3,
            max_pending: 2,
            ..config()
        })
        .unwrap();
        let ids: Vec<Option<String>> = (0..9)
            .map(|i| monitor.maybe_sample(&verdict(900_000), || format!("id{i}")))
            .collect();
        assert_eq!(ids.iter().filter(|id| id.is_some()).count(), 3);
        assert_eq!(monitor.snapshot().pending_reviews, 2);
        assert_eq!(monitor.record_review("id0", true), Err(DriftError::UnknownReview));
        assert!(monitor.record_review("id6", true).is_ok());
    }

    #[test]
    fn state_round_trips_and_malformed_state_is_refused() {
        let monitor = DriftMonitor::new(config()).unwrap();
        for i in 0..3 {
            let id = monitor
                .maybe_sample(&verdict(950_000), || format!("x{i}"))
                .unwrap();
            monitor.record_review(&id, false).unwrap();
        }
        let low: Vec<String> = (0..3)
            .map(|i| {
                monitor
                    .maybe_sample(&verdict(550_000), || format!("y{i}"))
                    .unwrap()
            })
            .collect();
        for id in &low {
            monitor.record_review(id, true).unwrap();
        }
        assert!(monitor.is_tripped("p@1"));
        let state = monitor.export_state();
        let text = serde_json::to_string(&state).unwrap();
        let restored = DriftMonitor::new(config()).unwrap();
        restored.restore(serde_json::from_str(&text).unwrap()).unwrap();
        assert!(restored.is_tripped("p@1"));
        assert_eq!(restored.snapshot().predicates, monitor.snapshot().predicates);
        let mut bad = state;
        bad.stats.get_mut("p@1").unwrap().pop();
        assert!(DriftMonitor::new(config()).unwrap().restore(bad).is_err());
    }

    #[test]
    fn config_is_validated() {
        assert!(DriftMonitor::new(DriftConfig {
            sample_every: 0,
            ..config()
        })
        .is_err());
        assert!(DriftMonitor::new(DriftConfig {
            min_reviews_per_band: 0,
            ..config()
        })
        .is_err());
        assert!(DriftMonitor::new(DriftConfig {
            max_pending: 0,
            ..config()
        })
        .is_err());
        assert!(DriftMonitor::new(DriftConfig {
            tolerance_ppm: 1_000_001,
            ..config()
        })
        .is_err());
    }
}
