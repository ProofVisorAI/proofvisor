//! Build-time calibration regression test.
//!
//! Measured on 2026-11-01 with the toy ONNX classifier in
//! `tests/common` over `tests/fixtures/synthetic_arg_matches_task.jsonl`
//! (18 synthetic examples, 8 positive): AUROC 975_000 ppm, separation
//! 775_000 ppm, accuracy 888_888 ppm, accuracy rising with confidence.
//! The floors below sit under those numbers; if a change to scoring,
//! rendering, tokenization, or validation erodes them, this test fails
//! before a deployment does.
//!
//! A production model gets its own copy of this test, pointed at its
//! own labelled set (seeded from shadow-mode traces and design-partner
//! calls) and at its own measured numbers. `pvctl judge-calibrate` runs
//! the same measurement against a deployed config.
#![cfg(feature = "runner")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(feature = "onnx")]
mod common;

use pv_judge::calibration::{calibrate, load_jsonl, CalibrationFloor};
use pv_judge::mock::{MockBehavior, MockJudge};
use pv_judge::{AdapterSlot, JudgeRunner, ModelPin, PredicateRegistry};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const SET: &str = include_str!("fixtures/synthetic_arg_matches_task.jsonl");

fn runner(adapter: Arc<dyn pv_judge::JudgeAdapter>) -> JudgeRunner {
    let mut adapters = BTreeMap::new();
    adapters.insert(
        "judge".to_owned(),
        AdapterSlot {
            adapter,
            deadline: Duration::from_secs(5),
        },
    );
    JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), 4).unwrap()
}

#[cfg(feature = "onnx")]
#[tokio::test]
async fn toy_model_separation_holds() {
    let dir = tempfile::tempdir().unwrap();
    let judge =
        pv_judge::local::LocalOnnxJudge::load(&common::config(dir.path(), &common::model_bytes(false)))
            .unwrap();
    let examples = load_jsonl(SET).unwrap();
    let report = calibrate(&runner(Arc::new(judge)), "judge", &examples)
        .await
        .unwrap();
    let measured = &report.predicates[0];
    assert_eq!(measured.examples, 18);
    assert_eq!(measured.positives, 8);
    assert_eq!(measured.failures, 0);
    assert_eq!(measured.auroc_ppm, 975_000);
    assert_eq!(measured.separation_ppm, 775_000);
    assert_eq!(measured.accuracy_ppm, 888_888);
    let floor = CalibrationFloor {
        min_examples: 18,
        min_auroc_ppm: 950_000,
        min_separation_ppm: 700_000,
        max_failure_ppm: 0,
        require_monotone: true,
        min_per_band: 4,
        tolerance_ppm: 0,
    };
    let shortfalls = report.shortfalls(&floor);
    assert!(shortfalls.is_empty(), "{shortfalls:?}");
}

#[tokio::test]
async fn a_judge_that_ignores_its_input_fails_the_floor() {
    let pin = ModelPin::new("coin", "1", "9".repeat(64)).unwrap();
    let constant = MockJudge::new(pin, MockBehavior::scores(&[("match", 0.5), ("mismatch", 0.5)]));
    let examples = load_jsonl(SET).unwrap();
    let report = calibrate(&runner(Arc::new(constant)), "judge", &examples)
        .await
        .unwrap();
    let floor = CalibrationFloor {
        min_examples: 1,
        min_auroc_ppm: 600_000,
        min_separation_ppm: 100_000,
        max_failure_ppm: 0,
        require_monotone: false,
        min_per_band: 1,
        tolerance_ppm: 0,
    };
    assert_eq!(report.predicates[0].auroc_ppm, 500_000);
    assert_eq!(report.shortfalls(&floor).len(), 2);
}

#[tokio::test]
async fn failures_count_against_the_floor() {
    let pin = ModelPin::new("down", "1", "9".repeat(64)).unwrap();
    let down = MockJudge::new(
        pin,
        MockBehavior::Fail(pv_judge::JudgeError::Unavailable("down".into())),
    );
    let examples = load_jsonl(SET).unwrap();
    let report = calibrate(&runner(Arc::new(down)), "judge", &examples)
        .await
        .unwrap();
    assert_eq!(report.predicates[0].failures, 18);
    let floor = CalibrationFloor {
        min_examples: 1,
        min_auroc_ppm: 0,
        min_separation_ppm: i64::MIN,
        max_failure_ppm: 0,
        require_monotone: false,
        min_per_band: 1,
        tolerance_ppm: 0,
    };
    assert_eq!(report.shortfalls(&floor).len(), 1);
}

#[tokio::test]
async fn unknown_labels_in_the_set_are_refused() {
    let pin = ModelPin::new("m", "1", "9".repeat(64)).unwrap();
    let judge = MockJudge::new(pin, MockBehavior::scores(&[("match", 0.5), ("mismatch", 0.5)]));
    let bad =
        load_jsonl(r#"{"predicate_id":"arg_matches_task@1","tool":"t","arguments":{},"label":"maybe"}"#)
            .unwrap();
    assert!(calibrate(&runner(Arc::new(judge)), "judge", &bad).await.is_err());
}
