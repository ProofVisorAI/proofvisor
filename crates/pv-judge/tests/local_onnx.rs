//! The local scorer against a real ONNX file and a real tokenizer.
//!
//! The model is built here, byte for byte, as an ONNX protobuf: it
//! casts token ids to floats, masks them, sums them, and maps the sum
//! `s` to logits `[25, s]`. With the tokenizer below (`warn` = 25,
//! `danger` = 50, every other word unknown = 0), arguments mentioning
//! `danger` score `mismatch` near 1, `warn` near one half, and anything
//! else near 0. That makes every step checkable: hashing, loading,
//! input binding, tokenization, inference, softmax, and validation.
#![cfg(feature = "onnx")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{config, model_bytes};
use pv_judge::local::LocalOnnxJudge;
use pv_judge::{
    AdapterSlot, FailureKind, JudgeOutcome, JudgeRunner, JudgeTask, PredicateRegistry, SessionContext,
    ARG_MATCHES_TASK,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

fn runner(judge: Arc<dyn pv_judge::JudgeAdapter>) -> JudgeRunner {
    let mut adapters = BTreeMap::new();
    adapters.insert(
        "local".to_owned(),
        AdapterSlot {
            adapter: judge,
            deadline: Duration::from_secs(5),
        },
    );
    JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), 4).unwrap()
}

async fn mismatch_ppm(runner: &JudgeRunner, args: serde_json::Value) -> u32 {
    let task = JudgeTask {
        predicate_id: ARG_MATCHES_TASK.to_owned(),
        adapter: "local".to_owned(),
    };
    let outcomes = runner
        .evaluate(&[task], "db_write", &args, &SessionContext::default())
        .await;
    match &outcomes[0] {
        JudgeOutcome::Scored(verdict) => verdict.ppm("mismatch").unwrap(),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_real_onnx_classifier_scores_through_the_runner() {
    let dir = tempfile::tempdir().unwrap();
    let judge = LocalOnnxJudge::load(&config(dir.path(), &model_bytes(false))).unwrap();
    let runner = runner(Arc::new(judge));
    assert!(mismatch_ppm(&runner, json!({"note": "danger"})).await > 999_000);
    let half = mismatch_ppm(&runner, json!({"note": "warn"})).await;
    assert!((499_000..=501_000).contains(&half), "{half}");
    assert!(mismatch_ppm(&runner, json!({"note": "fine"})).await < 1_000);
}

#[tokio::test]
async fn inputs_declared_in_another_order_bind_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let judge = LocalOnnxJudge::load(&config(dir.path(), &model_bytes(true))).unwrap();
    let runner = runner(Arc::new(judge));
    assert!(mismatch_ppm(&runner, json!({"note": "danger"})).await > 999_000);
}

#[test]
fn a_changed_model_file_refuses_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), &model_bytes(false));
    cfg.pin.weights_sha256 = "0".repeat(64);
    let error = LocalOnnxJudge::load(&cfg).err().unwrap();
    assert!(error.contains("hash mismatch"), "{error}");
    let mut cfg = config(dir.path(), &model_bytes(false));
    cfg.tokenizer_sha256 = "0".repeat(64);
    let error = LocalOnnxJudge::load(&cfg).err().unwrap();
    assert!(error.contains("tokenizer hash mismatch"), "{error}");
}

#[test]
fn a_model_with_the_wrong_number_of_outputs_is_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), &model_bytes(false));
    cfg.output_labels = vec!["a".into(), "b".into(), "c".into()];
    let judge = LocalOnnxJudge::load(&cfg).unwrap();
    let error = judge.classify("danger").unwrap_err();
    assert_eq!(error.kind(), FailureKind::Malformed);
}

#[tokio::test]
async fn labels_that_do_not_fit_the_predicate_fail_as_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), &model_bytes(false));
    cfg.output_labels = vec!["safe".into(), "unsafe".into()];
    let runner = runner(Arc::new(LocalOnnxJudge::load(&cfg).unwrap()));
    let outcomes = runner
        .evaluate(
            &[JudgeTask {
                predicate_id: ARG_MATCHES_TASK.to_owned(),
                adapter: "local".to_owned(),
            }],
            "t",
            &json!({}),
            &SessionContext::default(),
        )
        .await;
    assert!(matches!(&outcomes[0], JudgeOutcome::Failed(f) if f.kind == FailureKind::Malformed));
}

/// The committed model and tokenizer fixtures (used by the harness's
/// real-binary test) are exactly what the builder above produces. Run
/// with `PV_JUDGE_WRITE_FIXTURES=1` to regenerate them.
#[test]
fn committed_fixtures_match_the_builder() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let model = model_bytes(false);
    if std::env::var_os("PV_JUDGE_WRITE_FIXTURES").is_some() {
        std::fs::write(fixtures.join("toy_judge.onnx"), &model).unwrap();
        std::fs::write(fixtures.join("toy_tokenizer.json"), common::TOKENIZER).unwrap();
    }
    assert_eq!(std::fs::read(fixtures.join("toy_judge.onnx")).unwrap(), model);
    assert_eq!(
        std::fs::read_to_string(fixtures.join("toy_tokenizer.json")).unwrap(),
        common::TOKENIZER
    );
}

/// Padded arguments cannot push the operator's context out of a local
/// model's view: the context is rendered first and only the arguments'
/// tail is cut at the token limit.
#[tokio::test]
async fn a_request_longer_than_the_model_reads_is_not_judged() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), &model_bytes(false));
    cfg.max_input_tokens = 64;
    let runner = runner(Arc::new(LocalOnnxJudge::load(&cfg).unwrap()));
    let context = SessionContext {
        task: Some("refund order 1001".to_owned()),
        charter: "billing-agent".to_owned(),
        ..SessionContext::default()
    };
    let evaluate = |args: serde_json::Value| {
        let runner = &runner;
        let context = &context;
        async move {
            runner
                .evaluate(
                    &[JudgeTask {
                        predicate_id: ARG_MATCHES_TASK.to_owned(),
                        adapter: "local".to_owned(),
                    }],
                    "db_write",
                    &args,
                    context,
                )
                .await
                .remove(0)
        }
    };
    // Padding under an early key would push "danger" (the toy model's
    // trigger) past the token limit: the call fails instead of being
    // scored on its harmless start.
    let padded = json!({"a_note": "filler ".repeat(1_000), "z_table": "danger"});
    let JudgeOutcome::Failed(failure) = evaluate(padded).await else {
        panic!("a cut-off request must not be scored")
    };
    assert_eq!(failure.kind, FailureKind::Malformed, "{failure:?}");
    assert!(failure.detail.contains("cannot be judged in full"), "{failure:?}");
    // A request that fits is scored.
    assert!(matches!(
        evaluate(json!({"z_table": "danger"})).await,
        JudgeOutcome::Scored(_)
    ));
}
