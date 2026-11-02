//! The TypeSafe judge against a local server speaking TypeSafe's
//! documented System One wire format, and (when a key file is given)
//! against the live API.
#![cfg(feature = "cloud")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use parking_lot::Mutex;
use pv_judge::typesafe::{derived_weights_sha256, TypeSafeJudge, TypeSafeJudgeConfig};
use pv_judge::{
    AdapterSlot, FailureKind, JudgeOutcome, JudgeRunner, JudgeTask, PredicateRegistry, SessionContext,
    ARG_MATCHES_TASK,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const KEY: &str = "ts-test-key-0123456789";
const VERSION: &str = "jev-1.14.0";
const IBAN: &str = "DE89370400440532013000";

/// What the stand-in received.
#[derive(Clone, Default)]
struct Seen {
    bodies: Arc<Mutex<Vec<Value>>>,
    headers: Arc<Mutex<Vec<HeaderMap>>>,
}

/// How the stand-in answers.
#[derive(Clone)]
enum Answer {
    /// A choice answer with these probabilities, reported by `model`.
    Choice(&'static str, Value),
    /// A bare status code.
    Status(u16),
    /// Valid JSON in another shape.
    Shape(Value),
    /// A body larger than the adapter accepts.
    Huge,
    /// No answer before the deadline.
    Slow,
}

async fn serve(answer: Answer, seen: Seen) -> String {
    let router = Router::new()
        .route(
            "/v1/systemone",
            post(
                |State((answer, seen)): State<(Answer, Seen)>,
                 headers: HeaderMap,
                 Json(body): Json<Value>| async move {
                    seen.bodies.lock().push(body.clone());
                    seen.headers.lock().push(headers);
                    match answer {
                        Answer::Choice(model, probabilities) => {
                            let choice = probabilities
                                .as_object()
                                .and_then(|map| {
                                    map.iter()
                                        .max_by(|a, b| a.1.as_f64().partial_cmp(&b.1.as_f64()).unwrap())
                                        .map(|(label, _)| label.clone())
                                })
                                .unwrap_or_default();
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "model": model,
                                    "answers": {"verdict": {
                                        "type": "choice", "choice": choice,
                                        "confidence": 0.9, "probabilities": probabilities
                                    }},
                                    "usage": {"input_tokens": 120, "output_tokens": 1}
                                })),
                            )
                        }
                        Answer::Status(code) => (
                            StatusCode::from_u16(code).unwrap(),
                            Json(json!({"detail": format!("echo of input {IBAN}")})),
                        ),
                        Answer::Shape(value) => (StatusCode::OK, Json(value)),
                        Answer::Huge => (StatusCode::OK, Json(json!({"pad": "x".repeat(70 * 1024)}))),
                        Answer::Slow => {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            (StatusCode::OK, Json(json!({})))
                        }
                    }
                },
            ),
        )
        .with_state((answer, seen));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}/v1/systemone")
}

fn runner(endpoint: &str, key: &str, deadline: Duration) -> JudgeRunner {
    let judge = TypeSafeJudge::new(TypeSafeJudgeConfig {
        endpoint: url::Url::parse(endpoint).unwrap(),
        api_key: zeroize::Zeroizing::new(key.to_owned()),
        model_name: "jev".into(),
        model_version: VERSION.into(),
        timeout: Duration::from_secs(30),
    })
    .unwrap()
    .with_redactor(Arc::new(|value: &mut Value, _| redact(value)));
    let mut adapters = BTreeMap::new();
    adapters.insert(
        "typesafe".to_owned(),
        AdapterSlot {
            adapter: Arc::new(judge),
            deadline,
        },
    );
    JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), 4).unwrap()
}

/// Replace the IBAN wherever it appears, as the harness redaction would.
fn redact(value: &mut Value) {
    match value {
        Value::String(text) if text.contains(IBAN) => *text = text.replace(IBAN, "[REDACTED]"),
        Value::Array(items) => items.iter_mut().for_each(redact),
        Value::Object(map) => map.values_mut().for_each(redact),
        _ => {}
    }
}

async fn evaluate(runner: &JudgeRunner, args: Value) -> JudgeOutcome {
    runner
        .evaluate(
            &[JudgeTask {
                predicate_id: ARG_MATCHES_TASK.to_owned(),
                adapter: "typesafe".to_owned(),
            }],
            "refund_order",
            &args,
            &SessionContext {
                intent: Some("billing.refund".into()),
                task: Some("Refund order 1001 up to 200 EUR".into()),
                charter: "billing-agent".into(),
                ..SessionContext::default()
            },
        )
        .await
        .remove(0)
}

fn failure(outcome: &JudgeOutcome) -> (FailureKind, String) {
    match outcome {
        JudgeOutcome::Failed(failure) => (failure.kind, failure.detail.clone()),
        JudgeOutcome::Scored(verdict) => panic!("expected a failure, got {verdict:?}"),
    }
}

#[tokio::test]
async fn a_round_trip_sends_the_documented_request_and_reads_the_choice() {
    let seen = Seen::default();
    let endpoint = serve(
        Answer::Choice(VERSION, json!({"match": 0.18, "mismatch": 0.82})),
        seen.clone(),
    )
    .await;
    let runner = runner(&endpoint, KEY, Duration::from_secs(5));
    let outcome = evaluate(
        &runner,
        json!({"order_id": "1001", "iban": IBAN, "amount_eur": 4800}),
    )
    .await;
    let JudgeOutcome::Scored(verdict) = outcome else {
        panic!("expected a verdict, got {outcome:?}")
    };
    assert_eq!(verdict.ppm("mismatch"), Some(820_000));
    assert_eq!(verdict.model.version, VERSION);
    assert_eq!(verdict.model.weights_sha256, derived_weights_sha256(VERSION));

    let body = seen.bodies.lock()[0].clone();
    let headers = seen.headers.lock()[0].clone();
    assert_eq!(headers["authorization"], format!("Bearer {KEY}"));
    assert!(
        headers
            .keys()
            .all(|name| !name.as_str().starts_with("typesafe-danger-zone")),
        "no header that widens what TypeSafe accepts"
    );
    assert_eq!(body["model"], VERSION, "the pinned release, never an alias");
    let question = &body["questions"]["verdict"];
    assert_eq!(question["type"], "choice");
    assert_eq!(question["criteria"], json!({"match": null, "mismatch": null}));
    assert!(question["instructions"]
        .as_str()
        .unwrap()
        .contains("fit the task"));
    let state = body["state"].as_str().unwrap();
    let task_at = state.find("task: Refund order 1001").expect("the task is sent");
    let arguments_at = state.find("arguments: ").expect("the arguments are sent");
    assert!(task_at < arguments_at, "context first, arguments last");
    assert!(!state.contains(IBAN), "redacted before it leaves");
    assert!(state.contains("[REDACTED]"));
}

#[tokio::test]
async fn arguments_longer_than_the_judge_reads_are_not_sent() {
    let seen = Seen::default();
    let endpoint = serve(
        Answer::Choice(VERSION, json!({"match": 0.9, "mismatch": 0.1})),
        seen.clone(),
    )
    .await;
    let runner = runner(&endpoint, KEY, Duration::from_secs(5));
    // Sorted keys: padding under "a_note" would push "z_table" out of
    // the rendered state. The call fails instead of being judged on its
    // harmless start, and nothing is sent.
    let padded = json!({"a_note": "pad ".repeat(100_000), "z_table": "secrets"});
    let (kind, detail) = failure(&evaluate(&runner, padded).await);
    assert_eq!(kind, FailureKind::Malformed, "{detail}");
    assert!(detail.contains("cannot be judged in full"), "{detail}");
    assert!(
        seen.bodies.lock().is_empty(),
        "nothing may be sent for a call it cannot judge"
    );
}

#[tokio::test]
async fn every_bad_answer_is_a_failure_never_a_partial_verdict() {
    let cases: Vec<(Answer, FailureKind)> = vec![
        // Another release answered.
        (
            Answer::Choice("jev-1.13.0", json!({"match": 0.9, "mismatch": 0.1})),
            FailureKind::ModelMismatch,
        ),
        // A label is missing, or one the predicate does not have is added.
        (
            Answer::Choice(VERSION, json!({"match": 1.0})),
            FailureKind::Malformed,
        ),
        (
            Answer::Choice(VERSION, json!({"match": 0.5, "mismatch": 0.3, "maybe": 0.2})),
            FailureKind::Malformed,
        ),
        // Not a distribution.
        (
            Answer::Choice(VERSION, json!({"match": 0.9, "mismatch": 0.9})),
            FailureKind::Malformed,
        ),
        // Other shapes.
        (
            Answer::Shape(json!({"model": VERSION, "answers": {}, "usage": {}})),
            FailureKind::Malformed,
        ),
        (
            Answer::Shape(json!({"model": VERSION, "answers": {"verdict": {"type": "noul", "noul": 0.2}}})),
            FailureKind::Malformed,
        ),
        (Answer::Huge, FailureKind::Malformed),
        // Key, rate limit, overload, validation, server errors.
        (Answer::Status(401), FailureKind::Unavailable),
        (Answer::Status(429), FailureKind::Unavailable),
        (Answer::Status(529), FailureKind::Unavailable),
        (Answer::Status(422), FailureKind::Unavailable),
        (Answer::Status(500), FailureKind::Unavailable),
        (Answer::Slow, FailureKind::Timeout),
    ];
    for (answer, expected) in cases {
        let label = match &answer {
            Answer::Status(code) => format!("HTTP {code}"),
            Answer::Choice(model, probs) => format!("{model} {probs}"),
            Answer::Shape(value) => value.to_string(),
            Answer::Huge => "huge".into(),
            Answer::Slow => "slow".into(),
        };
        let endpoint = serve(answer, Seen::default()).await;
        let runner = runner(&endpoint, KEY, Duration::from_millis(1_000));
        let (kind, detail) = failure(&evaluate(&runner, json!({"order_id": "1001"})).await);
        assert_eq!(kind, expected, "{label}: {detail}");
        for secret in [KEY, IBAN, endpoint.as_str()] {
            assert!(
                !detail.contains(secret),
                "{label}: the failure detail leaks {secret:?}: {detail}"
            );
        }
    }
}

#[test]
fn aliases_empty_keys_and_plain_http_are_refused() {
    let build = |endpoint: &str, key: &str, version: &str| {
        TypeSafeJudge::new(TypeSafeJudgeConfig {
            endpoint: url::Url::parse(endpoint).unwrap(),
            api_key: zeroize::Zeroizing::new(key.to_owned()),
            model_name: "jev".into(),
            model_version: version.into(),
            timeout: Duration::from_secs(1),
        })
    };
    assert!(build(pv_judge::typesafe::DEFAULT_ENDPOINT, KEY, VERSION).is_ok());
    for alias in ["jev-latest", "jev-preview"] {
        let error = build(pv_judge::typesafe::DEFAULT_ENDPOINT, KEY, alias)
            .err()
            .unwrap();
        assert!(error.contains("not a fixed release"), "{error}");
    }
    assert!(build(pv_judge::typesafe::DEFAULT_ENDPOINT, "  ", VERSION).is_err());
    // A key file holding more than the key: a second line, a label, a
    // pasted character outside ASCII.
    for key in [
        "ts_key\nsecond line",
        "export TYPESAFE_API_KEY=ts_key",
        "ts_\u{2026}",
    ] {
        let error = build(pv_judge::typesafe::DEFAULT_ENDPOINT, key, VERSION)
            .err()
            .unwrap();
        assert!(error.contains("hold more than the key"), "{key:?}: {error}");
    }
    assert!(build("http://api.typesafe.ai/v1/systemone", KEY, VERSION).is_err());
}

/// The live API, when `PV_TYPESAFE_API_KEY_FILE` names a file holding a
/// key. It sends one benign, synthetic call and checks the answer has
/// the documented shape and the pinned release.
#[tokio::test]
async fn the_live_api_answers_a_pinned_choice() {
    let Ok(path) = std::env::var("PV_TYPESAFE_API_KEY_FILE") else {
        eprintln!("SKIPPED (PV_TYPESAFE_API_KEY_FILE unset): needs a TypeSafe API key");
        return;
    };
    let key = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("PV_TYPESAFE_API_KEY_FILE={path} cannot be read: {error}"));
    assert!(
        !key.trim().is_empty(),
        "PV_TYPESAFE_API_KEY_FILE={path} is empty: put the API key in it"
    );
    let runner = runner(
        pv_judge::typesafe::DEFAULT_ENDPOINT,
        key.trim(),
        Duration::from_secs(20),
    );
    match evaluate(&runner, json!({"order_id": "1001", "amount_eur": 45})).await {
        JudgeOutcome::Scored(verdict) => {
            assert_eq!(verdict.model.version, VERSION);
            let total: u32 = verdict.probs.iter().map(|p| p.ppm).sum();
            assert!((990_000..=1_010_000).contains(&total), "{verdict:?}");
        }
        JudgeOutcome::Failed(failure) => panic!("live TypeSafe call failed: {failure:?}"),
    }
}
