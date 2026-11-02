//! The cloud judge against a local HTTP server speaking the contract.
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
use pv_judge::cloud::{CloudJudge, CloudJudgeConfig};
use pv_judge::{
    AdapterSlot, FailureKind, JudgeOutcome, JudgeRunner, JudgeTask, ModelPin, PredicateRegistry,
    SessionContext, ARG_MATCHES_TASK,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Default)]
struct Seen {
    bodies: Arc<Mutex<Vec<Value>>>,
    auth: Arc<Mutex<Vec<Option<String>>>>,
}

fn pin() -> ModelPin {
    ModelPin::new("vendor-judge", "2026-10", "a".repeat(64)).unwrap()
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}/score")
}

fn runner(endpoint: &str, deadline: Duration, redact: bool) -> JudgeRunner {
    let mut judge = CloudJudge::new(CloudJudgeConfig {
        endpoint: url::Url::parse(endpoint).unwrap(),
        bearer: Some(zeroize::Zeroizing::new("judge-token".to_owned())),
        pin: pin(),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    if redact {
        judge = judge.with_redactor(Arc::new(|value: &mut Value| {
            if let Some(map) = value.as_object_mut() {
                if map.contains_key("secret") {
                    map.insert("secret".into(), json!("[REDACTED]"));
                }
            }
        }));
    }
    let mut adapters = BTreeMap::new();
    adapters.insert(
        "cloud".to_owned(),
        AdapterSlot {
            adapter: Arc::new(judge),
            deadline,
        },
    );
    JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), 4).unwrap()
}

async fn evaluate(runner: &JudgeRunner, args: Value) -> JudgeOutcome {
    runner
        .evaluate(
            &[JudgeTask {
                predicate_id: ARG_MATCHES_TASK.to_owned(),
                adapter: "cloud".to_owned(),
            }],
            "db_write",
            &args,
            &SessionContext {
                charter: "billing-agent".into(),
                ..SessionContext::default()
            },
        )
        .await
        .remove(0)
}

#[tokio::test]
async fn contract_round_trip_with_auth_and_redaction() {
    let seen = Seen::default();
    let router = Router::new()
        .route(
            "/score",
            post(|State(seen): State<Seen>, headers: HeaderMap, Json(body): Json<Value>| async move {
                seen.bodies.lock().push(body);
                seen.auth.lock().push(
                    headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned),
                );
                Json(json!({
                    "model": {"name": "vendor-judge", "version": "2026-10", "weights_sha256": "a".repeat(64)},
                    "probs": [{"label": "match", "p": 0.18}, {"label": "mismatch", "p": 0.82}],
                    "vendor_extra": "ignored"
                }))
            }),
        )
        .with_state(seen.clone());
    let endpoint = serve(router).await;
    let outcome = evaluate(
        &runner(&endpoint, Duration::from_secs(2), true),
        json!({"table": "t", "secret": "s3"}),
    )
    .await;
    let JudgeOutcome::Scored(verdict) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(verdict.ppm("mismatch"), Some(820_000));
    let body = seen.bodies.lock()[0].clone();
    assert_eq!(body["contract"], "proofvisor.judge.v1");
    assert_eq!(body["predicate"]["id"], ARG_MATCHES_TASK);
    assert_eq!(body["predicate"]["labels"], json!(["match", "mismatch"]));
    assert_eq!(body["arguments"], json!({"table": "t", "secret": "[REDACTED]"}));
    assert_eq!(body["context"]["charter"], "billing-agent");
    assert_eq!(seen.auth.lock()[0].as_deref(), Some("Bearer judge-token"));
}

#[tokio::test]
async fn failures_map_to_their_classes() {
    let router = Router::new()
        .route("/score", post(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
        .route(
            "/wrong-model",
            post(|| async {
                Json(json!({
                    "model": {"name": "vendor-judge", "version": "2026-11", "weights_sha256": "a".repeat(64)},
                    "probs": [{"label": "match", "p": 0.5}, {"label": "mismatch", "p": 0.5}]
                }))
            }),
        )
        .route("/garbage", post(|| async { "not json" }))
        .route(
            "/slow",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(3)).await;
                StatusCode::OK
            }),
        )
        .route(
            "/redirect",
            post(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/score")]) }),
        );
    let base = serve(router).await;
    let root = base.trim_end_matches("/score");
    let kind = |outcome: JudgeOutcome| match outcome {
        JudgeOutcome::Failed(failure) => {
            assert!(!failure.detail.contains("127.0.0.1"), "{}", failure.detail);
            failure.kind
        }
        other => panic!("{other:?}"),
    };
    let fast = Duration::from_secs(2);
    assert_eq!(
        kind(evaluate(&runner(&base, fast, false), json!({})).await),
        FailureKind::Unavailable
    );
    assert_eq!(
        kind(evaluate(&runner(&format!("{root}/wrong-model"), fast, false), json!({})).await),
        FailureKind::ModelMismatch
    );
    assert_eq!(
        kind(evaluate(&runner(&format!("{root}/garbage"), fast, false), json!({})).await),
        FailureKind::Malformed
    );
    assert_eq!(
        kind(evaluate(&runner(&format!("{root}/redirect"), fast, false), json!({})).await),
        FailureKind::Unavailable
    );
    assert_eq!(
        kind(
            evaluate(
                &runner(&format!("{root}/slow"), Duration::from_millis(100), false),
                json!({})
            )
            .await
        ),
        FailureKind::Timeout
    );
    // Nothing listening: a crashed judge.
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}/score")
    };
    assert_eq!(
        kind(evaluate(&runner(&dead, fast, false), json!({})).await),
        FailureKind::Unavailable
    );
}
