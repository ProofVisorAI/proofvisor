//! The TypeSafe adapter's length check, which it makes after redaction:
//! redaction that shortens, lengthens to exactly the limit, lengthens one
//! character past it, writes multi-byte characters, or writes characters
//! that the rendering escapes.
#![cfg(feature = "cloud")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use axum::routing::post;
use axum::Router;
use parking_lot::Mutex;
use pv_judge::cloud::{RedactionTarget, Redactor};
use pv_judge::render::MAX_ARGUMENT_CHARS;
use pv_judge::typesafe::{TypeSafeJudge, TypeSafeJudgeConfig};
use pv_judge::{
    AdapterSlot, FailureKind, JudgeOutcome, JudgeRunner, JudgeTask, PredicateRegistry, SessionContext,
    ARG_MATCHES_TASK,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const VERSION: &str = "jev-1.14.0";

/// A stand-in that records every state it is sent and answers "match".
async fn stand_in() -> (String, Arc<Mutex<Vec<String>>>) {
    let states: Arc<Mutex<Vec<String>>> = Arc::default();
    let recorded = Arc::clone(&states);
    let router = Router::new().route(
        "/v1/systemone",
        post(move |axum::Json(body): axum::Json<Value>| {
            let recorded = Arc::clone(&recorded);
            async move {
                recorded
                    .lock()
                    .push(body["state"].as_str().unwrap_or_default().to_owned());
                axum::Json(json!({"model": VERSION, "answers": {"verdict": {"type": "choice",
                    "probabilities": {"match": 0.99, "mismatch": 0.01}}}}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}/v1/systemone"), states)
}

/// Replace every character `from` in string values of the arguments
/// with `to` (the context is left as it is).
fn replacing(from: char, to: &'static str) -> Redactor {
    fn walk(value: &mut Value, from: char, to: &str) {
        match value {
            Value::String(text) => *text = text.replace(from, to),
            Value::Array(items) => items.iter_mut().for_each(|item| walk(item, from, to)),
            Value::Object(map) => map.values_mut().for_each(|item| walk(item, from, to)),
            _ => {}
        }
    }
    Arc::new(move |value: &mut Value, target| {
        if target == RedactionTarget::Arguments {
            walk(value, from, to);
        }
    })
}

async fn judge(redactor: Redactor, arguments: Value) -> (JudgeOutcome, Vec<String>) {
    let (endpoint, states) = stand_in().await;
    let adapter = TypeSafeJudge::new(TypeSafeJudgeConfig {
        endpoint: url::Url::parse(&endpoint).unwrap(),
        api_key: zeroize::Zeroizing::new("ts-redaction-key".to_owned()),
        model_name: "jev".into(),
        model_version: VERSION.into(),
        timeout: Duration::from_secs(10),
    })
    .unwrap()
    .with_redactor(redactor);
    let mut adapters = BTreeMap::new();
    adapters.insert(
        "typesafe".to_owned(),
        AdapterSlot {
            adapter: Arc::new(adapter),
            deadline: Duration::from_secs(5),
        },
    );
    let runner = JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), 4).unwrap();
    let outcome = runner
        .evaluate(
            &[JudgeTask {
                predicate_id: ARG_MATCHES_TASK.to_owned(),
                adapter: "typesafe".to_owned(),
            }],
            "refund_order",
            &arguments,
            &SessionContext {
                charter: "billing-agent".into(),
                task: Some("Refund order 1001".into()),
                ..SessionContext::default()
            },
        )
        .await
        .remove(0);
    let sent = states.lock().clone();
    (outcome, sent)
}

fn arguments_line(state: &str) -> &str {
    state
        .lines()
        .find_map(|line| line.strip_prefix("arguments: "))
        .unwrap()
}

fn scored(outcome: &JudgeOutcome) -> bool {
    matches!(outcome, JudgeOutcome::Scored(_))
}

fn malformed(outcome: &JudgeOutcome) -> bool {
    matches!(outcome, JudgeOutcome::Failed(failure) if failure.kind == FailureKind::Malformed)
}

/// `{"v":"..."}` is 8 characters around the value.
const WRAPPER: usize = 8;

#[tokio::test]
async fn redaction_that_shortens_long_arguments_lets_them_be_sent() {
    let args = json!({"v": "s".repeat(MAX_ARGUMENT_CHARS)});
    let (outcome, sent) = judge(replacing('s', ""), args).await;
    assert!(scored(&outcome), "{outcome:?}");
    assert_eq!(sent.len(), 1);
    assert_eq!(arguments_line(&sent[0]), r#"{"v":""}"#);
}

#[tokio::test]
async fn redaction_to_exactly_the_limit_is_sent_whole_and_one_more_character_is_not_sent() {
    // Each "a" becomes "bb": 8 + 2 * 4092 = 8192 characters as rendered.
    let at = json!({"v": "a".repeat((MAX_ARGUMENT_CHARS - WRAPPER) / 2)});
    let (outcome, sent) = judge(replacing('a', "bb"), at).await;
    assert!(scored(&outcome), "{outcome:?}");
    let line = arguments_line(&sent[0]);
    assert_eq!(line.chars().count(), MAX_ARGUMENT_CHARS, "sent whole");
    assert!(line.ends_with("\"}"));
    // One character more after redaction.
    let over = json!({"v": format!("c{}", "a".repeat((MAX_ARGUMENT_CHARS - WRAPPER) / 2))});
    let (outcome, sent) = judge(replacing('a', "bb"), over).await;
    assert!(malformed(&outcome), "{outcome:?}");
    assert!(sent.is_empty(), "a call that cannot be read in full is not sent");
}

#[tokio::test]
async fn redaction_that_writes_four_byte_characters_counts_characters() {
    // 8,184 emoji (32,736 bytes) render as 8,192 characters: under the
    // limit, which counts characters.
    let args = json!({"v": "a".repeat(MAX_ARGUMENT_CHARS - WRAPPER)});
    let (outcome, sent) = judge(replacing('a', "😀"), args).await;
    assert!(scored(&outcome), "{outcome:?}");
    assert_eq!(arguments_line(&sent[0]).chars().count(), MAX_ARGUMENT_CHARS);
}

#[tokio::test]
async fn redaction_that_writes_escaped_characters_is_measured_as_rendered() {
    // Each U+2028 is rendered as the six characters  : 1,400 of them
    // are 8,408 characters, over the limit, though the value has 1,400.
    let args = json!({"v": "a".repeat(1_400)});
    let (outcome, sent) = judge(replacing('a', "\u{2028}"), args).await;
    assert!(malformed(&outcome), "{outcome:?}");
    assert!(sent.is_empty());
    // Quotes are escaped to two characters each: 4,092 of them render as
    // exactly the limit and are sent whole.
    let args = json!({"v": "a".repeat((MAX_ARGUMENT_CHARS - WRAPPER) / 2)});
    let (outcome, sent) = judge(replacing('a', "\""), args).await;
    assert!(scored(&outcome), "{outcome:?}");
    assert_eq!(arguments_line(&sent[0]).chars().count(), MAX_ARGUMENT_CHARS);
}

#[tokio::test]
async fn a_redactor_that_changes_the_arguments_type_is_measured_after() {
    // The redactor replaces the whole object by a long string.
    let redactor: Redactor = Arc::new(|value: &mut Value, target| {
        if target == RedactionTarget::Arguments {
            *value = Value::String("r".repeat(MAX_ARGUMENT_CHARS));
        }
    });
    let (outcome, sent) = judge(redactor, json!({"v": 1})).await;
    assert!(malformed(&outcome), "{outcome:?}");
    assert!(sent.is_empty());
}
