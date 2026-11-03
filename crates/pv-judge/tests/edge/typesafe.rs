//! Edge cases for the TypeSafe adapter against a local stand-in that
//! answers with raw bytes and arbitrary status codes.
#![cfg(feature = "cloud")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use axum::routing::post;
use axum::Router;
use pv_judge::typesafe::{TypeSafeJudge, TypeSafeJudgeConfig};
use pv_judge::{
    AdapterSlot, FailureKind, FailurePolicy, JudgeAction, JudgeOutcome, JudgeRunner, JudgeTask,
    PredicateRegistry, SessionContext, ThresholdPolicy, ARG_MATCHES_TASK,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const KEY: &str = "ts-test-key-0123456789";
const VERSION: &str = "jev-1.14.0";

/// Serve one fixed status, extra headers and raw body on every path.
async fn serve(status: u16, headers: Vec<(&'static str, String)>, body: Vec<u8>) -> String {
    let router = Router::new()
        .route(
            "/v1/systemone",
            post(move || {
                let headers = headers.clone();
                let body = body.clone();
                async move {
                    let mut response = (StatusCode::from_u16(status).unwrap(), body).into_response();
                    response
                        .headers_mut()
                        .insert("content-type", "application/json".parse().unwrap());
                    for (name, value) in headers {
                        response.headers_mut().insert(name, value.parse().unwrap());
                    }
                    response
                }
            }),
        )
        .route(
            "/elsewhere",
            post(|| async {
                axum::Json(json!({
                    "model": VERSION,
                    "answers": {"verdict": {"type": "choice", "probabilities": {"match": 0.99, "mismatch": 0.01}}}
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}/v1/systemone")
}

fn runner(endpoint: &str) -> JudgeRunner {
    let judge = TypeSafeJudge::new(TypeSafeJudgeConfig {
        endpoint: url::Url::parse(endpoint).unwrap(),
        api_key: zeroize::Zeroizing::new(KEY.to_owned()),
        model_name: "jev".into(),
        model_version: VERSION.into(),
        timeout: Duration::from_secs(10),
    })
    .unwrap();
    let mut adapters = BTreeMap::new();
    adapters.insert(
        "typesafe".to_owned(),
        AdapterSlot {
            adapter: Arc::new(judge),
            deadline: Duration::from_secs(5),
        },
    );
    JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), 4).unwrap()
}

async fn evaluate(endpoint: &str) -> JudgeOutcome {
    runner(endpoint)
        .evaluate(
            &[JudgeTask {
                predicate_id: ARG_MATCHES_TASK.to_owned(),
                adapter: "typesafe".to_owned(),
            }],
            "refund_order",
            &json!({"order_id": "1001"}),
            &SessionContext {
                charter: "billing-agent".into(),
                ..SessionContext::default()
            },
        )
        .await
        .remove(0)
}

async fn outcome_for(status: u16, body: &str) -> JudgeOutcome {
    evaluate(&serve(status, Vec::new(), body.as_bytes().to_vec()).await).await
}

fn answer(model: &str, probabilities: &str) -> String {
    format!(
        r#"{{"model": "{model}", "answers": {{"verdict": {{"type": "choice", "choice": "match", "probabilities": {probabilities}}}}}}}"#
    )
}

fn kind(outcome: &JudgeOutcome) -> Result<FailureKind, String> {
    match outcome {
        JudgeOutcome::Failed(failure) => Ok(failure.kind),
        JudgeOutcome::Scored(verdict) => Err(format!("scored {:?}", verdict.probs)),
    }
}

fn default_action(outcome: &JudgeOutcome) -> JudgeAction {
    ThresholdPolicy::new(Vec::new(), FailurePolicy::default())
        .unwrap()
        .decide(std::slice::from_ref(outcome), &|_| false)
        .action
}

#[tokio::test]
async fn a_valid_answer_is_scored() {
    let outcome = outcome_for(200, &answer(VERSION, r#"{"match": 0.2, "mismatch": 0.8}"#)).await;
    assert!(kind(&outcome).is_err(), "{outcome:?}");
}

#[tokio::test]
async fn extra_answer_ids_are_ignored() {
    let body = format!(
        r#"{{"model": "{VERSION}", "answers": {{"other": {{"type": "noul"}}, "verdict": {{"type": "choice", "probabilities": {{"match": 0.2, "mismatch": 0.8}}}}}}}}"#
    );
    let outcome = outcome_for(200, &body).await;
    assert!(kind(&outcome).is_err(), "{outcome:?}");
}

#[tokio::test]
async fn probabilities_as_strings_or_out_of_range_numbers_are_malformed() {
    for probabilities in [
        r#"{"match": "0.2", "mismatch": "0.8"}"#,
        r#"{"match": 1e400, "mismatch": 0}"#,
        r#"{"match": null, "mismatch": 1}"#,
        r#"[0.2, 0.8]"#,
    ] {
        let outcome = outcome_for(200, &answer(VERSION, probabilities)).await;
        assert_eq!(kind(&outcome), Ok(FailureKind::Malformed), "{probabilities}");
    }
}

#[tokio::test]
async fn label_keys_in_another_case_are_malformed() {
    let outcome = outcome_for(200, &answer(VERSION, r#"{"Match": 0.2, "MISMATCH": 0.8}"#)).await;
    assert_eq!(kind(&outcome), Ok(FailureKind::Malformed));
}

#[tokio::test]
async fn duplicate_label_keys_on_the_wire_are_malformed() {
    // The last value of each duplicated key flips the verdict from a
    // confident mismatch to a confident match.
    let probabilities = r#"{"mismatch": 0.95, "match": 0.05, "mismatch": 0.05, "match": 0.95}"#;
    let outcome = outcome_for(200, &answer(VERSION, probabilities)).await;
    assert_eq!(
        kind(&outcome),
        Ok(FailureKind::Malformed),
        "a duplicated label key must be malformed (typesafe.rs module docs: 'a missing, extra or \
         duplicate label is a malformed answer'), but serde's BTreeMap keeps the last value silently"
    );
}

#[tokio::test]
async fn a_duplicated_answer_id_is_malformed() {
    let body = format!(
        r#"{{"model": "{VERSION}", "answers": {{"verdict": {{"type": "choice", "probabilities": {{"match": 0.05, "mismatch": 0.95}}}}, "verdict": {{"type": "choice", "probabilities": {{"match": 0.95, "mismatch": 0.05}}}}}}}}"#
    );
    let outcome = outcome_for(200, &body).await;
    assert_eq!(
        kind(&outcome),
        Ok(FailureKind::Malformed),
        "two answers to the same question id are accepted, the last one silently wins"
    );
}

#[tokio::test]
async fn a_duplicated_model_key_is_refused() {
    // serde refuses a duplicate struct field; check it stays that way.
    let body = format!(
        r#"{{"model": "jev-1.13.0", "model": "{VERSION}", "answers": {{"verdict": {{"type": "choice", "probabilities": {{"match": 0.2, "mismatch": 0.8}}}}}}}}"#
    );
    let outcome = outcome_for(200, &body).await;
    assert!(kind(&outcome).is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn a_model_string_with_whitespace_is_a_mismatch_and_denies() {
    for model in [" jev-1.14.0", "jev-1.14.0 ", "jev-1.14.0\n", "JEV-1.14.0"] {
        let body = answer(&model.replace('\n', "\\n"), r#"{"match": 0.2, "mismatch": 0.8}"#);
        let outcome = outcome_for(200, &body).await;
        assert_eq!(kind(&outcome), Ok(FailureKind::ModelMismatch), "{model:?}");
        assert_eq!(default_action(&outcome), JudgeAction::Deny);
    }
}

#[tokio::test]
async fn non_200_success_statuses_are_unavailable_as_documented() {
    // CONFIGURATION.md: "Errors (401 key, 429 rate limit, 529 overload,
    // any other non-200) make the judge unavailable for that call".
    let valid = answer(VERSION, r#"{"match": 0.9, "mismatch": 0.1}"#);
    let mut problems = Vec::new();
    for (status, body) in [
        (201, valid.as_str()),
        (202, valid.as_str()),
        (203, valid.as_str()),
        (204, ""),
    ] {
        let outcome = outcome_for(status, body).await;
        let got = kind(&outcome);
        if got != Ok(FailureKind::Unavailable) {
            problems.push(format!(
                "HTTP {status}: expected unavailable (deny by default), got {got:?} ({:?} by default)",
                default_action(&outcome)
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    for status in [301, 302, 307, 308] {
        let endpoint = serve(status, vec![("location", "/elsewhere".to_owned())], Vec::new()).await;
        let outcome = evaluate(&endpoint).await;
        assert_eq!(kind(&outcome), Ok(FailureKind::Unavailable), "HTTP {status}");
    }
}

#[tokio::test]
async fn an_empty_or_non_json_200_body_is_malformed() {
    for body in ["", " ", "null", "{}", "<html>oops</html>"] {
        let outcome = outcome_for(200, body).await;
        assert_eq!(kind(&outcome), Ok(FailureKind::Malformed), "{body:?}");
    }
}

#[tokio::test]
async fn a_response_exactly_at_the_size_limit_is_read_and_one_byte_more_is_refused() {
    let limit = 64 * 1024;
    let core = answer(VERSION, r#"{"match": 0.2, "mismatch": 0.8}"#);
    // Pad with trailing JSON whitespace, which the parser accepts.
    let exact = format!("{core}{}", " ".repeat(limit - core.len()));
    assert_eq!(exact.len(), limit);
    let outcome = outcome_for(200, &exact).await;
    assert!(
        kind(&outcome).is_err(),
        "exactly 64 KiB must be read: {outcome:?}"
    );
    let over = format!("{exact} ");
    let outcome = outcome_for(200, &over).await;
    assert_eq!(kind(&outcome), Ok(FailureKind::Malformed));
}

#[tokio::test]
async fn a_huge_model_string_is_a_mismatch_and_the_record_detail_is_bounded() {
    let model = "j".repeat(60_000);
    let outcome = outcome_for(200, &answer(&model, r#"{"match": 0.2, "mismatch": 0.8}"#)).await;
    assert_eq!(kind(&outcome), Ok(FailureKind::ModelMismatch));
    let record = pv_judge::OutcomeRecord::from_outcome(&outcome, "typesafe", pv_judge::AdapterKind::Cloud);
    assert!(record.detail.unwrap().chars().count() <= 256);
}
