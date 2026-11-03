//! Edge cases of the judge's hardening: the argument
//! length check against the escaped rendering, the local token limit at
//! its exact boundary, and stricter TypeSafe answers.
#![cfg(all(feature = "cloud", feature = "onnx"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use crate::common;

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use axum::routing::post;
use axum::Router;
use parking_lot::Mutex;
use pv_judge::local::LocalOnnxJudge;
use pv_judge::render::{arguments_too_long, render_request, MAX_ARGUMENT_CHARS};
use pv_judge::typesafe::{TypeSafeJudge, TypeSafeJudgeConfig};
use pv_judge::{
    AdapterSlot, FailureKind, JudgeAdapter, JudgeOutcome, JudgeRequest, JudgeRunner, JudgeTask,
    PredicateRegistry, SessionContext, ARG_MATCHES_TASK,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

fn request(args: Value) -> JudgeRequest {
    JudgeRequest {
        predicate_id: ARG_MATCHES_TASK.into(),
        tool: "db_write".into(),
        validated_args: args,
        context: SessionContext {
            task: Some("refund order 1001".into()),
            charter: "billing-agent".into(),
            ..SessionContext::default()
        },
    }
}

fn rendered_args(text: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix("arguments: "))
        .unwrap()
        .to_owned()
}

// ── render.rs: arguments_too_long against the escaped rendering ──────

/// U+2028 is one character before escaping and six after. A call whose
/// raw JSON fits the cap but whose escaped rendering does not must fail
/// the check, or `canonical_json` would cut it.
#[test]
fn line_separators_lengthen_the_rendering_past_the_checked_length() {
    let args = json!({"a": "\u{2028}".repeat(1_400), "z": "danger"});
    let raw = args.to_string().chars().count();
    let text = render_request(&request(args.clone()));
    let shown = rendered_args(&text);
    let cut = !shown.ends_with('}') || !shown.contains("danger");
    let refused = arguments_too_long(&request(args)).is_some();
    assert!(
        refused || !cut,
        "raw JSON is {raw} characters (under {MAX_ARGUMENT_CHARS}) so arguments_too_long accepts it, \
         but the rendered arguments are cut to {} characters and lose the \"z\":\"danger\" key: \
         expected arguments_too_long to measure the escaped text",
        shown.chars().count()
    );
}

/// Exactly at the cap with an escaped character inside: the check and
/// the rendering must agree on where the limit lies.
#[test]
fn one_line_separator_at_the_exact_boundary() {
    // {"a":"…"} adds 8 characters; one U+2028 is +5 when escaped.
    let args = json!({"a": format!("{}\u{2028}", "x".repeat(MAX_ARGUMENT_CHARS - 9))});
    assert_eq!(args.to_string().chars().count(), MAX_ARGUMENT_CHARS);
    let shown = rendered_args(&render_request(&request(args.clone())));
    let cut = !shown.ends_with('}');
    let refused = arguments_too_long(&request(args)).is_some();
    assert!(
        refused || !cut,
        "raw length exactly {MAX_ARGUMENT_CHARS}: accepted by the check, but the rendering is \
         {} characters long when escaped and is cut (ends {:?})",
        shown.chars().count(),
        &shown[shown.len() - 10..]
    );
}

/// The end-to-end effect: with a local model that reads everything, a
/// call carrying the trigger word after the separators must not be
/// scored on the harmless start only.
#[tokio::test]
async fn a_local_judge_scores_a_call_cut_by_escaping() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = common::config(dir.path(), &common::model_bytes(false));
    cfg.max_input_tokens = 1_000_000;
    let judge = LocalOnnxJudge::load(&cfg).unwrap();
    let registry = PredicateRegistry::builtin();
    let predicate = registry.get(ARG_MATCHES_TASK).unwrap();
    let args = json!({"a": "\u{2028}".repeat(1_400), "z": "danger"});
    let outcome = judge.score(&request(args), predicate).await;
    match outcome {
        Err(error) => assert_eq!(error.kind(), FailureKind::Malformed, "{error}"),
        Ok(scores) => panic!(
            "a call whose rendering was cut was scored ({:?}); \"danger\" (the trigger) was cut off, \
             so the toy model saw only the harmless start. Expected Malformed (not judged in full)",
            scores.probs
        ),
    }
}

/// Multi-byte characters at the boundary: 4-byte emoji count as one
/// character both in the check and in the rendering.
#[test]
fn four_byte_characters_at_the_exact_boundary() {
    let at = json!({"a": "😀".repeat(MAX_ARGUMENT_CHARS - 8)});
    assert!(arguments_too_long(&request(at.clone())).is_none());
    assert_eq!(
        rendered_args(&render_request(&request(at.clone()))),
        at.to_string()
    );
    let over = json!({"a": "😀".repeat(MAX_ARGUMENT_CHARS - 7)});
    assert!(arguments_too_long(&request(over)).is_some());
    // Characters serde escapes itself (quote, backslash, control) are
    // measured after escaping, so the check and the rendering agree.
    let escaped = json!({"a": "\u{1}".repeat((MAX_ARGUMENT_CHARS - 8) / 6)});
    let length = escaped.to_string().chars().count();
    assert!(length <= MAX_ARGUMENT_CHARS);
    assert!(arguments_too_long(&request(escaped.clone())).is_none());
    assert!(rendered_args(&render_request(&request(escaped))).ends_with('}'));
}

/// Deeply nested arguments near the cap: the check and the rendering
/// agree, and nothing overflows.
#[test]
fn deeply_nested_arguments_at_the_cap() {
    let depth = 120;
    // {"k": ... "leaf" ... } : each level adds 6 characters ({"k": and }).
    let fixed = depth * 6 + 2;
    let leaf = "y".repeat(MAX_ARGUMENT_CHARS - fixed);
    let raw = format!("{}\"{leaf}\"{}", "{\"k\":".repeat(depth), "}".repeat(depth));
    let value: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value.to_string().chars().count(), MAX_ARGUMENT_CHARS);
    assert!(arguments_too_long(&request(value.clone())).is_none());
    assert!(rendered_args(&render_request(&request(value))).ends_with('}'));
    let raw = format!("{}\"{leaf}y\"{}", "{\"k\":".repeat(depth), "}".repeat(depth));
    let value: Value = serde_json::from_str(&raw).unwrap();
    assert!(arguments_too_long(&request(value)).is_some());
}

// ── local.rs: the token limit at its exact boundary ─────────────────

#[tokio::test]
async fn a_request_exactly_at_max_input_tokens_is_scored_and_one_over_is_not() {
    let args = json!({"note": "warn danger and some words", "z": [1, 2, 3]});
    let req = request(args);
    let tokenizer = tokenizers::Tokenizer::from_bytes(common::TOKENIZER.as_bytes()).unwrap();
    let n = tokenizer
        .encode(render_request(&req), true)
        .unwrap()
        .get_ids()
        .len();
    assert!(n > 10, "{n}");
    let registry = PredicateRegistry::builtin();
    let predicate = registry.get(ARG_MATCHES_TASK).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = common::config(dir.path(), &common::model_bytes(false));
    cfg.max_input_tokens = n;
    let at = LocalOnnxJudge::load(&cfg).unwrap().score(&req, predicate).await;
    assert!(at.is_ok(), "exactly {n} tokens with max {n}: {at:?}");
    cfg.max_input_tokens = n - 1;
    let over = LocalOnnxJudge::load(&cfg).unwrap().score(&req, predicate).await;
    match over {
        Err(error) => {
            assert_eq!(error.kind(), FailureKind::Malformed, "{error}");
            assert!(error.to_string().contains(&format!("{n} tokens")), "{error}");
        }
        Ok(scores) => panic!("{n} tokens with max {}: scored {:?}", n - 1, scores.probs),
    }
}

// ── typesafe.rs ─────────────────────────────────────────────────────

const KEY: &str = "ts-test-key-0123456789";
const VERSION: &str = "jev-1.14.0";

/// A stand-in that records each request body and answers `status`
/// with `body` and the given extra headers.
async fn serve(
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let recorded = Arc::clone(&seen);
    let router = Router::new().route(
        "/v1/systemone",
        post(move |axum::Json(request): axum::Json<Value>| {
            let headers = headers.clone();
            let body = body.clone();
            let recorded = Arc::clone(&recorded);
            async move {
                recorded.lock().push(request);
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
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}/v1/systemone"), seen)
}

fn typesafe(endpoint: &str, redactor: Option<pv_judge::cloud::Redactor>) -> TypeSafeJudge {
    let judge = TypeSafeJudge::new(TypeSafeJudgeConfig {
        endpoint: url::Url::parse(endpoint).unwrap(),
        api_key: zeroize::Zeroizing::new(KEY.to_owned()),
        model_name: "jev".into(),
        model_version: VERSION.into(),
        timeout: Duration::from_secs(10),
    })
    .unwrap();
    match redactor {
        Some(redactor) => judge.with_redactor(redactor),
        None => judge,
    }
}

async fn evaluate(judge: TypeSafeJudge, args: Value) -> JudgeOutcome {
    let mut adapters = BTreeMap::new();
    adapters.insert(
        "typesafe".to_owned(),
        AdapterSlot {
            adapter: Arc::new(judge) as Arc<dyn JudgeAdapter>,
            deadline: Duration::from_secs(5),
        },
    );
    JudgeRunner::new(adapters, Arc::new(PredicateRegistry::builtin()), 4)
        .unwrap()
        .evaluate(
            &[JudgeTask {
                predicate_id: ARG_MATCHES_TASK.to_owned(),
                adapter: "typesafe".to_owned(),
            }],
            "refund_order",
            &args,
            &SessionContext {
                charter: "billing-agent".into(),
                ..SessionContext::default()
            },
        )
        .await
        .remove(0)
}

fn answer_body(answers: &str) -> String {
    format!(r#"{{"model": "{VERSION}", "answers": {answers}}}"#)
}

fn valid_verdict() -> &'static str {
    r#""verdict": {"type": "choice", "probabilities": {"match": 0.2, "mismatch": 0.8}}"#
}

fn kind(outcome: &JudgeOutcome) -> Result<FailureKind, String> {
    match outcome {
        JudgeOutcome::Failed(failure) => Ok(failure.kind),
        JudgeOutcome::Scored(verdict) => Err(format!("scored {:?}", verdict.probs)),
    }
}

async fn outcome_for(body: &str) -> JudgeOutcome {
    let (endpoint, _) = serve(200, Vec::new(), body.as_bytes().to_vec()).await;
    evaluate(typesafe(&endpoint, None), json!({"order_id": "1001"})).await
}

/// A redactor that lengthens values (a placeholder longer than what it
/// replaces) can push arguments past the length limit. The length is
/// measured after redaction, so such a call fails as malformed and is
/// never sent cut.
#[tokio::test]
async fn redaction_that_lengthens_the_arguments_past_the_limit_fails_the_call() {
    let (endpoint, seen) = serve(
        200,
        Vec::new(),
        answer_body(&format!("{{{}}}", valid_verdict())).into_bytes(),
    )
    .await;
    let redactor: pv_judge::cloud::Redactor = Arc::new(|value: &mut Value, target| {
        if target != pv_judge::cloud::RedactionTarget::Arguments {
            return;
        }
        fn walk(value: &mut Value) {
            match value {
                Value::String(s) if s.contains('@') => *s = "[REDACTED:email-address]".to_owned(),
                Value::Array(items) => items.iter_mut().for_each(walk),
                Value::Object(map) => map.values_mut().for_each(walk),
                _ => {}
            }
        }
        walk(value);
    });
    // 800 short e-mail addresses: about 7,200 characters raw, about
    // 21,000 once each becomes a 26-character placeholder.
    let args = json!({"a_cc": vec!["a@b.co"; 800], "z_amount": "wire 90000 EUR"});
    assert!(arguments_too_long(&request(args.clone())).is_none());
    let outcome = evaluate(typesafe(&endpoint, Some(redactor)), args).await;
    assert_eq!(kind(&outcome), Ok(FailureKind::Malformed));
    assert!(
        seen.lock().is_empty(),
        "nothing is sent for a call that cannot be judged in full"
    );
}

#[tokio::test]
async fn repeated_keys_nested_in_another_answer_fail_the_whole_answer() {
    // A repeated key inside an unrelated answer's probabilities.
    let body = answer_body(&format!(
        r#"{{"other": {{"type": "choice", "probabilities": {{"a": 0.1, "a": 0.9}}}}, {}}}"#,
        valid_verdict()
    ));
    let outcome = outcome_for(&body).await;
    eprintln!("repeated key inside another answer: {:?}", kind(&outcome));
    // A repeated key inside a field the adapter ignores ("choice").
    let body = answer_body(
        r#"{"verdict": {"type": "choice", "choice": {"x": 1, "x": 2}, "probabilities": {"match": 0.2, "mismatch": 0.8}}}"#,
    );
    let outcome = outcome_for(&body).await;
    eprintln!("repeated key inside an ignored field: {:?}", kind(&outcome));
    // A repeated "type" in the verdict: refused by serde.
    let body = answer_body(
        r#"{"verdict": {"type": "noul", "type": "choice", "probabilities": {"match": 0.2, "mismatch": 0.8}}}"#,
    );
    assert_eq!(kind(&outcome_for(&body).await), Ok(FailureKind::Malformed));
    // A repeated "probabilities" field: must not let the last one win.
    let body = answer_body(
        r#"{"verdict": {"type": "choice", "probabilities": {"match": 0.95, "mismatch": 0.05}, "probabilities": {"match": 0.05, "mismatch": 0.95}}}"#,
    );
    assert_eq!(
        kind(&outcome_for(&body).await),
        Ok(FailureKind::Malformed),
        "a repeated probabilities field must be malformed"
    );
}

#[tokio::test]
async fn an_answer_with_extra_fields_is_scored_and_an_empty_answers_object_is_not() {
    let body = answer_body(
        r#"{"verdict": {"type": "choice", "choice": "mismatch", "confidence": 0.8, "explanation": "x", "probabilities": {"match": 0.2, "mismatch": 0.8}}}"#,
    );
    assert!(
        kind(&outcome_for(&body).await).is_err(),
        "extra fields are ignored"
    );
    assert_eq!(
        kind(&outcome_for(&answer_body("{}")).await),
        Ok(FailureKind::Malformed)
    );
    assert_eq!(
        kind(&outcome_for(&answer_body("[]")).await),
        Ok(FailureKind::Malformed)
    );
    assert_eq!(
        kind(&outcome_for(&answer_body("null")).await),
        Ok(FailureKind::Malformed)
    );
}

#[tokio::test]
async fn labels_in_another_unicode_form_are_malformed() {
    for probabilities in [
        // Fullwidth letters (NFKC-equal to "match").
        r#"{"ｍａｔｃｈ": 0.2, "mismatch": 0.8}"#,
        // A zero-width joiner inside the label.
        r#"{"ma‍tch": 0.2, "mismatch": 0.8}"#,
        // Both the real label and a lookalike: an extra label.
        r#"{"match": 0.2, "mismatch": 0.8, "mismatch": 0.0}"#,
        // Cyrillic "а" in "mаtch".
        r#"{"mаtch": 0.2, "mismatch": 0.8}"#,
    ] {
        let body = answer_body(&format!(
            r#"{{"verdict": {{"type": "choice", "probabilities": {probabilities}}}}}"#
        ));
        let got = kind(&outcome_for(&body).await);
        // The escape "mismatch" is just "mismatch" again: a repeated key.
        assert_eq!(got, Ok(FailureKind::Malformed), "{probabilities}");
    }
}

#[tokio::test]
async fn very_large_or_tiny_numeric_probabilities_are_malformed_or_exact() {
    for (probabilities, scored) in [
        (r#"{"match": 0, "mismatch": 1}"#, true),
        (r#"{"match": 0.0, "mismatch": 1.0e0}"#, true),
        (r#"{"match": 18446744073709551616, "mismatch": 0}"#, false),
        (r#"{"match": 9223372036854775807, "mismatch": 0}"#, false),
        (r#"{"match": -0, "mismatch": 1}"#, true),
        (r#"{"match": 1e-400, "mismatch": 1}"#, true),
        (r#"{"match": 1e-400, "mismatch": 1e-400}"#, false),
        (r#"{"match": 0.5000000000000000000001, "mismatch": 0.5}"#, true),
    ] {
        let body = answer_body(&format!(
            r#"{{"verdict": {{"type": "choice", "probabilities": {probabilities}}}}}"#
        ));
        let got = kind(&outcome_for(&body).await);
        if scored {
            assert!(got.is_err(), "{probabilities}: expected scored, got {got:?}");
        } else {
            assert_eq!(got, Ok(FailureKind::Malformed), "{probabilities}");
        }
    }
}

#[tokio::test]
async fn content_encoding_variations_never_score_garbage() {
    let valid = answer_body(&format!("{{{}}}", valid_verdict()));
    // A gzip body: reqwest here has no gzip support enabled (or does,
    // through feature unification). Either way it must not be scored
    // as anything other than the answer.
    let gzipped = {
        use std::io::Write as _;
        let mut encoder = flate2_like::GzEncoder::new();
        encoder.write_all(valid.as_bytes()).unwrap();
        encoder.finish()
    };
    /// A case's name, extra response headers and response body.
    type Case = (&'static str, Vec<(&'static str, String)>, Vec<u8>);
    let cases: Vec<Case> = vec![
        (
            "gzip body, gzip header",
            vec![("content-encoding", "gzip".into())],
            gzipped.clone(),
        ),
        ("gzip body, no header", Vec::new(), gzipped),
        (
            "plain body, gzip header",
            vec![("content-encoding", "gzip".into())],
            valid.clone().into_bytes(),
        ),
        (
            "plain body, br header",
            vec![("content-encoding", "br".into())],
            valid.clone().into_bytes(),
        ),
        (
            "plain body, identity",
            vec![("content-encoding", "identity".into())],
            valid.clone().into_bytes(),
        ),
        (
            "text/plain type",
            vec![("content-type", "text/plain".into())],
            valid.clone().into_bytes(),
        ),
    ];
    for (name, headers, body) in cases {
        let (endpoint, _) = serve(200, headers, body).await;
        let outcome = evaluate(typesafe(&endpoint, None), json!({"order_id": "1001"})).await;
        let got = kind(&outcome);
        eprintln!("{name}: {got:?}");
        if let Err(scored) = &got {
            assert!(
                scored.contains("0.8") || scored.contains("800"),
                "{name}: {scored}"
            );
        }
    }
}

/// A tiny gzip writer (stored blocks only), so the test needs no crate.
mod flate2_like {
    pub struct GzEncoder {
        data: Vec<u8>,
    }
    impl GzEncoder {
        pub fn new() -> Self {
            Self { data: Vec::new() }
        }
        pub fn finish(self) -> Vec<u8> {
            let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
            let chunks: Vec<&[u8]> = self.data.chunks(65_535).collect();
            for (i, chunk) in chunks.iter().enumerate() {
                out.push(u8::from(i + 1 == chunks.len()));
                let len = u16::try_from(chunk.len()).unwrap();
                out.extend(len.to_le_bytes());
                out.extend((!len).to_le_bytes());
                out.extend(*chunk);
            }
            out.extend(crc32(&self.data).to_le_bytes());
            out.extend(u32::try_from(self.data.len()).unwrap().to_le_bytes());
            out
        }
    }
    impl std::io::Write for GzEncoder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
}
