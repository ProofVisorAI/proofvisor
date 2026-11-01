//! Console-pushed guardrails over model responses and console-pushed
//! transforms, end to end through the live router:
//!
//! * a buffered response that matches an `llm.egress` deny pattern is
//!   refused with HTTP 403 naming the policy, and nothing of it reaches
//!   the client;
//! * a streamed response that matches in its first frame is refused the
//!   same way, and one that matches later is cut at the matching frame
//!   with an error frame, the matched text never relayed;
//! * an `llm.ingress` transform rewrites the chat request before it is
//!   forwarded, and the compression record says which policy rewrote it;
//! * a `tool.args` transform rewrites the arguments before the backend
//!   sees them;
//! * a pushed token budget that the provider's completion overflows is
//!   refused naming the console policy, as the admission-time check does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::response::IntoResponse;
use pv_harness::policy_push::PolicyPush;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{tools_call, RecordingBus};

type Request = axum::http::Request<axum::body::Body>;

const CODENAME: &str = "Project Nightjar";

/// A chat upstream that answers from the last user message: a prompt
/// that mentions the codename gets it back, spread over several frames
/// when streaming so the match straddles a frame boundary; "early" puts
/// it in the first frame; "overspend" reports a completion far over any
/// pushed cap; anything else gets "ok". Every request body is recorded.
async fn chat_upstream() -> (String, Arc<Mutex<Vec<Value>>>) {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let recorded = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |request: Request| {
        let recorded = Arc::clone(&recorded);
        async move {
            let (_parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 22).await.unwrap();
            let request: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            recorded.lock().unwrap().push(request.clone());
            let prompt = request["messages"]
                .as_array()
                .and_then(|messages| messages.last())
                .and_then(|message| message["content"].as_str())
                .unwrap_or_default()
                .to_owned();
            let stream = request["stream"] == true;
            let (frames, completion_tokens): (Vec<String>, u64) = if prompt.contains("early") {
                (vec![format!("{CODENAME} is the codename.")], 6)
            } else if prompt.contains("codename") {
                (
                    vec![
                        "Sure. ".to_owned(),
                        "Let me think. ".to_owned(),
                        "The answer is Project ".to_owned(),
                        "Nightjar, as noted.".to_owned(),
                    ],
                    9,
                )
            } else if prompt.contains("overspend") {
                (vec!["a very long answer".to_owned()], 500)
            } else {
                (vec!["ok".to_owned()], 1)
            };
            if stream {
                // One network chunk per frame, with a pause between them,
                // so the relay sees the frames the way a real provider
                // sends them and can only act on what has arrived.
                let mut chunks: Vec<String> = frames
                    .iter()
                    .map(|text| {
                        format!(
                            "data: {}\n\n",
                            json!({"id": "c", "object": "chat.completion.chunk", "model": "m",
                                   "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}]})
                        )
                    })
                    .collect();
                chunks.push(format!(
                    "data: {}\n\n",
                    json!({"id": "c", "object": "chat.completion.chunk", "model": "m",
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 10, "completion_tokens": completion_tokens, "total_tokens": 10 + completion_tokens}})
                ));
                chunks.push("data: [DONE]\n\n".to_owned());
                let stream = futures::StreamExt::then(futures::stream::iter(chunks), |chunk| async move {
                    tokio::time::sleep(Duration::from_millis(15)).await;
                    Ok::<_, std::io::Error>(chunk)
                });
                let mut response = axum::response::Response::new(axum::body::Body::from_stream(stream));
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("text/event-stream"),
                );
                return response;
            }
            axum::Json(json!({
                "id": "c", "object": "chat.completion", "created": 1, "model": "m",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": frames.concat()}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": completion_tokens, "total_tokens": 10 + completion_tokens}
            }))
            .into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, seen)
}

fn policy(id: &str, name: &str, kind: &str, scope: &str, spec: Value) -> Value {
    json!({"id": id, "name": name, "kind": kind, "scope": scope, "enabled": true,
           "updatedAt": "2026-11-01T00:00:00.000Z", "spec": spec, "body": spec.to_string()})
}

struct Harness {
    state: Arc<pv_harness::AppState>,
    bus: Arc<RecordingBus>,
    upstream_seen: Arc<Mutex<Vec<Value>>>,
    backend: common::MockBackend,
    _dir: tempfile::TempDir,
}

/// A gateway with the bundle `pvctl console-sync --pull-policies` would
/// write: an egress guardrail, two transforms and a token budget.
async fn harness() -> Harness {
    let (url, upstream_seen) = chat_upstream().await;
    let backend = common::MockBackend::start().await;
    let dir = tempfile::tempdir().unwrap();
    let bus = Arc::new(RecordingBus::default());
    let mut config = common::leaked_test_config();
    config.upstream_url = url;
    config.tool_upstream_url = Some(backend.url.clone());
    config.breaker.min_tokens = u64::MAX;
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state(
        config,
        sandbox,
        Arc::clone(&bus) as Arc<dyn pv_bridge::EventBus>,
        7,
    );

    let bundle = json!({"version": 1, "etag": "beef", "policies": [
        policy("g-egress", "privacy.no_codenames", "guardrail", "llm.egress",
               json!({"applies_to": "llm.egress", "deny_patterns": ["(?i)project\\s+nightjar"], "effect": "block"})),
        policy("t-chat", "privacy.redact_tickets", "transform", "llm.request",
               json!({"applies_to": "llm.ingress", "redact_patterns": ["TCK-[0-9]{4}"], "replacement": "[ticket]"})),
        policy("t-tool", "privacy.redact_codenames", "transform", "tool.create_*",
               json!({"applies_to": "tool.args", "redact_patterns": ["(?i)nightjar"]})),
        policy("b-tokens", "llm.token_cap", "budget", "tool.*", json!({"max_tokens": 120})),
    ]});
    let path = dir.path().join("policies.json");
    pv_core::fsutil::write_atomic(&path, &serde_json::to_vec(&bundle).unwrap()).unwrap();
    let push = PolicyPush::new(path, Arc::clone(&state.sandbox), Arc::clone(&state.pushed_rates));
    let status = push.load_at_boot().unwrap().expect("the bundle applies at boot");
    assert!(status.unsupported.is_empty(), "{:?}", status.unsupported);
    assert_eq!(status.applied, vec!["g-egress", "t-chat", "t-tool", "b-tokens"]);
    Harness {
        state,
        bus,
        upstream_seen,
        backend,
        _dir: dir,
    }
}

fn chat_request(session: &str, text: &str, stream: bool) -> Request {
    let payload = json!({"model": "m", "stream": stream, "messages": [{"role": "user", "content": text}]});
    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-pv-session", session)
        .header("x-pv-workflow", "unsigned")
        .body(axum::body::Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap()
}

struct Reply {
    status: axum::http::StatusCode,
    body: String,
}

async fn send(state: &Arc<pv_harness::AppState>, request: Request) -> Reply {
    let router = pv_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 22).await.unwrap();
    Reply {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// The first stop-reason event attributed to `policy`, waiting for the
/// worker to publish it.
async fn attributed_stop(bus: &RecordingBus, policy: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = bus.payloads.lock().iter().find_map(|event| {
            let payload = event.get("payload")?;
            (payload.get("policy")?.as_str()? == policy).then(|| payload.clone())
        });
        if let Some(found) = found {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "no stop-reason event attributed to {policy}: {:?}",
            bus.payloads.lock()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_response_matching_an_egress_guardrail_is_refused_naming_the_policy() {
    let h = harness().await;
    let refused = send(
        &h.state,
        chat_request("egress-buffered", "what is the codename?", false),
    )
    .await;
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert!(
        refused.body.contains("privacy.no_codenames")
            && refused
                .body
                .contains("model response matches deny pattern 1 of 1"),
        "{}",
        refused.body
    );
    assert!(
        !refused.body.contains("Nightjar"),
        "the matched text never reaches the client: {}",
        refused.body
    );

    let stop = attributed_stop(&h.bus, "privacy.no_codenames").await;
    assert_eq!(stop["direction"], "upstream_response", "{stop}");
    assert!(
        stop["reason"].as_str().unwrap().contains("privacy.no_codenames"),
        "{stop}"
    );

    // The same session keeps working, and a clean answer passes.
    let fine = send(
        &h.state,
        chat_request("egress-buffered", "what time is it?", false),
    )
    .await;
    assert_eq!(fine.status, 200, "{}", fine.body);
    assert!(fine.body.contains("\"ok\""), "{}", fine.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_response_matching_in_its_first_frame_is_refused_before_any_byte() {
    let h = harness().await;
    let refused = send(
        &h.state,
        chat_request("egress-early", "early codename please", true),
    )
    .await;
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert!(refused.body.contains("privacy.no_codenames"), "{}", refused.body);
    assert!(!refused.body.contains("Nightjar"), "{}", refused.body);
    attributed_stop(&h.bus, "privacy.no_codenames").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_response_matching_later_is_cut_at_the_matching_frame() {
    let h = harness().await;
    let cut = send(
        &h.state,
        chat_request("egress-mid", "what is the codename?", true),
    )
    .await;
    // The status line went out with the first clean frames; the stream
    // then ends with an error frame instead of the matching text.
    assert_eq!(cut.status, 200, "{}", cut.body);
    assert!(
        cut.body.contains("\"content\":\"Sure. \""),
        "clean frames are relayed: {}",
        cut.body
    );
    assert!(cut.body.contains("Let me think."), "{}", cut.body);
    // The frame that completes the match is withheld. The one before it
    // was already relayed: the match only exists once both have arrived,
    // which is why the scan overlaps frames and the audit still refuses
    // the turn as a whole.
    assert!(
        cut.body.contains("The answer is Project ") && !cut.body.contains("Nightjar"),
        "the frame completing the match is withheld: {}",
        cut.body
    );
    assert!(
        cut.body.contains("\"code\":\"guardrail\"") && cut.body.contains("privacy.no_codenames"),
        "the stream ends with an error frame naming the policy: {}",
        cut.body
    );
    assert!(
        !cut.body.contains("[DONE]"),
        "no clean end marker after a refusal: {}",
        cut.body
    );
    let stop = attributed_stop(&h.bus, "privacy.no_codenames").await;
    assert!(
        stop["reason"].as_str().unwrap().contains("deny pattern 1 of 1"),
        "{stop}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ingress_transform_rewrites_the_request_before_the_model_sees_it() {
    let h = harness().await;
    let reply = send(
        &h.state,
        chat_request("redact-chat", "please look at TCK-1234 and TCK-5678", false),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let forwarded = h.upstream_seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        forwarded["messages"][0]["content"], "please look at [ticket] and [ticket]",
        "{forwarded}"
    );

    // The compression record names the transform and counts the
    // replacements, without the matched text.
    let deadline = Instant::now() + Duration::from_secs(5);
    let record = loop {
        let found = h
            .bus
            .payloads
            .lock()
            .iter()
            .find(|event| event.to_string().contains("privacy.redact_tickets"))
            .cloned();
        if let Some(found) = found {
            break found;
        }
        assert!(
            Instant::now() < deadline,
            "no event mentions the transform: {:?}",
            h.bus.payloads.lock()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let text = record.to_string();
    assert!(text.contains("\"replacements\":2"), "{text}");
    assert!(
        !text.contains("TCK-1234"),
        "the matched text is gone from the audit record: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_transform_rewrites_the_arguments_before_the_backend_sees_them() {
    let h = harness().await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("x-pv-session", "redact-tool")
        .header("x-pv-workflow", "unsigned")
        .body(axum::body::Body::from(tools_call(
            "create_ticket",
            json!({"title": "status of NIGHTJAR", "body": {"note": "nightjar slipped"}}),
        )))
        .unwrap();
    let reply = send(&h.state, request).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let calls = h.backend.tool_calls();
    assert_eq!(calls.len(), 1);
    let forwarded: Value = serde_json::from_slice(&calls[0].body).unwrap();
    assert_eq!(
        forwarded["params"]["arguments"]["title"], "status of [REDACTED]",
        "{forwarded}"
    );
    assert_eq!(
        forwarded["params"]["arguments"]["body"]["note"], "[REDACTED] slipped",
        "{forwarded}"
    );
    assert!(!calls[0].everything().to_lowercase().contains("nightjar"));

    // A tool outside the transform's scope is forwarded untouched.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("x-pv-session", "redact-tool-2")
        .header("x-pv-workflow", "unsigned")
        .body(axum::body::Body::from(tools_call(
            "search_tickets",
            json!({"q": "nightjar"}),
        )))
        .unwrap();
    assert_eq!(send(&h.state, request).await.status, 200);
    let calls = h.backend.tool_calls();
    assert_eq!(calls.len(), 2);
    let forwarded: Value = serde_json::from_slice(&calls[1].body).unwrap();
    assert_eq!(forwarded["params"]["arguments"]["q"], "nightjar", "{forwarded}");

    // A body the strict parser refuses is left alone for the parse gate.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("x-pv-session", "redact-tool-3")
        .header("x-pv-workflow", "unsigned")
        .body(axum::body::Body::from(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_ticket","name":"other","arguments":{"title":"nightjar"}}}"#,
        ))
        .unwrap();
    let refused = send(&h.state, request).await;
    assert_ne!(refused.status, 200, "{}", refused.body);
    assert_eq!(
        h.backend.tool_calls().len(),
        2,
        "nothing more reached the backend"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completion_that_overflows_a_pushed_token_budget_is_refused_naming_the_policy() {
    let h = harness().await;
    let (state, _) = {
        let state = &h.state;
        assert_eq!(
            state.sandbox.pushed().budget.max_tokens,
            Some(120),
            "the pushed cap is in force"
        );
        (state, ())
    };
    let refused = send(state, chat_request("overspend", "overspend please", false)).await;
    assert_eq!(refused.status, 403, "{}", refused.body);
    // The body is JSON, so the quotes around the name are escaped.
    assert!(
        refused.body.contains("policy \\\"llm.token_cap\\\"")
            && refused.body.contains("max_tokens exceeded (cap 120)"),
        "{}",
        refused.body
    );
    let stop = attributed_stop(&h.bus, "llm.token_cap").await;
    assert!(
        stop["reason"].as_str().unwrap().contains("llm.token_cap"),
        "{stop}"
    );
}
