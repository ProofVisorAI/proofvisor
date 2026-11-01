//! Console-pushed transforms over model responses, and egress guardrails
//! over the parts of a response that are not its text:
//!
//! * a buffered response is rewritten before it is relayed and before
//!   it is journaled, and the capture names the transform;
//! * a streamed response is held until complete and relayed with the
//!   rewritten text, keeping the provider's frame count, finish reason
//!   and usage;
//! * an egress guardrail refuses a response whose reasoning or tool-call
//!   arguments match, naming the part.

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
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::RecordingBus;

type Request = axum::http::Request<axum::body::Body>;

/// A chat upstream whose answer mentions two ticket numbers. A prompt
/// with "reason" adds reasoning text that names a codename; one with
/// "tool" adds a tool call whose arguments name it.
async fn chat_upstream() -> String {
    let app = axum::Router::new().fallback(move |request: Request| async move {
        let (_parts, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 22).await.unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let prompt = request["messages"][0]["content"].as_str().unwrap_or_default().to_owned();
        let stream = request["stream"] == true;
        let reasoning = prompt.contains("reason").then_some("Thinking about Project Nightjar first.");
        let tool = prompt.contains("tool");
        let pieces = ["Tickets ", "TCK-1234 and ", "TCK-", "9999 are open."];
        if stream {
            let mut chunks: Vec<String> = Vec::new();
            if let Some(reasoning) = reasoning {
                chunks.push(format!(
                    "data: {}\n\n",
                    json!({"id": "c", "object": "chat.completion.chunk", "model": "m",
                           "choices": [{"index": 0, "delta": {"reasoning_content": reasoning}, "finish_reason": null}]})
                ));
            }
            for text in pieces {
                chunks.push(format!(
                    "data: {}\n\n",
                    json!({"id": "c", "object": "chat.completion.chunk", "model": "m",
                           "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}]})
                ));
            }
            if tool {
                chunks.push(format!(
                    "data: {}\n\n",
                    json!({"id": "c", "object": "chat.completion.chunk", "model": "m",
                           "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "file_ticket", "arguments": "{\"title\": \"Nightjar follow-up\"}"}}]}, "finish_reason": null}]})
                ));
            }
            chunks.push(format!(
                "data: {}\n\n",
                json!({"id": "c", "object": "chat.completion.chunk", "model": "m",
                       "choices": [{"index": 0, "delta": {}, "finish_reason": if tool { "tool_calls" } else { "stop" }}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 12, "total_tokens": 22}})
            ));
            chunks.push("data: [DONE]\n\n".to_owned());
            let stream = futures::StreamExt::then(futures::stream::iter(chunks), |chunk| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, std::io::Error>(chunk)
            });
            let mut response = axum::response::Response::new(axum::body::Body::from_stream(stream));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/event-stream"),
            );
            return response;
        }
        let mut message = json!({"role": "assistant", "content": pieces.concat()});
        if let Some(reasoning) = reasoning {
            message["reasoning_content"] = Value::String(reasoning.to_owned());
        }
        if tool {
            message["tool_calls"] = json!([{"id": "call_1", "type": "function", "function": {"name": "file_ticket", "arguments": "{\"title\": \"Nightjar follow-up\"}"}}]);
        }
        axum::Json(json!({
            "id": "c", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "message": message, "finish_reason": if tool { "tool_calls" } else { "stop" }}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 12, "total_tokens": 22}
        }))
        .into_response()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

fn policy(id: &str, name: &str, kind: &str, scope: &str, spec: Value) -> Value {
    json!({"id": id, "name": name, "kind": kind, "scope": scope, "enabled": true,
           "updatedAt": "2026-11-01T00:00:00.000Z", "spec": spec, "body": spec.to_string()})
}

struct Harness {
    state: Arc<pv_harness::AppState>,
    bus: Arc<RecordingBus>,
    _dir: tempfile::TempDir,
}

/// A gateway with one `llm.egress` transform (ticket numbers) and one
/// `llm.egress` guardrail (the codename).
async fn harness() -> Harness {
    let url = chat_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let bus = Arc::new(RecordingBus::default());
    let mut config = common::leaked_test_config();
    config.upstream_url = url;
    config.breaker.min_tokens = u64::MAX;
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state(
        config,
        sandbox,
        Arc::clone(&bus) as Arc<dyn pv_bridge::EventBus>,
        7,
    );
    let bundle = json!({"version": 1, "etag": "cafe", "policies": [
        policy("t-egress", "privacy.redact_answers", "transform", "llm.egress",
               json!({"applies_to": "llm.egress", "redact_patterns": ["TCK-[0-9]{4}"], "replacement": "[ticket]"})),
        policy("g-egress", "privacy.no_codenames", "guardrail", "llm.egress",
               json!({"applies_to": "llm.egress", "deny_patterns": ["(?i)nightjar"]})),
    ]});
    let path = dir.path().join("policies.json");
    pv_core::fsutil::write_atomic(&path, &serde_json::to_vec(&bundle).unwrap()).unwrap();
    let push = PolicyPush::new(path, Arc::clone(&state.sandbox), Arc::clone(&state.pushed_rates));
    let status = push.load_at_boot().unwrap().expect("the bundle applies at boot");
    assert!(status.unsupported.is_empty(), "{:?}", status.unsupported);
    assert_eq!(status.applied, vec!["t-egress", "g-egress"]);
    Harness {
        state,
        bus,
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

/// Wait for the bus event whose text contains `needle`.
async fn event_containing(bus: &RecordingBus, needle: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = bus
            .payloads
            .lock()
            .iter()
            .find(|event| event.to_string().contains(needle))
            .cloned();
        if let Some(found) = found {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "no event contains {needle:?}: {:?}",
            bus.payloads.lock()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_response_is_rewritten_before_the_client_and_the_journal_see_it() {
    let h = harness().await;
    let reply = send(
        &h.state,
        chat_request("egress-buffered", "list the tickets", false),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let body: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(
        body["choices"][0]["message"]["content"], "Tickets [ticket] and [ticket] are open.",
        "{}",
        reply.body
    );
    assert_eq!(
        body["usage"]["completion_tokens"], 12,
        "the rest of the body is untouched"
    );
    assert!(!reply.body.contains("TCK-"), "{}", reply.body);

    let capture = event_containing(&h.bus, "privacy.redact_answers").await;
    let text = capture.to_string();
    assert!(text.contains("\"replacements\":2"), "{text}");
    assert!(
        !text.contains("TCK-1234"),
        "the event holds no original text: {text}"
    );
    // Nothing on the bus carries an original ticket number.
    let leaked = h
        .bus
        .payloads
        .lock()
        .iter()
        .any(|event| event.to_string().contains("TCK-"));
    assert!(!leaked, "{:?}", h.bus.payloads.lock());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_response_is_held_and_relayed_rewritten() {
    let h = harness().await;
    let reply = send(&h.state, chat_request("egress-stream", "list the tickets", true)).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        !reply.body.contains("TCK-"),
        "no ticket number is relayed: {}",
        reply.body
    );
    let frames: Vec<Value> = reply
        .body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    assert_eq!(
        frames.len(),
        5,
        "four content frames and the finish frame: {}",
        reply.body
    );
    let content: String = frames
        .iter()
        .filter_map(|frame| frame["choices"][0]["delta"]["content"].as_str())
        .collect();
    assert_eq!(content, "Tickets [ticket] and [ticket] are open.");
    assert_eq!(frames[4]["choices"][0]["finish_reason"], "stop");
    assert_eq!(frames[4]["usage"]["completion_tokens"], 12);
    assert!(reply.body.trim_end().ends_with("data: [DONE]"), "{}", reply.body);
    event_containing(&h.bus, "privacy.redact_answers").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_egress_guardrail_also_refuses_matching_reasoning_and_tool_calls() {
    let h = harness().await;
    let reasoning = send(
        &h.state,
        chat_request("egress-reasoning", "reason about the tickets", false),
    )
    .await;
    assert_eq!(reasoning.status, 403, "{}", reasoning.body);
    assert!(
        reasoning.body.contains("privacy.no_codenames") && reasoning.body.contains("model reasoning matches"),
        "{}",
        reasoning.body
    );
    assert!(!reasoning.body.contains("Nightjar"), "{}", reasoning.body);

    let tool = send(
        &h.state,
        chat_request("egress-tool", "use a tool for the tickets", true),
    )
    .await;
    // The matching tool-call frame is never relayed; the stream ends
    // with the error frame (a held stream has relayed nothing yet, so
    // this is a clean 403).
    assert_eq!(tool.status, 403, "{}", tool.body);
    assert!(
        tool.body.contains("privacy.no_codenames") && tool.body.contains("model tool call matches"),
        "{}",
        tool.body
    );
    assert!(!tool.body.contains("Nightjar"), "{}", tool.body);

    let fine = send(&h.state, chat_request("egress-fine", "list the tickets", false)).await;
    assert_eq!(fine.status, 200, "{}", fine.body);
}
