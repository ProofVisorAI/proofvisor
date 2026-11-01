//! End-to-end tests for four proxy behaviours that until now were pinned
//! by unit tests only: context compression on the chat path, the
//! signed-session requirement for consequential tools, the stripping of
//! upstream response headers, and the read-only operator dashboard.
//!
//! Each test drives the live HTTP router (`build_router`) against a
//! loopback upstream, so a regression in the wiring between the pipeline
//! and the routes is caught the way a client would see it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::HeaderValue;
use axum::response::IntoResponse;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Request = axum::http::Request<axum::body::Body>;

/// One chat request the mock upstream received.
#[derive(Debug, Clone)]
struct Seen {
    body: Value,
}

/// A chat upstream that answers every request with one canned OpenAI
/// chat completion, adds `extra_headers` to the response, and records
/// what it received.
async fn chat_upstream(extra_headers: Vec<(&'static str, &'static str)>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let recorded = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |request: Request| {
        let recorded = Arc::clone(&recorded);
        let extra_headers = extra_headers.clone();
        async move {
            let (_parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 22).await.unwrap();
            recorded.lock().unwrap().push(Seen {
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            });
            let mut response = axum::Json(json!({
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "created": 1,
                "model": "m",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 40, "completion_tokens": 1, "total_tokens": 41}
            }))
            .into_response();
            for (name, value) in extra_headers {
                response
                    .headers_mut()
                    .append(name, HeaderValue::from_static(value));
            }
            response
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, seen)
}

fn gateway(
    upstream: &str,
    bus: Arc<dyn pv_bridge::EventBus>,
    tweak: impl FnOnce(&mut pv_harness::HarnessConfig),
) -> Arc<pv_harness::AppState> {
    let mut config = common::leaked_test_config();
    config.upstream_url = upstream.to_owned();
    tweak(&mut config);
    let sandbox = common::sandbox_for(&config);
    common::app_state(config, sandbox, bus, 11)
}

fn chat_request(session: &str, payload: &Value) -> Request {
    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-pv-session", session)
        .header("x-pv-workflow", "unsigned")
        .body(axum::body::Body::from(serde_json::to_vec(payload).unwrap()))
        .unwrap()
}

fn tool_call(headers: &axum::http::HeaderMap, tool: &str) -> Request {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(common::tools_call(
            tool,
            json!({"amount": 1}),
        )))
        .unwrap()
}

fn get(uri: &str) -> Request {
    axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap()
}

struct Reply {
    status: axum::http::StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

async fn send(state: &Arc<pv_harness::AppState>, request: Request) -> Reply {
    let router = pv_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 22).await.unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// Wait until `predicate` holds for the bus payloads, or fail after 5 s.
async fn wait_for_payload(bus: &common::RecordingBus, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(found) = bus.payloads.lock().iter().find(|payload| predicate(payload)) {
            return found.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no matching payload reached the bus: {:?}",
            bus.payloads.lock()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── Context compression ─────────────────────────────────────────

/// A long, repetitive history is compressed before it is forwarded: the
/// upstream receives fewer messages than the client sent, the client
/// still gets a normal completion, and the audit trail carries a
/// compression record with the token counts before and after.
#[tokio::test]
async fn a_repetitive_history_is_compressed_before_forwarding_and_the_audit_records_it() {
    let (url, seen) = chat_upstream(Vec::new()).await;
    let bus = Arc::new(common::RecordingBus::default());
    let state = gateway(&url, Arc::clone(&bus) as Arc<dyn pv_bridge::EventBus>, |config| {
        assert!(config.compression_enabled, "compression is on by default");
    });

    // Forty exact copies of the same exchange: well past the 512-token
    // floor, and every pair but the protected tail is collapsible.
    let filler = "Please summarise the quarterly report again, section by section, in detail. ";
    let mut messages = vec![json!({"role": "system", "content": "You are terse."})];
    for _ in 0..40 {
        messages.push(json!({"role": "user", "content": filler.repeat(8)}));
        messages.push(
            json!({"role": "assistant", "content": "Here is the summary of the report, section by section."}),
        );
    }
    messages.push(json!({"role": "user", "content": "And the final figure?"}));
    let sent = messages.len();
    let payload = json!({"model": "m", "messages": messages});

    let answer = send(&state, chat_request("compress-1", &payload)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.json()["choices"][0]["message"]["content"], "ok");

    // Copy the captured request out of the lock: the bus wait below
    // awaits, and a `MutexGuard` must not live across an await point.
    let upstream: Vec<Seen> = seen.lock().unwrap().clone();
    assert_eq!(upstream.len(), 1, "exactly one upstream call");
    let forwarded = upstream[0].body["messages"].as_array().unwrap();
    // Duplicates are replaced by audit stubs, not deleted, so the
    // message count is unchanged and every position still exists.
    assert_eq!(forwarded.len(), sent);
    let stubs = forwarded
        .iter()
        .filter(|message| {
            message["content"]
                .as_str()
                .is_some_and(|content| content.starts_with("[pruned:"))
        })
        .count();
    assert!(
        stubs >= 30,
        "the repeated user turns must be stubbed before forwarding: {stubs} stubs in {}",
        upstream[0].body
    );
    let forwarded_bytes = upstream[0].body.to_string().len();
    let sent_bytes = payload.to_string().len();
    // Each stub is about 120 bytes (count, hash, reason and tag), so the
    // saving per collapsed 600-byte turn is roughly 80 %.
    assert!(
        forwarded_bytes * 2 < sent_bytes,
        "the forwarded payload must be much smaller: {forwarded_bytes} of {sent_bytes} bytes"
    );
    assert_eq!(
        forwarded[0]["content"], "You are terse.",
        "the system prompt survives compression"
    );
    assert_eq!(
        forwarded.last().unwrap()["content"],
        "And the final figure?",
        "the newest message survives compression"
    );
    assert_eq!(
        forwarded[sent - 2]["content"],
        "Here is the summary of the report, section by section.",
        "the protected tail is forwarded verbatim"
    );

    let record = wait_for_payload(&bus, |payload| {
        let text = payload.to_string();
        text.contains("agent.compression") && text.contains("tokens_before")
    })
    .await;
    let text = record.to_string();
    assert!(
        text.contains("\"changed\":true"),
        "the compression record must say the payload changed: {text}"
    );
    let before = record
        .pointer("/unmapped/payload/tokens_before")
        .or_else(|| record.pointer("/payload/tokens_before"))
        .and_then(Value::as_u64);
    let after = record
        .pointer("/unmapped/payload/tokens_after")
        .or_else(|| record.pointer("/payload/tokens_after"))
        .and_then(Value::as_u64);
    if let (Some(before), Some(after)) = (before, after) {
        assert!(
            after < before,
            "tokens_after {after} must be below tokens_before {before}"
        );
    }
}

/// With compression switched off the payload reaches the upstream
/// byte-for-byte, however repetitive it is.
#[tokio::test]
async fn compression_off_forwards_the_history_verbatim() {
    let (url, seen) = chat_upstream(Vec::new()).await;
    let state = gateway(&url, Arc::new(common::CountingBus::default()), |config| {
        config.compression_enabled = false;
    });
    let mut messages = Vec::new();
    for _ in 0..40 {
        messages
            .push(json!({"role": "user", "content": "the same question, again and again, forty times over"}));
        messages.push(json!({"role": "assistant", "content": "the same answer"}));
    }
    let payload = json!({"model": "m", "messages": messages});
    let answer = send(&state, chat_request("verbatim-1", &payload)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let upstream = seen.lock().unwrap();
    assert_eq!(upstream[0].body["messages"], payload["messages"]);
}

// ── Consequential tools need a signed session ───────────────────

/// A tool on the `consequential_tools` list is refused on an unsigned
/// session before the backend is contacted, and forwarded on a signed
/// one. The refusal names the built-in policy so the console can
/// attribute it.
#[tokio::test]
async fn a_consequential_tool_is_refused_on_an_unsigned_session_and_forwarded_on_a_signed_one() {
    let backend = common::MockBackend::start().await;
    let state = gateway(
        "http://127.0.0.1:9",
        Arc::new(common::CountingBus::default()),
        |config| {
            config.tool_upstream_url = Some(backend.url.clone());
            assert!(
                config.consequential_tools.iter().any(|tool| tool == "payout"),
                "payout is consequential by default"
            );
        },
    );

    let refused = send(
        &state,
        tool_call(&common::headers("unsigned-payout", "unsigned"), "payout"),
    )
    .await;
    assert_ne!(
        refused.status, 200,
        "an unsigned consequential call is refused: {}",
        refused.body
    );
    assert!(
        refused.body.contains("requires a signed workflow"),
        "the refusal explains the rule: {}",
        refused.body
    );
    assert!(
        backend.tool_calls().is_empty(),
        "the backend must never see the refused call"
    );

    let harmless = send(
        &state,
        tool_call(&common::headers("unsigned-lookup", "unsigned"), "lookup"),
    )
    .await;
    assert_eq!(
        harmless.status, 200,
        "a non-consequential tool runs unsigned: {}",
        harmless.body
    );
    assert_eq!(backend.tool_calls().len(), 1);

    let allowed = send(
        &state,
        tool_call(&common::signed_headers("signed-payout"), "payout"),
    )
    .await;
    assert_eq!(
        allowed.status, 200,
        "a signed session may run payout: {}",
        allowed.body
    );
    let calls = backend.tool_calls();
    assert_eq!(calls.len(), 2);
    assert!(
        String::from_utf8_lossy(&calls[1].body).contains("\"payout\""),
        "the signed call reached the backend"
    );
}

// ── Upstream response headers ───────────────────────────────────

/// Headers an upstream (or a middlebox) may echo back never cross the
/// proxy boundary: the provider credential header, `Authorization`,
/// cookies and server fingerprints are dropped, while content headers
/// the client needs pass through.
#[tokio::test]
async fn secret_bearing_upstream_response_headers_never_reach_the_client() {
    let (url, _seen) = chat_upstream(vec![
        ("authorization", "Bearer sk-provider-secret"),
        ("x-api-key", "sk-provider-secret"),
        ("set-cookie", "session=upstream-cookie; Path=/"),
        ("server", "provider-edge/9.9"),
        ("x-powered-by", "provider-framework"),
        ("etag", "\"abc123\""),
        ("cache-control", "no-store"),
        ("x-provider-request-id", "req_42"),
    ])
    .await;
    let state = gateway(&url, Arc::new(common::CountingBus::default()), |config| {
        config.upstream_auth_header = "x-api-key".to_owned();
    });

    let answer = send(&state, chat_request("headers-1", &common::chat_payload())).await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    for stripped in [
        "authorization",
        "x-api-key",
        "set-cookie",
        "server",
        "x-powered-by",
    ] {
        assert!(
            answer.header(stripped).is_none(),
            "{stripped} must be stripped from the relayed response: {:?}",
            answer.headers
        );
    }
    assert_eq!(answer.header("etag"), Some("\"abc123\""));
    assert_eq!(answer.header("cache-control"), Some("no-store"));
    assert_eq!(answer.header("x-provider-request-id"), Some("req_42"));
    assert_eq!(
        answer.header("x-content-type-options"),
        Some("nosniff"),
        "every relayed response is pinned nosniff"
    );
    assert!(
        answer
            .header("content-type")
            .is_some_and(|value| value.starts_with("application/json")),
        "content-type passes through: {:?}",
        answer.headers
    );
    assert!(
        !answer.body.contains("sk-provider-secret"),
        "the provider secret never appears in the body either"
    );
}

// ── Operator dashboard ──────────────────────────────────────────

/// With `dashboard_enabled = true` the page, its assets and its JSON API
/// are served and reflect live sessions; with it off, none of them exist.
#[tokio::test]
async fn the_operator_dashboard_serves_live_sessions_only_when_enabled() {
    let (url, _seen) = chat_upstream(Vec::new()).await;
    let state = gateway(&url, Arc::new(common::CountingBus::default()), |config| {
        config.dashboard_enabled = true;
    });

    let page = send(&state, get("/dashboard")).await;
    assert_eq!(page.status, 200);
    assert!(
        page.header("content-type")
            .is_some_and(|value| value.starts_with("text/html")),
        "{:?}",
        page.headers
    );
    assert!(page.body.contains("<html"), "the dashboard page is HTML");
    assert_eq!(send(&state, get("/dashboard/app.js")).await.status, 200);
    assert_eq!(send(&state, get("/dashboard/style.css")).await.status, 200);

    let empty = send(&state, get("/api/v1/dashboard/stats")).await;
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert_eq!(empty.json()["session_count"], 0);

    let answer = send(&state, chat_request("dash-session", &common::chat_payload())).await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let stats = send(&state, get("/api/v1/dashboard/stats")).await.json();
    assert_eq!(stats["session_count"], 1, "{stats}");
    assert_eq!(stats["open_count"], 1, "{stats}");

    let list = send(&state, get("/api/v1/dashboard/sessions")).await.json();
    let sessions = list["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "{list}");
    assert_eq!(sessions[0]["id"], "dash-session");
    assert_eq!(sessions[0]["open"], true);

    let detail = send(&state, get("/api/v1/dashboard/sessions/dash-session")).await;
    assert_eq!(detail.status, 200, "{}", detail.body);
    assert_eq!(detail.json()["summary"]["id"], "dash-session", "{}", detail.body);
    assert_eq!(detail.json()["summary"]["open"], true, "{}", detail.body);
    assert_eq!(
        send(&state, get("/api/v1/dashboard/sessions/no-such-session"))
            .await
            .status,
        404
    );

    let (url, _seen) = chat_upstream(Vec::new()).await;
    let disabled = gateway(&url, Arc::new(common::CountingBus::default()), |config| {
        config.dashboard_enabled = false;
    });
    for path in [
        "/dashboard",
        "/dashboard/app.js",
        "/api/v1/dashboard/stats",
        "/api/v1/dashboard/sessions",
    ] {
        assert_eq!(
            send(&disabled, get(path)).await.status,
            404,
            "{path} must not exist when the dashboard is off"
        );
    }
}
