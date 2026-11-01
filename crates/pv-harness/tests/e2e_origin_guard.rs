//! A browser page must not be able to drive the daemon cross-site. A
//! server-side agent never sends `Origin`; a browser always does on a
//! cross-origin `POST`, even in `no-cors` mode where no preflight runs.
//! These tests pin that every state-changing route refuses a foreign
//! `Origin`, accepts an allowlisted one, and still serves requests that
//! carry none.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use serde_json::{json, Value};
use std::sync::Arc;

type Request = axum::http::Request<axum::body::Body>;

async fn chat_upstream() -> String {
    let app = axum::Router::new().fallback(|| async {
        axum::Json(json!({
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 4, "completion_tokens": 1, "total_tokens": 5}
        }))
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

fn gateway(upstream: &str, allowed: &[&str]) -> Arc<pv_harness::AppState> {
    let mut config = common::leaked_test_config();
    config.upstream_url = upstream.to_owned();
    config.mcp_allowed_origins = allowed.iter().map(|s| (*s).to_owned()).collect();
    let sandbox = common::sandbox_for(&config);
    common::app_state(config, sandbox, Arc::new(common::CountingBus::default()), 23)
}

fn post(uri: &str, origin: Option<&str>, body: Vec<u8>) -> Request {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-pv-session", "origin-guard")
        .header("x-pv-workflow", "unsigned");
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    builder.body(axum::body::Body::from(body)).unwrap()
}

fn chat_body() -> Vec<u8> {
    serde_json::to_vec(&json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})).unwrap()
}

async fn send(state: &Arc<pv_harness::AppState>, request: Request) -> (u16, Value) {
    let router = pv_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn chat_refuses_a_foreign_origin_and_serves_allowlisted_and_absent_ones() {
    let upstream = chat_upstream().await;
    let state = gateway(&upstream, &["https://console.example.test"]);

    let (status, body) = send(
        &state,
        post("/v1/chat/completions", Some("https://evil.example"), chat_body()),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Origin is not allowed"),
        "{body}"
    );

    let (status, body) = send(
        &state,
        post(
            "/v1/chat/completions",
            Some("https://console.example.test"),
            chat_body(),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = send(&state, post("/v1/chat/completions", None, chat_body())).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_blob_post_without_content_type_is_still_refused_by_origin() {
    // `fetch(url, {mode: "no-cors", body: new Blob([json])})` sends no
    // Content-Type at all, which the chat route tolerates; the Origin
    // header is what stops it.
    let upstream = chat_upstream().await;
    let state = gateway(&upstream, &[]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("origin", "http://attacker.example")
        .header("x-pv-session", "blob")
        .body(axum::body::Body::from(chat_body()))
        .unwrap();
    let (status, _) = send(&state, request).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn session_lifecycle_and_token_routes_refuse_a_foreign_origin() {
    let upstream = chat_upstream().await;
    let state = gateway(&upstream, &[]);
    let (status, _) = send(&state, post("/v1/chat/completions", None, chat_body())).await;
    assert_eq!(status, 200);

    for uri in [
        "/v1/sessions/origin-guard/close",
        "/v1/sessions/origin-guard/promote",
        "/v1/token",
        "/v1/revoke",
    ] {
        let (status, body) = send(&state, post(uri, Some("https://evil.example"), Vec::new())).await;
        assert_eq!(status, 403, "{uri}: {body}");
    }

    // Two Origin headers are as suspicious as a wrong one.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/sessions/origin-guard/close")
        .header("origin", "https://a.example")
        .header("origin", "https://a.example")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _) = send(&state, request).await;
    assert_eq!(status, 403);

    // Without an Origin the close goes through as before.
    let (status, body) = send(&state, post("/v1/sessions/origin-guard/close", None, Vec::new())).await;
    assert_eq!(status, 200, "{body}");
}
