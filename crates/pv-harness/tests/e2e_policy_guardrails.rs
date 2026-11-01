//! Console-pushed guardrail policies, end to end through the daemon: a
//! bundle file with guardrail specs is applied at boot, a tool call whose
//! arguments match a deny pattern is refused at the policy stage naming
//! the console policy, a chat request whose content matches is refused at
//! the sanitize stage naming its policy (and the stop-reason event
//! carries the name, so `pvctl console-sync` attributes the block), and a
//! free-text guardrail is accepted but reported unsupported.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use pv_harness::pipeline::PipelineError;
use pv_harness::policy_push::PolicyPush;
use serde_json::{json, Value};
use std::sync::Arc;

use common::{headers, tools_call, RecordingBus};

async fn mcp(
    state: &Arc<pv_harness::AppState>,
    session: &str,
    body: Vec<u8>,
) -> (axum::http::StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("x-pv-session", session)
        .header("x-pv-workflow", "unsigned")
        .body(axum::body::Body::from(body))
        .unwrap();
    let router = pv_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn guardrail(id: &str, name: &str, scope: &str, spec: Value) -> Value {
    json!({"id": id, "name": name, "kind": "guardrail", "scope": scope, "enabled": true,
           "updatedAt": "2026-11-01T00:00:00.000Z", "spec": spec, "body": spec.to_string()})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushed_guardrails_refuse_tool_arguments_and_chat_content_naming_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let bus = Arc::new(RecordingBus::default());
    let mut config = common::leaked_test_config();
    config.breaker.min_tokens = u64::MAX;
    let sandbox = common::sandbox_for(&config);
    let state = common::app_state(
        config,
        sandbox,
        Arc::clone(&bus) as Arc<dyn pv_bridge::EventBus>,
        7,
    );

    // The bundle `pvctl console-sync --pull-policies` would write: two
    // guardrail specs, one free-text guardrail, one allowlist.
    let bundle = json!({"version": 1, "etag": "feed", "policies": [
        guardrail("g-tool", "privacy.pii_egress", "tool.*", json!({
            "applies_to": "tool.args",
            "deny_patterns": [r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", r"\b(?:[0-9][ -]?){12,18}[0-9]\b"],
            "effect": "block"
        })),
        guardrail("g-chat", "llm.no_cards", "llm.request", json!({
            "applies_to": "llm.ingress",
            "deny_patterns": [r"\b(?:[0-9][ -]?){12,18}[0-9]\b"]
        })),
        {"id": "g-text", "name": "privacy.handbook", "kind": "guardrail", "scope": "llm.egress", "enabled": true,
         "updatedAt": "2026-11-01T00:00:00.000Z", "spec": null, "body": "Never paste customer PII into a prompt."},
        {"id": "a-1", "name": "runtime.no_wires", "kind": "allowlist", "scope": "tool.*", "enabled": true,
         "updatedAt": "2026-11-01T00:00:00.000Z", "spec": {"deny_tools": ["send_wire"]}, "body": ""},
    ]});
    let path = dir.path().join("policies.json");
    pv_core::fsutil::write_atomic(&path, &serde_json::to_vec(&bundle).unwrap()).unwrap();
    let push = PolicyPush::new(path, Arc::clone(&state.sandbox), Arc::clone(&state.pushed_rates));
    let status = push.load_at_boot().unwrap().expect("the bundle applies at boot");
    assert_eq!(status.applied, vec!["g-tool", "g-chat", "a-1"]);
    assert_eq!(status.unsupported.len(), 1);
    assert_eq!(status.unsupported[0].id, "g-text");
    assert!(
        status.unsupported[0].reason.contains("no JSON spec"),
        "{}",
        status.unsupported[0].reason
    );

    // A tool call whose arguments carry an SSN is refused at the policy
    // stage, exactly like an allowlist refusal: a JSON-RPC policy denial
    // naming the console policy, without the matched text.
    let (http, reply) = mcp(
        &state,
        "s-pii",
        tools_call("create_ticket", json!({"customer": {"ssn": "123-45-6789"}})),
    )
    .await;
    let message = reply["error"]["data"]["reason"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        message.contains("policy \"privacy.pii_egress\"")
            && message.contains("deny pattern 1 of 2 (at /customer/ssn)"),
        "{http} {reply}"
    );
    assert!(!message.contains("6789"), "the SSN must not be echoed: {message}");
    let (_, wire) = mcp(&state, "s-pii", tools_call("send_wire", json!({}))).await;
    assert!(
        wire["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("runtime.no_wires"),
        "allowlists still apply: {wire}"
    );
    // Clean arguments pass the sandbox (the forward to the unreachable
    // tool upstream is a separate matter).
    let store = pv_state::InMemoryStore::new();
    assert!(state
        .sandbox
        .check(
            &store,
            "s-clean",
            &tools_call("create_ticket", json!({"customer": {"name": "Ann"}}))
        )
        .is_allowed());

    // A chat request carrying a card number is refused at the sanitize
    // stage, naming the policy, before any token is charged.
    let payload = json!({"model": "m", "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": [{"type": "text", "text": "charge 4111 1111 1111 1111 please"}]}
    ]});
    let refused = state.prepare_chat(&headers("c-card", "unsigned"), payload, None);
    let Err(error) = refused else {
        panic!("the chat request must be refused");
    };
    assert!(matches!(error, PipelineError::Blocked { .. }), "{error:?}");
    let text = error.to_string();
    assert!(
        text.contains("policy \"llm.no_cards\"") && text.contains("(at /messages/1/content/0/text)"),
        "{text}"
    );
    assert!(
        !text.contains("4111"),
        "the card number must not be echoed: {text}"
    );
    assert!(state
        .prepare_chat(
            &headers("c-ok", "unsigned"),
            common::chat("what is the refund policy?"),
            None
        )
        .is_ok());

    // The stop-reason event names the policy (`payload.policy`), which is
    // what pvctl console-sync uploads as the attributed block.
    let mut attributed = None;
    for _ in 0..100 {
        attributed = bus.payloads.lock().iter().find_map(|event| {
            let payload = event.get("payload")?;
            (payload.get("policy")?.as_str()? == "llm.no_cards").then(|| payload.clone())
        });
        if attributed.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let attributed = attributed.expect("a stop-reason event attributed to llm.no_cards");
    assert!(
        attributed["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("llm.no_cards"),
        "{attributed}"
    );
}
