//! Edge cases, through the live router, of three features added together:
//! the refusals the judge sees rebuilt at startup from an embedded
//! Bridge's recorded events (`AppState::with_judge`), `record_inputs`
//! (what the judge was asked, kept in each judged call's record) under
//! audit redaction, and the automatic promotion of closed unsigned
//! sessions holding a trace verdict (`Finalizer::promote_judged_sessions`).
//! Each test states the behaviour it expects; a failing test is a finding.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use crate::common;

use pv_harness::judge::{
    JudgeAdapterConfig, JudgeAdapterKind, JudgeConfig, JudgeFailureConfig, JudgeModeConfig,
    JudgePredicateBinding, JudgeService, JudgeThresholdConfig, JudgeToolConfig, JudgeTraceConfig,
    TraceSource,
};
use pv_harness::{AppState, HarnessConfig};
use pv_judge::mock::{MockBehavior, MockJudge};
use pv_judge::{ModelPin, ARG_MATCHES_TASK, OUTPUT_SAFE};
use pv_sandbox::{Sandbox, SandboxConfig};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn pin() -> ModelPin {
    ModelPin::new("rip-judge", "1", "cd".repeat(32)).unwrap()
}

fn judge_config() -> JudgeConfig {
    JudgeConfig {
        mode: JudgeModeConfig::Enforce,
        max_concurrency: 8,
        adapters: vec![JudgeAdapterConfig {
            name: "j".into(),
            kind: JudgeAdapterKind::Cloud,
            deadline_ms: Some(2_000),
            model_name: pin().name,
            model_version: pin().version,
            weights_sha256: pin().weights_sha256,
            model_path: None,
            tokenizer_path: None,
            tokenizer_sha256: None,
            output_labels: Vec::new(),
            max_input_tokens: None,
            endpoint: Some("http://127.0.0.1:9/judge".into()),
            bearer_file: None,
            redact: true,
        }],
        tools: vec![JudgeToolConfig {
            tool: "update_ticket".into(),
            predicates: vec![JudgePredicateBinding {
                id: ARG_MATCHES_TASK.into(),
                adapter: "j".into(),
            }],
            allow_cloud: true,
        }],
        thresholds: vec![JudgeThresholdConfig {
            predicate: ARG_MATCHES_TASK.into(),
            label: "mismatch".into(),
            deny_above: Some(0.7),
            ask_above: None,
            min_confidence: None,
        }],
        on_failure: JudgeFailureConfig::default(),
        predicates: Vec::new(),
        pilot: None,
        drift: None,
        background_max_concurrency: 8,
        max_concurrency_per_caller: None,
        trace: None,
        breaker: None,
        standing_rules: Vec::new(),
        record_inputs: false,
    }
}

fn trace() -> JudgeTraceConfig {
    JudgeTraceConfig {
        adapter: "j".into(),
        predicate: OUTPUT_SAFE.into(),
        sources: vec![TraceSource::Tool],
        finding_above: 0.7,
        allow_cloud: true,
        max_output_chars: 16_384,
    }
}

/// `update_ticket` is judged with the mismatch the test sets; trace
/// verdicts are always "safe".
fn mock() -> Arc<MockJudge> {
    let mock = Arc::new(MockJudge::new(
        pin(),
        MockBehavior::scores(&[("match", 0.95), ("mismatch", 0.05)]),
    ));
    mock.set_for_predicate(
        OUTPUT_SAFE,
        MockBehavior::scores(&[("safe", 0.98), ("unsafe", 0.02)]),
    );
    mock
}

fn mismatch(p: f64) -> MockBehavior {
    MockBehavior::scores(&[("match", 1.0 - p), ("mismatch", p)])
}

struct Harness {
    state: Arc<AppState>,
    bus: Arc<common::RecordingBus>,
}

fn build(judge: JudgeConfig, mock: &Arc<MockJudge>, tweak: impl FnOnce(&mut HarnessConfig)) -> Harness {
    let mut config = common::leaked_test_config();
    tweak(&mut config);
    config.judge = Some(judge.clone());
    let mut schemas = HashMap::new();
    for tool in ["update_ticket", "read_ticket"] {
        schemas.insert(tool.to_owned(), json!({"type": "object"}));
    }
    let sandbox = Sandbox::new(
        SandboxConfig {
            schemas,
            budget: config.budget.clone(),
            payout_field: config.payout_field.clone(),
            require_schema: false,
        },
        Vec::new(),
    )
    .unwrap()
    .with_judge_policy(judge.threshold_policy().unwrap());
    let bus = Arc::new(common::RecordingBus::default());
    let state = common::app_state(config, sandbox, Arc::clone(&bus) as _, 13);
    let mut adapters: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>> = BTreeMap::new();
    adapters.insert("j".into(), Arc::clone(mock) as _);
    let service = JudgeService::new(&judge, adapters, Arc::clone(&state.metrics)).unwrap();
    Harness {
        state: Arc::new((*state).clone().with_judge(Arc::new(service))),
        bus,
    }
}

async fn call(h: &Harness, session: &str, workflow: &str, tool: &str, arguments: Value) -> u16 {
    let body = json!({"jsonrpc": "2.0", "id": NEXT_ID.fetch_add(1, Ordering::SeqCst), "method": "tools/call",
                      "params": {"name": tool, "arguments": arguments}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("x-pv-session", session)
        .header("x-pv-workflow", workflow)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let router = pv_harness::build_router((*h.state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    response.status().as_u16()
}

async fn events(bus: &common::RecordingBus, class: &str, session: &str, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let found: Vec<Value> = bus
            .payloads
            .lock()
            .iter()
            .filter(|event| event["class_name"] == class && event["session_uid"] == session)
            .cloned()
            .collect();
        if found.len() >= count {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "only {} {class} events for {session}",
            found.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A JSON-RPC tool server answering every call with a short text.
async fn backend() -> String {
    let router = axum::Router::new().fallback(|axum::Json(body): axum::Json<Value>| async move {
        axum::Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": "ticket 7: open"}]}}))
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/rpc", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    url
}

// ── The refusal log rebuilt from recorded events ────────────────────

/// Expected to pass: a refusal recorded by one harness, written to the
/// embedded Bridge's segment as the Bridge stores it, is seen by the
/// judge of a new harness started on that data directory, with its
/// predicate; and an enforced JUDGE_DENIED record counts as
/// `would_block` (what `pvctl judge-export --would-block-only` keeps).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_recorded_before_a_restart_reaches_the_judge_after_it() {
    let first_mock = mock();
    first_mock.set_default(mismatch(0.9));
    let first = build(judge_config(), &first_mock, |_| {});
    assert_eq!(
        call(
            &first,
            "s-restore",
            "unsigned",
            "update_ticket",
            json!({"note": "x"})
        )
        .await,
        403
    );
    let recorded = events(&first.bus, "agent.tool_call", "s-restore", 1).await;
    let event = recorded[0].clone();
    assert_eq!(event["payload"]["denial_code"], "JUDGE_DENIED");
    assert_eq!(event["payload"]["judge"]["would_block"], true);

    let second_mock = mock();
    second_mock.set_default(mismatch(0.05));
    let second = build(judge_config(), &second_mock, |config| {
        let topic = std::path::Path::new(&config.bridge_data_dir).join("topics/agent.tool_call");
        std::fs::create_dir_all(&topic).unwrap();
        let line = json!({"partition": 0, "offset": 0, "key": "k", "value": event, "stored_at": 1});
        std::fs::write(topic.join("p0.jsonl"), format!("{line}\n")).unwrap();
    });
    assert_eq!(
        call(
            &second,
            "s-restore",
            "unsigned",
            "update_ticket",
            json!({"note": "y"})
        )
        .await,
        200
    );
    let seen = second_mock.last_request().unwrap().context.prior_denials;
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].tool, "update_ticket");
    assert_eq!(seen[0].denial_code, "JUDGE_DENIED");
    assert_eq!(seen[0].predicate_id.as_deref(), Some(ARG_MATCHES_TASK));
}

// ── record_inputs under audit redaction ─────────────────────────────

/// An argument the operator's `redaction_paths` names is redacted from
/// the audit trail's copy of the arguments (the ATIF tool call, through
/// `redact_user_value`). With `record_inputs`, the same arguments are
/// also kept as JSON text in `payload.judge.inputs.arguments_json`; they
/// are redacted before they become text, so the secret does not reach the
/// audit stream there either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recorded_inputs_are_redacted_like_the_arguments() {
    let mut judge = judge_config();
    judge.record_inputs = true;
    let h = build(judge, &mock(), |config| {
        config.redaction_paths = vec!["/password".into()];
    });
    let secret = "hunter2-correct-horse";
    assert_eq!(
        call(
            &h,
            "s-redact",
            "unsigned",
            "update_ticket",
            json!({"table": "orders", "password": secret})
        )
        .await,
        200
    );
    let event = events(&h.bus, "agent.tool_call", "s-redact", 1).await[0].clone();
    let inputs = &event["payload"]["judge"]["inputs"];
    assert!(inputs.is_object(), "inputs are recorded: {event}");
    assert!(
        !event.to_string().contains(secret),
        "the argument named by redaction_paths is in the recorded event: {inputs}"
    );
}

/// Redaction must leave the recorded arguments readable: a whole-number
/// card number is replaced inside the JSON text, which leaves
/// `{"card":[REDACTED]}`, no longer JSON, and `pvctl judge-export` then
/// exports the example with `"arguments": null`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redacted_recorded_arguments_stay_valid_json() {
    let mut judge = judge_config();
    judge.record_inputs = true;
    let h = build(judge, &mock(), |config| {
        config.redaction_patterns = vec!["TCK-[0-9]{4}".into()];
    });
    assert_eq!(
        call(
            &h,
            "s-card",
            "unsigned",
            "update_ticket",
            json!({"table": "orders", "card": 4_111_111_111_111_111u64})
        )
        .await,
        200
    );
    let event = events(&h.bus, "agent.tool_call", "s-card", 1).await[0].clone();
    let text = event["payload"]["judge"]["inputs"]["arguments_json"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !text.contains("4111111111111111"),
        "the card number is redacted: {text}"
    );
    let parsed = serde_json::from_str::<Value>(&text);
    assert!(
        parsed.is_ok(),
        "the redacted arguments_json is not JSON any more: {text}"
    );
}

// ── Automatic promotion ─────────────────────────────────────────────

async fn traced_and_closed(h: &Harness, session: &str) -> Arc<pv_harness::session::Session> {
    assert_eq!(
        call(h, session, "unsigned", "read_ticket", json!({"id": 7})).await,
        200
    );
    events(&h.bus, "agent.judge", session, 1).await;
    let session = h.state.sessions.get(session).unwrap();
    h.state
        .finalizer
        .close_session(Arc::clone(&session), pv_events::StopReason::SessionClosed)
        .await
        .unwrap();
    session
}

async fn traced_harness() -> Harness {
    let url = backend().await;
    let mut judge = judge_config();
    judge.trace = Some(trace());
    build(judge, &mock(), |config| {
        config.tool_upstream_url = Some(url);
        config.tool_upstream_transport = pv_harness::config::BackendTransport::JsonRpc;
    })
}

/// Two promotion passes running at once promote the one session once,
/// so they must report one promotion between them (and count one in
/// `pv_judge_auto_promotions_total`). The second pass finds the session
/// already promoted inside `promote` and counts it again. Production runs
/// one reconciler loop, so this needs two callers of the pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_passes_at_once_count_one_promotion() {
    let h = traced_harness().await;
    let session = traced_and_closed(&h, "t-twice").await;
    let finalizer = &h.state.finalizer;
    let (first, second) = tokio::join!(
        finalizer.promote_judged_sessions(&h.state.sessions),
        finalizer.promote_judged_sessions(&h.state.sessions)
    );
    assert!(session.is_promoted());
    assert_eq!(
        first + second,
        1,
        "one session, reported promoted {first} + {second} times"
    );
}

/// Expected to pass: a promotion that keeps failing is tried on five
/// passes, then given up and counted once as failed; a session promoted
/// by hand before the pass is skipped; a signed session and a shadow
/// would-be block without a trace verdict are never promoted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failing_manual_signed_and_untraced_sessions() {
    let h = traced_harness().await;
    let finalizer = &h.state.finalizer;
    let failing = traced_and_closed(&h, "t-failing").await;
    let atif = failing.atif_path.lock().clone().expect("an unsigned trajectory");
    std::fs::remove_file(&atif).unwrap();
    let mut attempts = 0;
    for _ in 0..8 {
        if h.state.sessions.judged_unpromoted().is_empty() {
            break;
        }
        attempts += 1;
        assert_eq!(finalizer.promote_judged_sessions(&h.state.sessions).await, 0);
    }
    assert_eq!(attempts, 5);
    assert!(!failing.is_promoted());
    assert!(h
        .state
        .metrics
        .render()
        .contains("pv_judge_auto_promotions_total{outcome=\"failed\"} 1"));

    let manual = traced_and_closed(&h, "t-manual").await;
    finalizer.promote(Arc::clone(&manual)).await.unwrap();
    assert!(h.state.sessions.judged_unpromoted().is_empty());
    assert_eq!(finalizer.promote_judged_sessions(&h.state.sessions).await, 0);

    assert_eq!(
        call(&h, "t-signed", "signed", "read_ticket", json!({"id": 7})).await,
        200
    );
    events(&h.bus, "agent.judge", "t-signed", 1).await;
    let signed = h.state.sessions.get("t-signed").unwrap();
    finalizer
        .close_session(Arc::clone(&signed), pv_events::StopReason::SessionClosed)
        .await
        .unwrap();
    assert!(h.state.sessions.judged_unpromoted().is_empty());

    let mut shadow = judge_config();
    shadow.mode = JudgeModeConfig::Shadow;
    let shadow_mock = mock();
    shadow_mock.set_default(mismatch(0.9));
    let s = build(shadow, &shadow_mock, |_| {});
    assert_eq!(
        call(&s, "t-shadow", "unsigned", "update_ticket", json!({"note": "x"})).await,
        200
    );
    let judged = events(&s.bus, "agent.judge", "t-shadow", 1).await;
    assert_eq!(judged[0]["payload"]["kind"], "shadow");
    let session = s.state.sessions.get("t-shadow").unwrap();
    s.state
        .finalizer
        .close_session(Arc::clone(&session), pv_events::StopReason::SessionClosed)
        .await
        .unwrap();
    assert!(s.state.sessions.judged_unpromoted().is_empty());
    assert_eq!(
        s.state.finalizer.promote_judged_sessions(&s.state.sessions).await,
        0
    );
}
