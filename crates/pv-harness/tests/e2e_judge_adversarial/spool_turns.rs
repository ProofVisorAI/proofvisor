//! The tool-execution folder's turn-taking (spool.rs), through the live
//! router: many sessions closing at once while other sessions keep
//! making new tool calls. The scan limit is tested at unit level
//! (`routes_edge_extra_tests.rs`), with a small limit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use crate::common;

use axum::response::IntoResponse as _;
use pv_harness::judge::{
    JudgeAdapterConfig, JudgeAdapterKind, JudgeConfig, JudgeFailureConfig, JudgeModeConfig,
    JudgePredicateBinding, JudgeService, JudgeThresholdConfig, JudgeToolConfig,
};
use pv_harness::{AppState, HarnessConfig};
use pv_judge::mock::{MockBehavior, MockJudge};
use pv_judge::{ModelPin, ARG_MATCHES_TASK};
use pv_sandbox::{Sandbox, SandboxConfig};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const TOOL: &str = "update_ticket";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn pin() -> ModelPin {
    ModelPin::new("spool-judge", "1", "ed".repeat(32)).unwrap()
}

fn judge_config() -> JudgeConfig {
    JudgeConfig {
        mode: JudgeModeConfig::Enforce,
        max_concurrency: 256,
        adapters: vec![JudgeAdapterConfig {
            name: "edge".into(),
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
            endpoint: Some("http://127.0.0.1:9/x".to_owned()),
            bearer_file: None,
            redact: true,
        }],
        tools: vec![JudgeToolConfig {
            tool: TOOL.into(),
            predicates: vec![JudgePredicateBinding {
                id: ARG_MATCHES_TASK.into(),
                adapter: "edge".into(),
            }],
            allow_cloud: true,
        }],
        thresholds: vec![JudgeThresholdConfig {
            predicate: ARG_MATCHES_TASK.into(),
            label: "mismatch".into(),
            deny_above: Some(0.7),
            ask_above: Some(0.3),
            min_confidence: None,
        }],
        on_failure: JudgeFailureConfig::default(),
        predicates: Vec::new(),
        pilot: None,
        drift: None,
        background_max_concurrency: 64,
        max_concurrency_per_caller: None,
        trace: None,
        breaker: None,
        standing_rules: Vec::new(),
        record_inputs: false,
    }
}

#[derive(Clone)]
struct Harness {
    state: Arc<AppState>,
}

fn build(tweak: impl FnOnce(&mut HarnessConfig)) -> Harness {
    let judge = judge_config();
    let mut config = common::leaked_test_config();
    tweak(&mut config);
    config.judge = Some(judge.clone());
    let mut schemas = HashMap::new();
    schemas.insert(TOOL.to_owned(), json!({"type": "object"}));
    schemas.insert("read_ticket".to_owned(), json!({"type": "object"}));
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
    let state = common::app_state(config, sandbox, Arc::clone(&bus) as _, 9);
    let mock = Arc::new(MockJudge::new(
        pin(),
        MockBehavior::scores(&[("match", 0.95), ("mismatch", 0.05)]),
    ));
    let mut adapters: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>> = BTreeMap::new();
    adapters.insert("edge".into(), mock as _);
    let service = JudgeService::new(&judge, adapters, Arc::clone(&state.metrics)).unwrap();
    Harness {
        state: Arc::new((*state).clone().with_judge(Arc::new(service))),
    }
}

async fn tool_call(h: &Harness, session: &str, tool: &str) -> (u16, Value) {
    let body = json!({"jsonrpc": "2.0", "id": NEXT_ID.fetch_add(1, Ordering::SeqCst), "method": "tools/call",
                      "params": {"name": tool, "arguments": {"note": "x"}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("x-pv-session", session)
        .header("x-pv-workflow", "unsigned")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let router = pv_harness::build_router((*h.state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn raw_backend() -> String {
    let body = json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}})
        .to_string()
        .into_bytes();
    let router = axum::Router::new().fallback(move || {
        let body = body.clone();
        async move { ([("content-type", "application/json")], body).into_response() }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/rpc", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    url
}

async fn close(h: &Harness, session: &str) -> Result<(), String> {
    let Some(session) = h.state.sessions.get(session) else {
        return Err(format!("{session} is not open"));
    };
    h.state
        .finalizer
        .close_session(session, pv_events::StopReason::SessionClosed)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn tool_dir(h: &Harness) -> std::path::PathBuf {
    std::path::Path::new(&h.state.config.atif_spool_dir).join("tool-executions")
}

fn files_by_kind(h: &Harness) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(tool_dir(h)) {
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let suffix = name.split_once('.').map_or(name.clone(), |(_, s)| s.to_owned());
            *counts.entry(suffix).or_default() += 1;
        }
    }
    counts
}

async fn backend_harness() -> Harness {
    let url = raw_backend().await;
    build(|config| {
        config.tool_upstream_url = Some(url);
        config.tool_upstream_transport = pv_harness::config::BackendTransport::JsonRpc;
    })
}

/// Sessions close all at once while other sessions keep making new tool
/// calls (which create intent files, and write outcome and audited files
/// by renaming a temporary file into the folder). Every close must
/// succeed, and once every session is closed no tool file may be left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn closes_racing_new_tool_calls_all_succeed_and_leave_no_files() {
    let mut close_errors = Vec::new();
    let mut call_errors = Vec::new();
    let mut left_per_round = Vec::new();
    for round in 0..1 {
        let h = backend_harness().await;
        const N: usize = 20;
        for n in 0..N {
            for tool in [TOOL, "read_ticket"] {
                let (status, body) = tool_call(&h, &format!("r{round}-old-{n}"), tool).await;
                assert_eq!(status, 200, "{body}");
            }
        }
        // New tool calls in other sessions, running for as long as the closes do.
        let stop = Arc::new(AtomicBool::new(false));
        let mut busy = Vec::new();
        for worker in 0..8 {
            let (h, stop) = (h.clone(), Arc::clone(&stop));
            busy.push(tokio::spawn(async move {
                let mut errors = Vec::new();
                let mut sessions = Vec::new();
                let mut n = 0;
                // At most 4 each, so the sequential closes below stay few.
                while !stop.load(Ordering::SeqCst) && n < 4 {
                    let session = format!("r{round}-new-{worker}-{n}");
                    for tool in [TOOL, "read_ticket"] {
                        let (status, body) = tool_call(&h, &session, tool).await;
                        if status != 200 {
                            errors.push(format!("{session} {tool}: {status} {body}"));
                        }
                    }
                    sessions.push(session);
                    n += 1;
                }
                (sessions, errors)
            }));
        }
        let mut closes = Vec::new();
        for n in 0..N {
            let h = h.clone();
            closes.push(tokio::spawn(async move {
                let session = format!("r{round}-old-{n}");
                close(&h, &session).await.map_err(|e| format!("{session}: {e}"))
            }));
        }
        for close in closes {
            if let Err(error) = close.await.unwrap() {
                close_errors.push(error);
            }
        }
        stop.store(true, Ordering::SeqCst);
        let mut new_sessions = Vec::new();
        for task in busy {
            let (sessions, errors) = task.await.unwrap();
            new_sessions.extend(sessions);
            call_errors.extend(errors);
        }
        // With nothing else running, close the new sessions one at a time.
        for session in &new_sessions {
            if let Err(error) = close(&h, session).await {
                close_errors.push(format!("{session} (sequential): {error}"));
            }
        }
        let left = files_by_kind(&h);
        eprintln!(
            "round {round}: {} new sessions made beside {N} closes; files left {left:?}",
            new_sessions.len()
        );
        left_per_round.push(left);
    }
    eprintln!(
        "close errors ({}): {:?}",
        close_errors.len(),
        &close_errors[..close_errors.len().min(6)]
    );
    eprintln!(
        "tool call errors ({}): {:?}",
        call_errors.len(),
        &call_errors[..call_errors.len().min(3)]
    );
    assert!(
        close_errors.is_empty(),
        "{} closes failed while other sessions made tool calls; first: {:?}",
        close_errors.len(),
        &close_errors[..close_errors.len().min(3)]
    );
    assert!(
        left_per_round.iter().all(BTreeMap::is_empty),
        "tool files left after every session closed: {left_per_round:?}"
    );
}
