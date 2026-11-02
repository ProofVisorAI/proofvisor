//! Edge cases of the semantic judge through the live router.
//!
//! * Calls the earlier gates refuse never reach the judge.
//! * Odd arguments (missing, Unicode, control characters, 1 MiB) reach
//!   the judge intact.
//! * Retries with forwarding on: a refused call stays refused, an allowed
//!   call executes once.
//! * Many judged calls at once in one session.
//! * Hostile or unusual answers from a real HTTP judge.
//! * Operator endpoint and drift-file edge cases; shadow mode with the
//!   drift switch on; multi-hop and self-referencing delegation.
//! * Threshold boundaries, a crashing version 2 WASM policy, and config
//!   values at and past their limits.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use parking_lot::Mutex;
use pv_harness::judge::{
    JudgeAdapterConfig, JudgeAdapterKind, JudgeConfig, JudgeDriftConfig, JudgeFailureConfig, JudgeModeConfig,
    JudgePredicateBinding, JudgeService, JudgeThresholdConfig, JudgeToolConfig,
};
use pv_harness::{AppState, HarnessConfig};
use pv_judge::mock::{MockBehavior, MockJudge};
use pv_judge::{ModelPin, ARG_MATCHES_TASK, CHILD_USES_PARENT_ENTITLEMENT};
use pv_sandbox::{PolicyEngine, Sandbox, SandboxConfig};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HMAC_SECRET: &[u8] = b"judge-edges-hmac-secret-32-bytes";
const HMAC_KID: &str = "edges-kid";
const OPERATOR_TOKEN: &str = "edges-operator-token-0123456789abcdef";
const TOOL: &str = "update_ticket";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn pin() -> ModelPin {
    ModelPin::new("edge-judge", "1", "ed".repeat(32)).unwrap()
}

fn judge_config(mode: JudgeModeConfig, endpoint: &str) -> JudgeConfig {
    JudgeConfig {
        mode,
        max_concurrency: 64,
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
            endpoint: Some(endpoint.to_owned()),
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
    }
}

fn mismatch(p: f64) -> MockBehavior {
    MockBehavior::scores(&[("match", 1.0 - p), ("mismatch", p)])
}

#[derive(Clone)]
struct Harness {
    state: Arc<AppState>,
    bus: Arc<common::RecordingBus>,
}

struct Setup {
    judge: JudgeConfig,
    policies: Vec<Box<dyn PolicyEngine>>,
    /// `None`: a scripted judge; `Some`: build the real adapters from config.
    real_adapters: bool,
}

fn build(setup: Setup, mock: &Arc<MockJudge>, tweak: impl FnOnce(&mut HarnessConfig)) -> Harness {
    let mut config = common::leaked_test_config();
    tweak(&mut config);
    config.judge = Some(setup.judge.clone());
    let mut schemas = HashMap::new();
    schemas.insert(
        TOOL.to_owned(),
        json!({"type": "object", "properties": {"note": {"type": "string"}, "n": {"type": "integer"}}}),
    );
    let sandbox = Sandbox::new(
        SandboxConfig {
            schemas,
            budget: config.budget.clone(),
            payout_field: config.payout_field.clone(),
            require_schema: false,
        },
        setup.policies,
    )
    .unwrap()
    .with_judge_policy(setup.judge.threshold_policy().unwrap());
    let bus = Arc::new(common::RecordingBus::default());
    let state = if config.require_identity {
        common::app_state_with_identity(config, sandbox, Arc::clone(&bus) as _, 9, HMAC_SECRET, HMAC_KID)
    } else {
        common::app_state(config, sandbox, Arc::clone(&bus) as _, 9)
    };
    let adapters = if setup.real_adapters {
        pv_harness::judge::build_adapters(&setup.judge, None).unwrap()
    } else {
        let mut adapters: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>> = BTreeMap::new();
        adapters.insert("edge".into(), Arc::clone(mock) as _);
        adapters
    };
    let service = JudgeService::new(&setup.judge, adapters, Arc::clone(&state.metrics)).unwrap();
    Harness {
        state: Arc::new((*state).clone().with_judge(Arc::new(service))),
        bus,
    }
}

fn scripted(judge: JudgeConfig, tweak: impl FnOnce(&mut HarnessConfig)) -> (Harness, Arc<MockJudge>) {
    let mock = Arc::new(MockJudge::new(pin(), mismatch(0.05)));
    let h = build(
        Setup {
            judge,
            policies: Vec::new(),
            real_adapters: false,
        },
        &mock,
        tweak,
    );
    (h, mock)
}

struct Reply {
    status: u16,
    json: Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.json["error"]["data"]["code"].as_str().unwrap_or("<none>")
    }
}

async fn send(h: &Harness, request: axum::http::Request<axum::body::Body>) -> Reply {
    let router = pv_harness::build_router((*h.state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 64 << 20)
        .await
        .unwrap();
    Reply {
        status,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn rpc(session: &str, body: &Value, extra: &[(&str, &str)]) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header("content-type", "application/json")
        .header("x-pv-session", session);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(axum::body::Body::from(body.to_string())).unwrap()
}

fn tools_call(tool: &str, arguments: Option<Value>) -> Value {
    let mut params = json!({"name": tool});
    if let Some(arguments) = arguments {
        params["arguments"] = arguments;
    }
    json!({"jsonrpc": "2.0", "id": NEXT_ID.fetch_add(1, Ordering::SeqCst), "method": "tools/call", "params": params})
}

async fn call(h: &Harness, session: &str, arguments: Value) -> Reply {
    send(h, rpc(session, &tools_call(TOOL, Some(arguments)), &[])).await
}

async fn tool_events(bus: &common::RecordingBus, session: &str, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events: Vec<Value> = bus
            .payloads
            .lock()
            .iter()
            .filter(|event| event["class_name"] == "agent.tool_call" && event["session_uid"] == session)
            .cloned()
            .collect();
        if events.len() >= count {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "only {} tool events for {session}",
            events.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn token(
    instance_uid: &str,
    jti: &str,
    parent: Option<String>,
    act: Option<pv_identity::ActorClaim>,
) -> String {
    let now = pv_core::time::now_ms() / 1000;
    let claims = pv_identity::NhiClaims {
        sub: "user:edge@acme.io".into(),
        iss: "edge-issuer".into(),
        aud: pv_identity::Audience::Single("agentvisor-ai".to_owned()),
        iat: now,
        nbf: None,
        exp: now + 300,
        jti: jti.to_owned(),
        azp: Some("edge-app".into()),
        act,
        instance_uid: instance_uid.to_owned(),
        charter: "edge-agent".into(),
        version: "1.0".into(),
        scopes: vec!["tool:*".into()],
        parent_token: parent,
    };
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some(HMAC_KID.to_owned()),
        ..Default::default()
    };
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(HMAC_SECRET),
    )
    .unwrap()
}

// ── Gate order ──────────────────────────────────────────────────────

#[tokio::test]
async fn calls_the_earlier_gates_refuse_never_reach_the_judge() {
    // Consequential tool on the unsigned workflow.
    let (h, mock) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |config| {
            config.consequential_tools = vec![TOOL.into()];
        },
    );
    let reply = call(&h, "g-1", json!({"note": "x"})).await;
    assert_eq!(reply.code(), "POLICY_DENIED", "{}", reply.json);
    assert_eq!(mock.calls(), 0);

    // Unmapped tool with intent mapping required; expired mission.
    let (h, mock) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |config| {
            config.require_intent_mapping = true;
        },
    );
    assert_eq!(
        call(&h, "g-2", json!({"note": "x"})).await.code(),
        "UNMAPPED_TOOL"
    );
    let (h2, mock2) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |config| {
            config.mission = Some(pv_harness::config::MissionConfig {
                id: "old".into(),
                allowed_intents: vec![TOOL.into()],
                expires_at: 1,
                agents: Vec::new(),
                charters: Vec::new(),
                subjects: Vec::new(),
                task: Some("expired task".into()),
            });
        },
    );
    assert_eq!(
        call(&h2, "g-3", json!({"note": "x"})).await.code(),
        "MISSION_EXPIRED"
    );

    assert_eq!(
        mock.calls() + mock2.calls(),
        0,
        "no refused call reached the judge"
    );

    // Schema violation; a notification (no id); a batch.
    let (h3, mock3) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |_| {},
    );
    assert_eq!(
        call(&h3, "g-4", json!({"n": "not a number"})).await.code(),
        "SCHEMA_VIOLATION"
    );
    let notification =
        json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": TOOL, "arguments": {}}});
    assert_eq!(send(&h3, rpc("g-5", &notification, &[])).await.status, 400);
    let batch = json!([tools_call(TOOL, Some(json!({})))]);
    assert_eq!(send(&h3, rpc("g-6", &batch, &[])).await.status, 400);
    assert_eq!(mock3.calls(), 0, "no refused call reached the judge");

    // Identity required and no token.
    let (h, mock) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |config| {
            config.require_identity = true;
        },
    );
    assert_eq!(call(&h, "g-7", json!({"note": "x"})).await.status, 401);
    assert_eq!(mock.calls(), 0);
}

#[tokio::test]
async fn a_closed_session_refuses_without_recording_a_denial() {
    let (h, mock) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |_| {},
    );
    assert_eq!(call(&h, "c-1", json!({"note": "x"})).await.status, 200);
    let session = h.state.sessions.get("c-1").unwrap();
    h.state
        .finalizer
        .close_session(session, pv_events::StopReason::SessionClosed)
        .await
        .unwrap();
    mock.set_default(mismatch(0.95));
    let reply = call(&h, "c-1", json!({"note": "x"})).await;
    assert_eq!(reply.status, 400, "{}", reply.json);
    // A new session of the same agent starts without that refusal.
    mock.set_default(mismatch(0.05));
    call(&h, "c-2", json!({"note": "y"})).await;
    assert!(mock.last_request().unwrap().context.prior_denials.is_empty());
}

// ── Arguments ───────────────────────────────────────────────────────

#[tokio::test]
async fn unusual_arguments_reach_the_judge_intact() {
    let (h, mock) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |config| {
            config.max_request_bytes = 8 << 20;
        },
    );
    // Missing arguments are an empty object.
    let reply = send(&h, rpc("a-1", &tools_call(TOOL, None), &[])).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(mock.last_request().unwrap().validated_args, json!({}));
    // Unicode, right-to-left text, emoji, control characters, nesting.
    let odd = json!({"note": "مرحبا 👋 \u{202E}evil\u{202C} line1\nline2\t\u{0007}", "n": -0,
                     "nested": {"deep": [1, {"x": null}]}});
    assert_eq!(call(&h, "a-2", odd.clone()).await.status, 200);
    assert_eq!(mock.last_request().unwrap().validated_args, odd);
    // A 1 MiB argument.
    let large = json!({"note": "x".repeat(1 << 20)});
    let started = Instant::now();
    let reply = call(&h, "a-3", large.clone()).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(mock.last_request().unwrap().validated_args, large);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    tool_events(&h.bus, "a-3", 1).await;
}

// ── Retries and forwarding ──────────────────────────────────────────

#[tokio::test]
async fn retries_keep_refusals_refused_and_execute_allowed_calls_once() {
    let backend = common::MockBackend::start().await;
    let (h, mock) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |config| {
            config.tool_upstream_url = Some(backend.url.clone());
            config.tool_upstream_transport = pv_harness::config::BackendTransport::JsonRpc;
        },
    );
    let denied_call = json!({"jsonrpc": "2.0", "id": "retry-deny", "method": "tools/call",
                             "params": {"name": TOOL, "arguments": {"note": "drop everything"}}});
    mock.set_default(mismatch(0.95));
    for attempt in 0..3 {
        let reply = send(&h, rpc("r-1", &denied_call, &[])).await;
        assert_eq!(reply.code(), "JUDGE_DENIED", "attempt {attempt}: {}", reply.json);
    }
    assert!(
        backend.tool_calls().is_empty(),
        "a refused call must never execute"
    );

    mock.set_default(mismatch(0.05));
    let allowed_call = json!({"jsonrpc": "2.0", "id": "retry-ok", "method": "tools/call",
                              "params": {"name": TOOL, "arguments": {"note": "add a note"}}});
    let judged_before = mock.calls();
    for attempt in 0..3 {
        let reply = send(&h, rpc("r-1", &allowed_call, &[])).await;
        assert_eq!(reply.status, 200, "attempt {attempt}: {}", reply.json);
    }
    assert_eq!(
        backend.tool_calls().len(),
        1,
        "an allowed call executes exactly once"
    );
    assert_eq!(
        mock.calls() - judged_before,
        1,
        "replays of a completed call are not re-judged"
    );
    // Reusing the id with other arguments is refused, never judged.
    let reused = json!({"jsonrpc": "2.0", "id": "retry-ok", "method": "tools/call",
                        "params": {"name": TOOL, "arguments": {"note": "something else"}}});
    assert_eq!(send(&h, rpc("r-1", &reused, &[])).await.status, 409);
    assert_eq!(mock.calls() - judged_before, 1);
}

// ── Concurrency ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn many_judged_calls_at_once_in_one_session() {
    let (h, mock) = scripted(
        judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
        |_| {},
    );
    mock.set_scorer(|request| {
        let risky = request.validated_args["n"].as_i64().unwrap_or(0) % 2 == 1;
        MockBehavior::delayed(
            Duration::from_millis(20),
            mismatch(if risky { 0.95 } else { 0.05 }),
        )
    });
    let mut handles = Vec::new();
    for n in 0..60 {
        let h = h.clone();
        handles.push(tokio::spawn(async move {
            (n, call(&h, "p-1", json!({"n": n})).await)
        }));
    }
    for handle in handles {
        let (n, reply) = handle.await.unwrap();
        if n % 2 == 1 {
            assert_eq!(reply.code(), "JUDGE_DENIED", "call {n}: {}", reply.json);
        } else {
            assert_eq!(reply.status, 200, "call {n}: {}", reply.json);
        }
    }
    assert_eq!(tool_events(&h.bus, "p-1", 60).await.len(), 60);
    // The refusal history the judge sees is bounded.
    call(&h, "p-1", json!({"n": 100})).await;
    let seen = mock.last_request().unwrap();
    assert!(
        seen.context.prior_denials.len() <= 16,
        "{}",
        seen.context.prior_denials.len()
    );
    assert!(!seen.context.prior_denials.is_empty());
}

// ── A real HTTP judge answering oddly ───────────────────────────────

type Respond = Box<dyn Fn() -> axum::response::Response + Send + Sync>;
type Responder = Arc<Mutex<Respond>>;

async fn odd_judge() -> (String, Responder) {
    let responder: Responder = Arc::new(Mutex::new(Box::new(|| StatusCode::OK.into_response())));
    let shared = Arc::clone(&responder);
    let router = Router::new().route(
        "/score",
        post(move || {
            let shared = Arc::clone(&shared);
            async move { (shared.lock())() }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/score", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (url, responder)
}

use axum::response::IntoResponse as _;

fn answer(body: String) -> Respond {
    Box::new(move || {
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            body.clone(),
        )
            .into_response()
    })
}

fn model() -> String {
    format!(
        r#"{{"name":"edge-judge","version":"1","weights_sha256":"{}"}}"#,
        "ed".repeat(32)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn odd_answers_from_a_real_http_judge() {
    let (url, responder) = odd_judge().await;
    let mut judge = judge_config(JudgeModeConfig::Enforce, &url);
    judge.adapters[0].deadline_ms = Some(500);
    let mock = Arc::new(MockJudge::new(pin(), mismatch(0.0)));
    let h = build(
        Setup {
            judge,
            policies: Vec::new(),
            real_adapters: true,
        },
        &mock,
        |_| {},
    );
    let m = model();
    let cases: Vec<(&str, Respond, &str)> = vec![
        (
            "labels in another order",
            answer(format!(
                r#"{{"model":{m},"probs":[{{"label":"mismatch","p":0.9}},{{"label":"match","p":0.1}}]}}"#
            )),
            "JUDGE_DENIED",
        ),
        (
            "sum 1.0011 is malformed",
            answer(format!(
                r#"{{"model":{m},"probs":[{{"label":"match","p":0.9011}},{{"label":"mismatch","p":0.1}}]}}"#
            )),
            "APPROVAL_REQUIRED",
        ),
        (
            "label case differs",
            answer(format!(
                r#"{{"model":{m},"probs":[{{"label":"Match","p":0.99}},{{"label":"mismatch","p":0.01}}]}}"#
            )),
            "APPROVAL_REQUIRED",
        ),
        (
            "probabilities as strings",
            answer(format!(
                r#"{{"model":{m},"probs":[{{"label":"match","p":"0.99"}},{{"label":"mismatch","p":"0.01"}}]}}"#
            )),
            "APPROVAL_REQUIRED",
        ),
        (
            "extra field in the model",
            answer(format!(
                r#"{{"model":{{"name":"edge-judge","version":"1","weights_sha256":"{}","region":"eu"}},"probs":[{{"label":"match","p":0.99}},{{"label":"mismatch","p":0.01}}]}}"#,
                "ed".repeat(32)
            )),
            "APPROVAL_REQUIRED",
        ),
        (
            "missing model",
            answer(r#"{"probs":[{"label":"match","p":0.99},{"label":"mismatch","p":0.01}]}"#.to_owned()),
            "APPROVAL_REQUIRED",
        ),
        ("empty body", answer(String::new()), "APPROVAL_REQUIRED"),
        (
            "70 KiB body",
            answer(format!(
                r#"{{"model":{m},"pad":"{}","probs":[{{"label":"match","p":0.99}},{{"label":"mismatch","p":0.01}}]}}"#,
                "x".repeat(70 * 1024)
            )),
            "APPROVAL_REQUIRED",
        ),
        (
            "HTTP 429",
            Box::new(|| StatusCode::TOO_MANY_REQUESTS.into_response()),
            "JUDGE_UNAVAILABLE",
        ),
        (
            "HTTP 500",
            Box::new(|| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            "JUDGE_UNAVAILABLE",
        ),
    ];
    for (name, respond, expected) in cases {
        *responder.lock() = respond;
        let reply = call(&h, &format!("o-{}", name.len()), json!({"note": name})).await;
        assert_eq!(reply.code(), expected, "{name}: {}", reply.json);
    }
    // Plain allows: extra top-level fields, integer and negative-zero probabilities.
    for (name, body) in [
        (
            "sum 1.0009 is within tolerance",
            format!(
                r#"{{"model":{m},"probs":[{{"label":"match","p":0.9009}},{{"label":"mismatch","p":0.1}}]}}"#
            ),
        ),
        (
            "extra top-level field",
            format!(
                r#"{{"model":{m},"note":"v2","probs":[{{"label":"match","p":0.99}},{{"label":"mismatch","p":0.01}}]}}"#
            ),
        ),
        (
            "integer probabilities",
            format!(r#"{{"model":{m},"probs":[{{"label":"match","p":1}},{{"label":"mismatch","p":0}}]}}"#),
        ),
        (
            "negative zero",
            format!(
                r#"{{"model":{m},"probs":[{{"label":"match","p":1.0}},{{"label":"mismatch","p":-0.0}}]}}"#
            ),
        ),
    ] {
        *responder.lock() = answer(body);
        let reply = call(&h, "o-allow", json!({"note": name})).await;
        assert_eq!(reply.status, 200, "{name}: {}", reply.json);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_judge_that_trickles_its_answer_past_the_deadline_times_out() {
    // Headers at once, body only after the deadline.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/score", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buffer = vec![0u8; 65_536];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 400\r\n\r\n{\"model\":")
                    .await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    let mut judge = judge_config(JudgeModeConfig::Enforce, &url);
    judge.adapters[0].deadline_ms = Some(300);
    let mock = Arc::new(MockJudge::new(pin(), mismatch(0.0)));
    let h = build(
        Setup {
            judge,
            policies: Vec::new(),
            real_adapters: true,
        },
        &mock,
        |_| {},
    );
    let started = Instant::now();
    let reply = call(&h, "t-1", json!({"note": "x"})).await;
    assert_eq!(reply.code(), "JUDGE_UNAVAILABLE", "{}", reply.json);
    assert!(
        started.elapsed() < Duration::from_millis(1_500),
        "{:?}",
        started.elapsed()
    );
}

// ── Operator endpoints, drift file, shadow + drift ──────────────────

fn with_drift(mode: JudgeModeConfig, state_file: &str) -> JudgeConfig {
    let mut judge = judge_config(mode, "http://127.0.0.1:9/x");
    judge.drift = Some(JudgeDriftConfig {
        state_file: state_file.to_owned(),
        sample_every: 1,
        min_reviews_per_band: 1,
        tolerance: 0.0,
        max_pending: 4,
    });
    judge
}

fn operators(config: &mut HarnessConfig) {
    config.operator_tokens = vec![pv_harness::config::OperatorTokenConfig {
        name: "ops".into(),
        sha256: pv_core::digest::sha256_hex(OPERATOR_TOKEN.as_bytes()),
    }];
}

async fn admin(h: &Harness, method: &str, path: &str, body: &str, authorized: bool) -> Reply {
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if authorized {
        builder = builder.header("authorization", format!("Bearer {OPERATOR_TOKEN}"));
    }
    send(h, builder.body(axum::body::Body::from(body.to_owned())).unwrap()).await
}

#[tokio::test]
async fn operator_endpoint_edge_cases() {
    let dir = tempfile::tempdir().unwrap();
    // A state file that cannot even be read stops the start.
    std::fs::write(dir.path().join("blocker"), "not a directory").unwrap();
    let unreadable = with_drift(
        JudgeModeConfig::Enforce,
        &dir.path().join("blocker/drift.json").to_string_lossy(),
    );
    let mut adapters: BTreeMap<String, Arc<dyn pv_judge::JudgeAdapter>> = BTreeMap::new();
    adapters.insert("edge".into(), Arc::new(MockJudge::new(pin(), mismatch(0.0))) as _);
    let error = JudgeService::new(&unreadable, adapters, Arc::new(pv_core::metrics::Registry::new()))
        .err()
        .unwrap();
    assert!(error.contains("drift state file"), "{error}");
    // A state directory that becomes read-only while running: saves fail,
    // the switch still applies, and the response says it was not saved.
    let state_dir = dir.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    let (h, mock) = scripted(
        with_drift(
            JudgeModeConfig::Enforce,
            &state_dir.join("drift.json").to_string_lossy(),
        ),
        operators,
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    assert_eq!(
        admin(&h, "GET", "/admin/v1/judge/drift", "", false).await.status,
        401
    );
    assert_eq!(
        admin(&h, "POST", "/admin/v1/judge/reviews", "{not json", true)
            .await
            .status,
        400
    );
    assert_eq!(
        admin(
            &h,
            "POST",
            "/admin/v1/judge/reviews",
            r#"{"review_id":"x","correct":true,"extra":1}"#,
            true
        )
        .await
        .status,
        400
    );
    assert_eq!(
        admin(
            &h,
            "POST",
            "/admin/v1/judge/reviews",
            r#"{"review_id":"never-sampled","correct":true}"#,
            true
        )
        .await
        .status,
        404
    );
    let reset = admin(
        &h,
        "POST",
        "/admin/v1/judge/drift/reset",
        r#"{"predicate_id":"nope@1"}"#,
        true,
    )
    .await;
    assert_eq!(reset.status, 200);
    assert_eq!(reset.json["was_tripped"], false);
    assert_eq!(reset.json["persisted"], false);
    // Sampled ids are bounded (max_pending = 4): the oldest is dropped.
    for n in 0..6 {
        mock.set_default(mismatch(if n % 2 == 0 { 0.05 } else { 0.25 }));
        call(&h, &format!("d-{n}"), json!({"n": n})).await;
    }
    let first = tool_events(&h.bus, "d-0", 1).await[0]["payload"]["judge"]["verdicts"][0]["review_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let evicted = admin(
        &h,
        "POST",
        "/admin/v1/judge/reviews",
        &json!({"review_id": first, "correct": true}).to_string(),
        true,
    )
    .await;
    assert_eq!(evicted.status, 404, "{}", evicted.json);
    let recent = tool_events(&h.bus, "d-5", 1).await[0]["payload"]["judge"]["verdicts"][0]["review_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let saved = admin(
        &h,
        "POST",
        "/admin/v1/judge/reviews",
        &json!({"review_id": recent, "correct": true}).to_string(),
        true,
    )
    .await;
    assert_eq!(saved.status, 200, "{}", saved.json);
    assert_eq!(saved.json["persisted"], false);
    let metrics = h.state.metrics.render();
    assert!(
        metrics.contains("pv_judge_drift_persist_failures_total"),
        "missing failure counter"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[tokio::test]
async fn shadow_mode_never_blocks_even_with_the_drift_switch_on() {
    let dir = tempfile::tempdir().unwrap();
    let state_file = dir.path().join("drift.json");
    let (h, mock) = scripted(
        with_drift(JudgeModeConfig::Shadow, &state_file.to_string_lossy()),
        operators,
    );
    let drift = h.state.judge.as_ref().unwrap().drift().unwrap();
    for (top, correct, id) in [(0.75, true, "lo"), (0.95, false, "hi")] {
        let verdict = pv_judge::Verdict {
            predicate_id: ARG_MATCHES_TASK.into(),
            probs: vec![
                pv_judge::LabelProb {
                    label: "match".into(),
                    ppm: pv_judge::prob_to_ppm(top),
                },
                pv_judge::LabelProb {
                    label: "mismatch".into(),
                    ppm: pv_judge::prob_to_ppm(1.0 - top),
                },
            ],
            model: pin(),
            latency_us: 1,
        };
        let review = drift.maybe_sample(&verdict, || id.to_owned()).unwrap();
        drift.record_review(&review, correct).unwrap();
    }
    assert!(drift.is_tripped(ARG_MATCHES_TASK));
    mock.set_default(mismatch(0.05));
    let reply = call(&h, "sd-1", json!({"note": "x"})).await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    let record = &tool_events(&h.bus, "sd-1", 1).await[0]["payload"]["judge"];
    assert_eq!(record["would_block"], true);
    assert_eq!(record["cause"]["kind"], "drift_gate");
    assert_eq!(record["drift_tripped"], json!([ARG_MATCHES_TASK]));
}

// ── Delegation ──────────────────────────────────────────────────────

#[tokio::test]
async fn multi_hop_and_self_referencing_delegation() {
    let mut judge = judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x");
    judge.tools[0].predicates.push(JudgePredicateBinding {
        id: CHILD_USES_PARENT_ENTITLEMENT.into(),
        adapter: "edge".into(),
    });
    let (h, mock) = scripted(judge, |config| config.require_identity = true);
    let auth = |t: &str| format!("Bearer {t}");
    // The grandparent is refused.
    mock.set_default(mismatch(0.95));
    let grandparent = token("agent-gp", "jti-gp", None, None);
    let reply = send(
        &h,
        rpc(
            "m-gp",
            &tools_call(TOOL, Some(json!({"note": "x"}))),
            &[("authorization", &auth(&grandparent))],
        ),
    )
    .await;
    assert_eq!(reply.code(), "JUDGE_DENIED", "{}", reply.json);
    // grandchild → child → grandparent: the grandchild sees the grandparent.
    let child = token("agent-c", "jti-c", Some(grandparent), None);
    let grandchild = token("agent-gc", "jti-gc", Some(child), None);
    mock.set_default(mismatch(0.05));
    send(
        &h,
        rpc(
            "m-gc",
            &tools_call(TOOL, Some(json!({"note": "y"}))),
            &[("authorization", &auth(&grandchild))],
        ),
    )
    .await;
    let seen = mock.last_request().unwrap();
    assert_eq!(seen.context.delegation_depth, 2);
    assert!(seen
        .context
        .prior_denials
        .iter()
        .any(|denial| denial.instance_uid == "agent-gp" && denial.source == pv_judge::DenialSource::Parent));
    // An `act` claim naming the caller itself adds no parent: the agent's
    // own refusals stay "session" ones and are not duplicated as "parent".
    mock.set_default(mismatch(0.95));
    let me = token(
        "agent-self",
        "jti-self-1",
        None,
        Some(pv_identity::ActorClaim {
            sub: "agent-self".into(),
            act: None,
        }),
    );
    send(
        &h,
        rpc(
            "m-self",
            &tools_call(TOOL, Some(json!({"note": "z"}))),
            &[("authorization", &auth(&me))],
        ),
    )
    .await;
    mock.set_default(mismatch(0.05));
    send(
        &h,
        rpc(
            "m-self-2",
            &tools_call(TOOL, Some(json!({"note": "z"}))),
            &[("authorization", &auth(&me))],
        ),
    )
    .await;
    let seen = mock.last_request().unwrap();
    assert!(
        seen.context
            .prior_denials
            .iter()
            .all(|denial| denial.source != pv_judge::DenialSource::Parent),
        "{:?}",
        seen.context.prior_denials
    );
}

// ── Thresholds at their limits ──────────────────────────────────────

#[tokio::test]
async fn threshold_limits() {
    let mut judge = judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x");
    judge.thresholds[0].deny_above = Some(1.0);
    judge.thresholds[0].ask_above = None;
    let (h, mock) = scripted(judge, |_| {});
    mock.set_default(mismatch(1.0));
    assert_eq!(
        call(&h, "l-1", json!({})).await.status,
        200,
        "deny_above = 1 never denies"
    );

    let mut judge = judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x");
    judge.thresholds[0].deny_above = Some(0.0);
    judge.thresholds[0].ask_above = None;
    let (h, mock) = scripted(judge, |_| {});
    mock.set_default(mismatch(0.000_001));
    assert_eq!(call(&h, "l-2", json!({})).await.code(), "JUDGE_DENIED");
    mock.set_default(mismatch(0.0));
    assert_eq!(
        call(&h, "l-2", json!({})).await.status,
        200,
        "exactly 0 is not above 0"
    );

    // Only a confidence floor.
    let mut judge = judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x");
    judge.thresholds[0] = JudgeThresholdConfig {
        predicate: ARG_MATCHES_TASK.into(),
        label: "mismatch".into(),
        deny_above: None,
        ask_above: None,
        min_confidence: Some(0.8),
    };
    let (h, mock) = scripted(judge, |_| {});
    mock.set_default(mismatch(0.25));
    assert_eq!(call(&h, "l-3", json!({})).await.code(), "APPROVAL_REQUIRED");
    mock.set_default(mismatch(0.9));
    assert_eq!(
        call(&h, "l-3", json!({})).await.status,
        200,
        "a confident mismatch passes a floor-only rule"
    );
}

// ── A crashing version 2 policy ─────────────────────────────────────

#[tokio::test]
async fn a_version_2_policy_that_traps_fails_closed() {
    const TRAPS: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) (i32.const 0))
      (func (export "evaluate_v2") (param i32 i32) (result i32) unreachable))
    "#;
    let policy = pv_sandbox::WasmPolicy::from_bytes("trapping-v2", TRAPS.as_bytes()).unwrap();
    let mock = Arc::new(MockJudge::new(pin(), mismatch(0.05)));
    let h = build(
        Setup {
            judge: judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x"),
            policies: vec![Box::new(policy)],
            real_adapters: false,
        },
        &mock,
        |_| {},
    );
    let reply = call(&h, "w-1", json!({"note": "x"})).await;
    assert_eq!(reply.code(), "POLICY_DENIED", "{}", reply.json);
    let record = &tool_events(&h.bus, "w-1", 1).await[0]["payload"]["judge"];
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["policy_decision"], "deny");
    assert_eq!(record["policy"], "trapping-v2");
    assert_eq!(
        record["would_block"], false,
        "it blocks with or without the verdicts"
    );
}

// ── Config values at and past their limits ──────────────────────────

#[test]
fn config_limits() {
    let check = |tweak: &dyn Fn(&mut JudgeConfig)| {
        let mut judge = judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x");
        tweak(&mut judge);
        let mut errors = Vec::new();
        judge.collect_errors(&mut errors);
        errors
    };
    assert!(check(&|_| {}).is_empty());
    assert!(check(&|j| j.adapters[0].deadline_ms = Some(1)).is_empty());
    assert!(check(&|j| j.adapters[0].deadline_ms = Some(30_000)).is_empty());
    assert!(!check(&|j| j.adapters[0].deadline_ms = Some(0)).is_empty());
    assert!(!check(&|j| j.adapters[0].deadline_ms = Some(30_001)).is_empty());
    assert!(check(&|j| j.max_concurrency = 4_096).is_empty());
    assert!(!check(&|j| j.max_concurrency = 0).is_empty());
    assert!(!check(&|j| j.max_concurrency = 4_097).is_empty());
    assert!(check(&|j| j.thresholds[0].deny_above = Some(1.0)).is_empty());
    assert!(!check(&|j| j.thresholds[0].deny_above = Some(1.000_1)).is_empty());
    assert!(!check(&|j| j.thresholds[0].deny_above = Some(f64::NAN)).is_empty());
    assert!(!check(&|j| j.thresholds[0].ask_above = Some(-0.1)).is_empty());
    assert!(check(&|j| j.adapters[0].endpoint = Some("http://[::1]:9/x".into())).is_empty());
    assert!(!check(&|j| j.adapters[0].endpoint = Some("not a url".into())).is_empty());
    assert!(!check(&|j| j.tools[0].tool = String::new()).is_empty());
    assert!(!check(&|j| j.tools[0].tool = "bad\nname".into()).is_empty());
    // Unknown keys anywhere in [judge] are refused.
    for toml in [
        "upstream_url = \"http://x\"\n[judge]\nmode = \"enforce\"\ntypo = 1\n",
        "upstream_url = \"http://x\"\n[judge]\nmode = \"maybe\"\n",
        "upstream_url = \"http://x\"\n[judge]\n",
    ] {
        assert!(HarnessConfig::from_toml(toml).is_err(), "{toml}");
    }
}

#[test]
fn bearer_files_are_checked_when_the_adapters_are_built() {
    let dir = tempfile::tempdir().unwrap();
    let mut judge = judge_config(JudgeModeConfig::Enforce, "http://127.0.0.1:9/x");
    judge.adapters[0].bearer_file = Some(dir.path().join("missing").to_string_lossy().into_owned());
    assert!(pv_harness::judge::build_adapters(&judge, None).is_err());
    let readable = dir.path().join("readable");
    std::fs::write(&readable, "token").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o644)).unwrap();
        judge.adapters[0].bearer_file = Some(readable.to_string_lossy().into_owned());
        let error = pv_harness::judge::build_adapters(&judge, None).err().unwrap();
        assert!(error.contains("owner-only"), "{error}");
        std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(pv_harness::judge::build_adapters(&judge, None).is_ok());
    }
}
