//! The semantic judge end to end in the real `proofvisord` binary, with
//! every neighbouring feature switched on at once:
//!
//! * identity (HMAC tokens, scopes, a delegation chain), the intent map
//!   and a mission with a `task` statement, a principal budget;
//! * a version 1 WASM policy (the built-in payload limit) and a version 2
//!   policy that reads verdicts and asks;
//! * forwarding to a JSON-RPC tool backend, redaction patterns, operator
//!   tokens, the drift gate with its state file, and an HTTP judge.
//!
//! It drives the daemon over HTTP (`/v1/mcp`, `/mcp`, chat, session close,
//! admin routes, `/metrics`) and checks every observable result: the
//! responses, what the backend and the judge received, the events in the
//! embedded Bridge, the signed receipt against an independently held key,
//! the ATIF trajectory, the budget, and the drift switch across a restart.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use axum::routing::post;
use axum::{Json, Router};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HMAC_SECRET: &str = "full-stack-judge-hmac-secret-0123456789abcdef";
const HMAC_KID: &str = "full-kid";
const AUDIENCE: &str = "proofvisor-full";
const OPERATOR_TOKEN: &str = "full-stack-operator-token-0123456789abcdef";
const SIGNING_SEED: [u8; 32] = [42; 32];
const TASK: &str = "Reconcile March invoices for customer 1001";
const PROMPT_SECRET: &str = "PROMPT-SECRET-77";
const PIN_HASH: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

/// Version 2 policy: ask (2) when a judge outcome gives `out_of_scope`
/// a probability of 0.6xxxxx; allow otherwise. It never denies.
const V2_POLICY: &str = r#"
(module
  (memory (export "memory") 4)
  (data (i32.const 0) "out_of_scope\",\"ppm\":6")
  (global $next (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $ptr))
  (func (export "evaluate_v2") (param $ptr i32) (param $len i32) (result i32)
    (local $i i32) (local $j i32) (local $end i32)
    (local.set $end (i32.sub (i32.add (local.get $ptr) (local.get $len)) (i32.const 21)))
    (local.set $i (local.get $ptr))
    (block $done
      (loop $scan
        (br_if $done (i32.gt_s (local.get $i) (local.get $end)))
        (local.set $j (i32.const 0))
        (block $miss
          (loop $cmp
            (br_if $miss (i32.ne
              (i32.load8_u (i32.add (local.get $i) (local.get $j)))
              (i32.load8_u (local.get $j))))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (if (i32.eq (local.get $j) (i32.const 21)) (then (return (i32.const 2))))
            (br $cmp)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const 0)))
"#;

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// ── Mock services ───────────────────────────────────────────────────

#[derive(Clone, Default)]
struct Recorder {
    bodies: Arc<Mutex<Vec<Value>>>,
}

impl Recorder {
    fn all(&self) -> Vec<Value> {
        self.bodies.lock().clone()
    }
}

async fn serve(router: Router) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    port
}

async fn chat_upstream() -> u16 {
    serve(Router::new().fallback(|| async {
        Json(json!({
            "id": "c", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6}
        }))
    }))
    .await
}

async fn tool_backend(seen: Recorder) -> u16 {
    serve(Router::new().fallback(move |Json(body): Json<Value>| {
        let seen = seen.clone();
        async move {
            seen.bodies.lock().push(body.clone());
            Json(json!({
                "jsonrpc": "2.0", "id": body["id"],
                "result": {"content": [{"type": "text", "text": "done"}]}
            }))
        }
    }))
    .await
}

/// The judge: scores by keywords and records every request. Clearing
/// `alive` makes it answer HTTP 500 (a broken judge).
async fn judge_service(seen: Recorder, alive: Arc<AtomicBool>) -> u16 {
    serve(Router::new().route(
        "/score",
        post(move |Json(body): Json<Value>| {
            let seen = seen.clone();
            let alive = Arc::clone(&alive);
            async move {
                seen.bodies.lock().push(body.clone());
                if !alive.load(Ordering::SeqCst) {
                    return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                }
                let arguments = body["arguments"].to_string();
                let tool = body["tool"].as_str().unwrap_or_default();
                let (risky, safe, p) = match body["predicate"]["id"].as_str().unwrap_or_default() {
                    "arg_matches_task@1" => (
                        "mismatch",
                        "match",
                        if arguments.contains("danger") {
                            0.9
                        } else if arguments.contains("maybe") {
                            0.25
                        } else {
                            0.05
                        },
                    ),
                    "child_uses_parent_entitlement@1" => {
                        let parent_refused = body["context"]["prior_denials"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|denial| denial["source"] == "parent" && denial["tool"] == tool);
                        (
                            "laundering",
                            "independent",
                            if parent_refused { 0.9 } else { 0.05 },
                        )
                    }
                    "ticket_in_scope@1" => (
                        "out_of_scope",
                        "in_scope",
                        if arguments.contains("warn") { 0.65 } else { 0.05 },
                    ),
                    _ => return Err(axum::http::StatusCode::BAD_REQUEST),
                };
                Ok(Json(json!({
                    "model": {"name": "full-judge", "version": "1", "weights_sha256": PIN_HASH},
                    "probs": [{"label": safe, "p": 1.0 - p}, {"label": risky, "p": p}]
                })))
            }
        }),
    ))
    .await
}

// ── The daemon ──────────────────────────────────────────────────────

struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// SIGTERM and wait for a graceful exit (the drift file and the
    /// Bridge are flushed by then).
    fn stop(mut self) {
        let _ = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(self.0.id().to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.0.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("proofvisord did not stop after SIGTERM");
    }
}

fn owner_only(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Stack {
    root: PathBuf,
    port: u16,
    config: PathBuf,
}

impl Stack {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn bridge(&self) -> PathBuf {
        self.root.join("data/bridge")
    }

    fn start(&self) -> Daemon {
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_proofvisord"))
            .arg("--config")
            .arg(&self.config)
            .current_dir(&self.root)
            .env("PV_SIGNING_SEED_FILE", self.root.join("signing.seed"))
            .env("RUST_LOG", "warn")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn proofvisord");
        let mut daemon = Daemon(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return daemon;
            }
            if let Ok(Some(status)) = daemon.0.try_wait() {
                panic!("proofvisord exited during startup: {status}");
            }
            assert!(Instant::now() < deadline, "daemon never listened");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn build_stack(mode: &str, chat_port: u16, tool_port: u16, judge_port: u16) -> (tempfile::TempDir, Stack) {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().to_path_buf();
    let port = free_port();
    std::fs::create_dir_all(root.join("tool-schemas")).unwrap();
    for tool in ["refund_order", "update_ticket", "lookup"] {
        std::fs::write(
            root.join(format!("tool-schemas/{tool}.json")),
            r#"{"type":"object","properties":{"note":{"type":"string"}},"additionalProperties":false}"#,
        )
        .unwrap();
    }
    std::fs::write(root.join("v2.wat"), V2_POLICY).unwrap();
    owner_only(&root.join("hmac.secret"), HMAC_SECRET.as_bytes());
    owner_only(&root.join("signing.seed"), hex::encode(SIGNING_SEED).as_bytes());
    let config = root.join("proofvisor.toml");
    std::fs::write(
        &config,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:{port}"
upstream_url = "http://127.0.0.1:{chat_port}"
require_identity = true
identity_hmac_secret_file = "{secret}"
identity_hmac_kid = "{HMAC_KID}"
audience = "{AUDIENCE}"
default_workflow = "unsigned"
compression_enabled = false
dashboard_enabled = false
atif_spool_dir = "{spool}"
bridge_data_dir = "{bridge}"
tool_schema_dir = "{schemas}"
state_backend = "memory"
embedder_backend = "hash"
vector_backend = "memory"
tool_upstream_url = "http://127.0.0.1:{tool_port}/rpc"
tool_upstream_transport = "json_rpc"
wasm_policy_paths = ["config/policies/payload_limit.wat", "{v2}"]
redaction_patterns = ['ACCT-[0-9]{{6}}']
consequential_tools = []

[intent_map]
refund_order = "billing.refund"
update_ticket = "support.update"
lookup = "support.read"

[mission]
id = "m-march"
allowed_intents = ["billing.refund", "support.update", "support.read"]
expires_at = 4102444800
task = "{TASK}"

[principal_budget]
max_total_tool_calls = 6

[[operator_tokens]]
name = "reviewer"
sha256 = "{operator}"

[judge]
mode = "{mode}"

[[judge.adapters]]
name = "vendor"
kind = "cloud"
endpoint = "http://127.0.0.1:{judge_port}/score"
deadline_ms = 3000
model_name = "full-judge"
model_version = "1"
weights_sha256 = "{PIN_HASH}"

[[judge.predicates]]
id = "ticket_in_scope@1"
labels = ["in_scope", "out_of_scope"]
positive_label = "out_of_scope"
description = "Is the ticket update within the support scope?"

[[judge.tools]]
tool = "refund_order"
allow_cloud = true
predicates = [
  {{ id = "arg_matches_task@1", adapter = "vendor" }},
  {{ id = "child_uses_parent_entitlement@1", adapter = "vendor" }},
]

[[judge.tools]]
tool = "update_ticket"
allow_cloud = true
predicates = [{{ id = "ticket_in_scope@1", adapter = "vendor" }}]

[[judge.thresholds]]
predicate = "arg_matches_task@1"
label = "mismatch"
deny_above = 0.7
ask_above = 0.3

[[judge.thresholds]]
predicate = "child_uses_parent_entitlement@1"
label = "laundering"
deny_above = 0.7

[judge.drift]
state_file = "{drift}"
sample_every = 1
min_reviews_per_band = 1
tolerance = 0.0
"#,
            secret = root.join("hmac.secret").display(),
            spool = root.join("spool/atif").display(),
            bridge = root.join("data/bridge").display(),
            schemas = root.join("tool-schemas").display(),
            v2 = root.join("v2.wat").display(),
            operator = pv_core::digest::sha256_hex(OPERATOR_TOKEN.as_bytes()),
            drift = root.join("judge-drift.json").display(),
        ),
    )
    .unwrap();
    (scratch, Stack { root, port, config })
}

fn token(jti: &str, instance_uid: &str, parent: Option<String>) -> String {
    let now = pv_core::time::now_ms() / 1000;
    let claims = pv_identity::NhiClaims {
        sub: "user:dana@acme.io".into(),
        iss: "full-issuer".into(),
        aud: pv_identity::Audience::Single(AUDIENCE.to_owned()),
        iat: now,
        nbf: None,
        exp: now + 600,
        jti: jti.to_owned(),
        azp: Some("billing-app".into()),
        act: None,
        instance_uid: instance_uid.to_owned(),
        charter: "billing-agent".into(),
        version: "1.0".into(),
        scopes: vec!["tool:*".into(), "chat:write".into(), "session:close".into()],
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
        &jsonwebtoken::EncodingKey::from_secret(HMAC_SECRET.as_bytes()),
    )
    .unwrap()
}

struct Reply {
    status: u16,
    json: Value,
    headers: reqwest::header::HeaderMap,
}

impl Reply {
    fn code(&self) -> &str {
        self.json["error"]["data"]["code"].as_str().unwrap_or("<none>")
    }
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    bearer: &str,
    extra: &[(&str, &str)],
    body: &Value,
) -> Reply {
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(body);
    if !bearer.is_empty() {
        request = request.bearer_auth(bearer);
    }
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response.text().await.unwrap();
    Reply {
        status,
        json: serde_json::from_str(&text).unwrap_or(Value::String(text)),
        headers,
    }
}

async fn tool(
    client: &reqwest::Client,
    stack: &Stack,
    bearer: &str,
    session: &str,
    workflow: &str,
    name: &str,
    note: &str,
) -> Reply {
    post_json(
        client,
        &stack.url("/v1/mcp"),
        bearer,
        &[("x-pv-session", session), ("x-pv-workflow", workflow)],
        // A fresh JSON-RPC id per request, as MCP clients send: with
        // forwarding on, an id names one tool request in its session.
        &json!({"jsonrpc": "2.0", "id": NEXT_ID.fetch_add(1, Ordering::SeqCst), "method": "tools/call",
                "params": {"name": name, "arguments": {"note": note}}}),
    )
    .await
}

/// Every event the daemon published for `session`, in chain order.
fn session_events(bridge: &Path, session: &str) -> Vec<Value> {
    let mut events = Vec::new();
    for class in pv_events::EventClass::all() {
        for partition in 0..64 {
            let Ok(stored) =
                pv_bridge::EmbeddedBroker::fetch_read_only(bridge, class.topic(), partition, 0, 100_000)
            else {
                break;
            };
            events.extend(
                stored
                    .into_iter()
                    .map(|event| event.value)
                    .filter(|event| event["session_uid"] == session),
            );
        }
    }
    events.sort_by_key(|event| event["metadata"]["sequence"].as_u64().unwrap_or(u64::MAX));
    events
}

/// Tool-call events for `session`, once at least `count` are stored.
async fn tool_events(bridge: &Path, session: &str, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events: Vec<Value> = session_events(bridge, session)
            .into_iter()
            .filter(|event| event["class_name"] == "agent.tool_call")
            .collect();
        if events.len() >= count {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "only {} tool events for {session}",
            events.len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn review_id_for(event: &Value, predicate: &str) -> String {
    event["payload"]["judge"]["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|verdict| verdict["predicate_id"] == predicate)
        .and_then(|verdict| verdict["review_id"].as_str())
        .unwrap_or_else(|| panic!("no review id for {predicate} in {event}"))
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_judge_works_with_every_neighbouring_feature_in_the_real_binary() {
    let backend_calls = Recorder::default();
    let judge_calls = Recorder::default();
    let alive = Arc::new(AtomicBool::new(true));
    let chat_port = chat_upstream().await;
    let tool_port = tool_backend(backend_calls.clone()).await;
    let judge_port = judge_service(judge_calls.clone(), Arc::clone(&alive)).await;
    let (_scratch, stack) = build_stack("enforce", chat_port, tool_port, judge_port);
    let client = reqwest::Client::new();
    let main = token("jti-main", "agent-main", None);
    let daemon = stack.start();

    // ── Chat works, and the prompt never reaches the judge ──────────
    let chat = post_json(
        &client,
        &stack.url("/v1/chat/completions"),
        &main,
        &[("x-pv-session", "s-chat")],
        &json!({"model": "m", "messages": [{"role": "user", "content": PROMPT_SECRET}]}),
    )
    .await;
    assert_eq!(chat.status, 200, "{}", chat.json);

    // ── An untagged tool: forwarded, never judged ───────────────────
    let lookup = tool(
        &client,
        &stack,
        &main,
        "s-main",
        "unsigned",
        "lookup",
        "order 1001",
    )
    .await;
    assert_eq!(lookup.status, 200, "{}", lookup.json);
    assert_eq!(backend_calls.all().len(), 1);
    assert!(judge_calls.all().is_empty());

    // ── A tagged tool, benign: judged on both predicates, forwarded ─
    let benign = tool(
        &client,
        &stack,
        &main,
        "s-main",
        "unsigned",
        "refund_order",
        "refund ACCT-123456 for the March invoice",
    )
    .await;
    assert_eq!(benign.status, 200, "{}", benign.json);
    assert_eq!(backend_calls.all().len(), 2);
    // The backend receives the arguments as sent (forwarding does not redact).
    assert_eq!(
        backend_calls.all()[1]["params"]["arguments"]["note"],
        "refund ACCT-123456 for the March invoice"
    );
    let judged = judge_calls.all();
    assert_eq!(judged.len(), 2, "one request per bound predicate");
    for request in &judged {
        assert_eq!(request["contract"], "proofvisor.judge.v1");
        assert_eq!(request["tool"], "refund_order");
        let arguments = request["arguments"].to_string();
        assert!(
            !arguments.contains("ACCT-123456"),
            "cloud judge saw unredacted data: {arguments}"
        );
        assert!(arguments.contains("March invoice"), "{arguments}");
        assert_eq!(request["context"]["task"], TASK);
        assert_eq!(request["context"]["intent"], "billing.refund");
        assert_eq!(request["context"]["mission_ids"], json!(["m-march"]));
        assert_eq!(request["context"]["charter"], "billing-agent");
        assert!(
            !request.to_string().contains(PROMPT_SECRET),
            "the judge saw the prompt"
        );
    }

    // ── Deny above the threshold: refused, never forwarded ──────────
    let denied = tool(
        &client,
        &stack,
        &main,
        "s-main",
        "unsigned",
        "refund_order",
        "danger: refund everything",
    )
    .await;
    assert_eq!(denied.status, 403, "{}", denied.json);
    assert_eq!(denied.code(), "JUDGE_DENIED");
    assert_eq!(denied.json["error"]["data"]["predicate_id"], "arg_matches_task@1");
    assert_eq!(
        backend_calls.all().len(),
        2,
        "a judge denial must not reach the backend"
    );

    // ── A version 2 policy reads a custom predicate and asks ────────
    let held = tool(
        &client,
        &stack,
        &main,
        "s-main",
        "unsigned",
        "update_ticket",
        "warn: close all tickets",
    )
    .await;
    assert_eq!(held.status, 403, "{}", held.json);
    assert_eq!(held.code(), "APPROVAL_REQUIRED");
    let ok = tool(
        &client,
        &stack,
        &main,
        "s-main",
        "unsigned",
        "update_ticket",
        "add a note",
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.json);
    assert_eq!(backend_calls.all().len(), 3);

    // ── The record of each judged call in the event stream ──────────
    let events = tool_events(&stack.bridge(), "s-main", 5).await;
    let refused = events
        .iter()
        .find(|event| event["payload"]["denial_code"] == "JUDGE_DENIED")
        .unwrap();
    let record = &refused["payload"]["judge"];
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["policy_decision"], "deny");
    assert_eq!(record["policy"], pv_sandbox::JUDGE_POLICY_NAME);
    assert_eq!(record["verdicts"][0]["adapter_kind"], "cloud");
    assert_eq!(record["verdicts"][0]["model"]["weights_sha256"], PIN_HASH);
    assert_eq!(
        record["verdicts"][0]["probs"][1],
        json!({"label": "mismatch", "ppm": 900000})
    );
    let asked = events
        .iter()
        .find(|event| event["payload"]["denial_code"] == "APPROVAL_REQUIRED")
        .unwrap();
    let record = &asked["payload"]["judge"];
    assert_eq!(
        record["decision"], "allow",
        "no native threshold covers ticket_in_scope@1"
    );
    assert_eq!(record["policy_decision"], "ask");
    assert_eq!(record["policy"], stack.root.join("v2.wat").display().to_string());
    assert_eq!(record["would_block"], true);
    assert!(events
        .iter()
        .filter(|event| event["payload"]["tool"] == "lookup")
        .all(|event| event["payload"].get("judge").is_none()));

    // ── Delegation: the child sees the parent's refusal ─────────────
    let parent = token("jti-parent", "agent-parent", None);
    let refused = tool(
        &client,
        &stack,
        &parent,
        "s-parent",
        "unsigned",
        "refund_order",
        "danger: wire it all",
    )
    .await;
    assert_eq!(refused.code(), "JUDGE_DENIED");
    let child = token("jti-child", "agent-child", Some(parent.clone()));
    let laundering = tool(
        &client,
        &stack,
        &child,
        "s-child",
        "unsigned",
        "refund_order",
        "refund order 1001",
    )
    .await;
    assert_eq!(laundering.status, 403, "{}", laundering.json);
    assert_eq!(laundering.code(), "JUDGE_DENIED");
    assert_eq!(
        laundering.json["error"]["data"]["predicate_id"],
        "child_uses_parent_entitlement@1"
    );
    let child_request = judge_calls
        .all()
        .into_iter()
        .rev()
        .find(|request| request["predicate"]["id"] == "child_uses_parent_entitlement@1")
        .unwrap();
    assert_eq!(child_request["context"]["delegation_depth"], 1);
    assert!(child_request["context"]["prior_denials"]
        .as_array()
        .unwrap()
        .iter()
        .any(|denial| denial["instance_uid"] == "agent-parent" && denial["source"] == "parent"));

    // ── The principal budget counts only admitted calls ─────────────
    // agent-main was admitted 3 times (lookup, refund, ticket note) and
    // refused twice; the cap is 6, so exactly 3 more fit.
    for n in 0..3 {
        let reply = tool(&client, &stack, &main, "s-budget", "unsigned", "lookup", "more").await;
        assert_eq!(reply.status, 200, "call {n}: {}", reply.json);
    }
    let over = tool(
        &client,
        &stack,
        &main,
        "s-budget",
        "unsigned",
        "lookup",
        "one too many",
    )
    .await;
    assert_eq!(over.code(), "BUDGET_EXCEEDED", "{}", over.json);

    // ── The MCP Streamable HTTP transport takes the same path ───────
    let mcp_agent = token("jti-mcp", "agent-mcp", None);
    let init = post_json(
        &client,
        &stack.url("/mcp"),
        &mcp_agent,
        &[],
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "full-stack", "version": "1"}}}),
    )
    .await;
    assert_eq!(init.status, 200, "{}", init.json);
    let mcp_session = init.headers["mcp-session-id"].to_str().unwrap().to_owned();
    let version = init.json["result"]["protocolVersion"]
        .as_str()
        .unwrap()
        .to_owned();
    let mcp_denied = post_json(
        &client,
        &stack.url("/mcp"),
        &mcp_agent,
        &[
            ("mcp-session-id", &mcp_session),
            ("mcp-protocol-version", &version),
        ],
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "refund_order", "arguments": {"note": "danger"}}}),
    )
    .await;
    assert_eq!(mcp_denied.code(), "JUDGE_DENIED", "{}", mcp_denied.json);
    assert_eq!(mcp_denied.json["id"], 2);

    // ── Metrics ─────────────────────────────────────────────────────
    let metrics = client
        .get(stack.url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for series in [
        "pv_judge_calls_total{predicate=\"arg_matches_task@1\",status=\"scored\"}",
        "pv_judge_decisions_total{mode=\"enforce\",decision=\"deny\",enforced=\"true\"}",
        "pv_judge_wait_seconds",
        "pv_judge_drift_tripped",
    ] {
        assert!(metrics.contains(series), "missing {series}");
    }

    // ── A signed session: the receipt signs the verdicts ────────────
    let signed_denied = tool(
        &client,
        &stack,
        &main,
        "s-signed",
        "signed",
        "refund_order",
        "danger again",
    )
    .await;
    assert_eq!(signed_denied.code(), "JUDGE_DENIED");
    let close = post_json(
        &client,
        &stack.url("/v1/sessions/s-signed/close"),
        &main,
        &[],
        &json!({}),
    )
    .await;
    assert_eq!(close.status, 200, "{}", close.json);
    let receipt: pv_receipts::Receipt = serde_json::from_value(close.json["receipt"].clone()).unwrap();
    let mut ring = pv_receipts::Keyring::new();
    ring.add_key_bytes(&pv_receipts::Signer::public_key_bytes(
        &pv_receipts::Ed25519Signer::from_seed(&SIGNING_SEED),
    ))
    .unwrap();
    receipt
        .verify(&ring)
        .expect("the receipt verifies against the independently held key");
    let pv_receipts::ReceiptSubject::EventChain {
        chain_head,
        event_count,
    } = receipt.body.subject.clone()
    else {
        panic!("expected an event-chain receipt")
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let chained = loop {
        let events = session_events(&stack.bridge(), "s-signed");
        let chained: Vec<Value> = events
            .into_iter()
            .filter(|event| event["class_name"] != "agent.receipt")
            .take(usize::try_from(event_count).unwrap())
            .collect();
        if u64::try_from(chained.len()).unwrap() == event_count {
            break chained;
        }
        assert!(
            Instant::now() < deadline,
            "the signed session's events never all reached the Bridge"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let honest = pv_receipts::chain::EventChain::compute("s-signed", &chained).unwrap();
    assert_eq!(
        honest.head_hex(),
        chain_head,
        "the receipt signs exactly the stored events"
    );
    let index = chained
        .iter()
        .position(|event| event["payload"]["judge"].is_object())
        .expect("the judged call is in the signed chain");
    let mut tampered = chained.clone();
    tampered[index]["payload"]["judge"]["verdicts"][0]["probs"][1]["ppm"] = json!(10000);
    assert_ne!(
        pv_receipts::chain::EventChain::compute("s-signed", &tampered)
            .unwrap()
            .head_hex(),
        chain_head
    );

    // ── An unsigned session: the ATIF trajectory carries the record ─
    let close = post_json(
        &client,
        &stack.url("/v1/sessions/s-main/close"),
        &main,
        &[],
        &json!({}),
    )
    .await;
    assert_eq!(close.status, 200, "{}", close.json);
    let path = close.json["path"].as_str().expect("an ATIF path").to_owned();
    let text = std::fs::read_to_string(&path).unwrap();
    let trajectory: Value = serde_json::from_str(&text).unwrap();
    assert!(pv_atif::validate_value(&trajectory, pv_atif::Mode::Strict).is_empty());
    assert!(!text.contains("ACCT-123456"), "the ATIF file must be redacted");
    let judged_steps = trajectory["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["tool_calls"][0]["extra"]["judge"].is_object())
        .count();
    assert_eq!(judged_steps, 4, "two refund calls and two ticket calls");

    // ── The drift gate trips on reviews and survives a restart ──────
    let operator = OPERATOR_TOKEN;
    let review = |id: String, correct: bool| {
        let client = client.clone();
        let url = stack.url("/admin/v1/judge/reviews");
        async move {
            post_json(
                &client,
                &url,
                operator,
                &[],
                &json!({"review_id": id, "correct": correct}),
            )
            .await
        }
    };
    // A separate agent: agent-main's principal budget is spent.
    let drifter = token("jti-drift", "agent-drift", None);
    let hesitant = tool(
        &client,
        &stack,
        &drifter,
        "s-drift",
        "unsigned",
        "refund_order",
        "maybe refund",
    )
    .await;
    assert_eq!(hesitant.status, 200, "{}", hesitant.json);
    let drift_events = tool_events(&stack.bridge(), "s-drift", 1).await;
    let reply = review(review_id_for(&drift_events[0], "arg_matches_task@1"), true).await;
    assert_eq!(reply.json["persisted"], true, "{}", reply.json);
    // A confident verdict from earlier, reviewed wrong: accuracy falls
    // as confidence rises.
    let confident = tool_events(&stack.bridge(), "s-parent", 1).await;
    let reply = review(review_id_for(&confident[0], "arg_matches_task@1"), false).await;
    assert_eq!(reply.json["tripped_now"], true, "{}", reply.json);
    daemon.stop();
    assert!(stack.root.join("judge-drift.json").exists());

    let daemon = stack.start();
    let drift = client
        .get(stack.url("/admin/v1/judge/drift"))
        .bearer_auth(operator)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let tripped = drift["predicates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|predicate| predicate["predicate_id"] == "arg_matches_task@1")
        .unwrap();
    assert_eq!(tripped["tripped"], true, "{drift}");
    let held = tool(
        &client,
        &stack,
        &drifter,
        "s-after",
        "unsigned",
        "refund_order",
        "refund order 1001",
    )
    .await;
    assert_eq!(
        held.code(),
        "APPROVAL_REQUIRED",
        "restored ask-by-default: {}",
        held.json
    );
    let reset = post_json(
        &client,
        &stack.url("/admin/v1/judge/drift/reset"),
        operator,
        &[],
        &json!({"predicate_id": "arg_matches_task@1"}),
    )
    .await;
    assert_eq!(reset.json["was_tripped"], true);
    assert_eq!(reset.json["persisted"], true);
    let fine = tool(
        &client,
        &stack,
        &drifter,
        "s-after",
        "unsigned",
        "refund_order",
        "refund order 1001",
    )
    .await;
    assert_eq!(fine.status, 200, "{}", fine.json);

    // ── A broken judge fails closed; everything else keeps working ──
    alive.store(false, Ordering::SeqCst);
    let broken = tool(
        &client,
        &stack,
        &drifter,
        "s-after",
        "unsigned",
        "refund_order",
        "refund order 1001",
    )
    .await;
    assert_eq!(broken.code(), "JUDGE_UNAVAILABLE", "{}", broken.json);
    let untagged = tool(
        &client,
        &stack,
        &drifter,
        "s-after",
        "unsigned",
        "lookup",
        "still fine",
    )
    .await;
    assert_eq!(untagged.status, 200, "{}", untagged.json);
    let chat = post_json(
        &client,
        &stack.url("/v1/chat/completions"),
        &main,
        &[("x-pv-session", "s-chat-2")],
        &json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(chat.status, 200);
    daemon.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadow_mode_in_the_real_binary_never_blocks_and_records_the_would_be_block() {
    let backend_calls = Recorder::default();
    let judge_calls = Recorder::default();
    let alive = Arc::new(AtomicBool::new(true));
    let chat_port = chat_upstream().await;
    let tool_port = tool_backend(backend_calls.clone()).await;
    let judge_port = judge_service(judge_calls.clone(), Arc::clone(&alive)).await;
    let (_scratch, stack) = build_stack("shadow", chat_port, tool_port, judge_port);
    let client = reqwest::Client::new();
    let main = token("jti-shadow", "agent-shadow", None);
    let daemon = stack.start();
    let reply = tool(
        &client,
        &stack,
        &main,
        "s-shadow",
        "unsigned",
        "refund_order",
        "danger: refund all",
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.json);
    alive.store(false, Ordering::SeqCst);
    let reply = tool(
        &client,
        &stack,
        &main,
        "s-shadow",
        "unsigned",
        "refund_order",
        "refund",
    )
    .await;
    assert_eq!(
        reply.status, 200,
        "shadow mode ignores judge failures: {}",
        reply.json
    );
    assert_eq!(backend_calls.all().len(), 2);
    let events = tool_events(&stack.bridge(), "s-shadow", 2).await;
    let record = &events[0]["payload"]["judge"];
    assert_eq!(record["mode"], "shadow");
    assert_eq!(record["enforced"], false);
    assert_eq!(record["would_block"], true);
    assert_eq!(record["decision"], "deny");
    assert_eq!(
        events[1]["payload"]["judge"]["verdicts"][0]["status"],
        "unavailable"
    );
    daemon.stop();
}

/// The local ONNX judge in the real binary: the daemon hashes the model
/// and tokenizer it loads against their pins, scores tagged calls
/// in-process, and the verdicts carry the model's real pin.
#[cfg(feature = "onnx")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_onnx_judge_scores_in_the_real_binary() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../pv-judge/tests/fixtures");
    let model = std::fs::read(fixtures.join("toy_judge.onnx")).unwrap();
    let tokenizer = std::fs::read(fixtures.join("toy_tokenizer.json")).unwrap();
    let chat_port = chat_upstream().await;
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().to_path_buf();
    let port = free_port();
    std::fs::create_dir_all(root.join("tool-schemas")).unwrap();
    std::fs::write(
        root.join("tool-schemas/refund_order.json"),
        r#"{"type":"object","properties":{"note":{"type":"string"}}}"#,
    )
    .unwrap();
    std::fs::write(root.join("judge.onnx"), &model).unwrap();
    std::fs::write(root.join("tokenizer.json"), &tokenizer).unwrap();
    let model_hash = pv_core::digest::sha256_hex(&model);
    let config = root.join("proofvisor.toml");
    std::fs::write(
        &config,
        format!(
            r#"config_version = 1
listen = "127.0.0.1:{port}"
upstream_url = "http://127.0.0.1:{chat_port}"
require_identity = false
default_workflow = "unsigned"
compression_enabled = false
dashboard_enabled = false
atif_spool_dir = "{spool}"
bridge_data_dir = "{bridge}"
tool_schema_dir = "{schemas}"
state_backend = "memory"
embedder_backend = "hash"
vector_backend = "memory"
consequential_tools = []

[judge]
mode = "enforce"

[[judge.adapters]]
name = "local"
kind = "local"
model_path = "{model_path}"
tokenizer_path = "{tokenizer_path}"
tokenizer_sha256 = "{tokenizer_hash}"
output_labels = ["match", "mismatch"]
model_name = "toy-judge"
model_version = "1"
weights_sha256 = "{model_hash}"

[[judge.tools]]
tool = "refund_order"
predicates = [{{ id = "arg_matches_task@1", adapter = "local" }}]

[[judge.thresholds]]
predicate = "arg_matches_task@1"
label = "mismatch"
deny_above = 0.7
ask_above = 0.3
"#,
            spool = root.join("spool/atif").display(),
            bridge = root.join("data/bridge").display(),
            schemas = root.join("tool-schemas").display(),
            model_path = root.join("judge.onnx").display(),
            tokenizer_path = root.join("tokenizer.json").display(),
            tokenizer_hash = pv_core::digest::sha256_hex(&tokenizer),
        ),
    )
    .unwrap();
    owner_only(&root.join("signing.seed"), hex::encode(SIGNING_SEED).as_bytes());
    let stack = Stack { root, port, config };
    let client = reqwest::Client::new();
    let daemon = stack.start();
    let call = |note: &'static str| {
        let client = client.clone();
        let url = stack.url("/v1/mcp");
        async move {
            post_json(
                &client,
                &url,
                "",
                &[("x-pv-session", "s-local")],
                &json!({"jsonrpc": "2.0", "id": NEXT_ID.fetch_add(1, Ordering::SeqCst), "method": "tools/call",
                        "params": {"name": "refund_order", "arguments": {"note": note}}}),
            )
            .await
        }
    };
    // `danger` scores mismatch ≈ 1, `warn` ≈ 0.5, anything else ≈ 0.
    let first = call("danger refund everything").await;
    assert_eq!(first.code(), "JUDGE_DENIED", "{} {}", first.status, first.json);
    assert_eq!(call("warn large refund").await.code(), "APPROVAL_REQUIRED");
    assert_eq!(call("refund order 1001").await.status, 200);
    let events = tool_events(&stack.bridge(), "s-local", 3).await;
    let verdict = &events[0]["payload"]["judge"]["verdicts"][0];
    assert_eq!(verdict["adapter_kind"], "local");
    assert_eq!(verdict["model"]["weights_sha256"], model_hash);
    assert!(verdict["probs"][1]["ppm"].as_u64().unwrap() > 999_000);
    daemon.stop();
}
