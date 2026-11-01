//! End-to-end test for `pvctl console-sync --watch --pull-policies` with
//! the real binary against a loopback console.
//!
//! The unit tests in `console_sync.rs` cover one-shot passes in-process.
//! This suite runs the shipped binary in watch mode and checks what an
//! operator relies on: a trajectory that appears while the watcher runs
//! is uploaded on the next pass, the console policy bundle is written to
//! the daemon's bundle file and re-requested with `If-None-Match`, the
//! daemon's own status file is reported back, and Ctrl-C ends the loop
//! with a clean exit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::io::Read as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_pvctl");
const TOKEN: &str = "ingest-token-for-the-watch-test";
const DEPLOYMENT: &str = "dep-watch";
const BUNDLE_ETAG: &str = "0123abcd4567ef89";

/// One request the loopback console received.
#[derive(Debug, Clone)]
struct Post {
    endpoint: String,
    authorization: Option<String>,
    deployment: Option<String>,
    body: Value,
}

#[derive(Default)]
struct Console {
    posts: Vec<Post>,
    bundle_requests: usize,
    not_modified: usize,
}

type Shared = Arc<Mutex<Console>>;

async fn ingest(
    State((console, endpoint)): State<(Shared, &'static str)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    console.lock().unwrap().posts.push(Post {
        endpoint: endpoint.to_owned(),
        authorization: text("authorization"),
        deployment: text("x-pv-deployment"),
        body,
    });
    let reply = match endpoint {
        "events" => json!({"inserted": 1}),
        "policy-status" => json!({"ok": true, "stale": false}),
        _ => json!({"ok": true}),
    };
    (StatusCode::OK, Json(reply))
}

async fn policies(State(console): State<Shared>, headers: HeaderMap) -> axum::response::Response {
    let mut console = console.lock().unwrap();
    console.bundle_requests += 1;
    let wanted = format!("\"{BUNDLE_ETAG}\"");
    if headers.get("if-none-match").and_then(|value| value.to_str().ok()) == Some(wanted.as_str()) {
        console.not_modified += 1;
        return StatusCode::NOT_MODIFIED.into_response();
    }
    Json(json!({
        "version": 1,
        "etag": BUNDLE_ETAG,
        "policies": [{
            "id": "pol-1",
            "name": "runtime.no_wires",
            "kind": "allowlist",
            "scope": "tool.*",
            "spec": {"deny_tools": ["send_wire"]}
        }]
    }))
    .into_response()
}

async fn start_console() -> (String, Shared) {
    let console: Shared = Arc::default();
    let app = Router::new()
        .route(
            "/api/v1/ingest/pubkey",
            post(ingest).with_state((Arc::clone(&console), "pubkey")),
        )
        .route(
            "/api/v1/ingest/sessions",
            post(ingest).with_state((Arc::clone(&console), "sessions")),
        )
        .route(
            "/api/v1/ingest/events",
            post(ingest).with_state((Arc::clone(&console), "events")),
        )
        .route(
            "/api/v1/ingest/receipts",
            post(ingest).with_state((Arc::clone(&console), "receipts")),
        )
        .route(
            "/api/v1/ingest/policy-status",
            post(ingest).with_state((Arc::clone(&console), "policy-status")),
        )
        .route(
            "/api/v1/ingest/policies",
            get(policies).with_state(Arc::clone(&console)),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, console)
}

/// A closed, authenticated trajectory the way the daemon leaves one.
fn write_trajectory(spool: &Path, session: &str) {
    let mut builder = pv_atif::TrajectoryBuilder::new(
        pv_atif::Agent {
            name: "watch-agent".to_owned(),
            version: "1.0.0".to_owned(),
            model_name: Some("gpt-test".to_owned()),
            tool_definitions: None,
            extra: None,
        },
        Some(session.to_owned()),
    );
    builder
        .push_step(pv_atif::Step {
            step_id: 0,
            timestamp: Some("2026-01-01T00:00:00Z".to_owned()),
            source: pv_atif::Source::User,
            message: json!("hello"),
            reasoning_effort: None,
            reasoning_content: None,
            model_name: None,
            tool_calls: None,
            observation: None,
            metrics: None,
            is_copied_context: None,
            llm_call_count: Some(0),
            extra: None,
        })
        .unwrap();
    let path = spool.join(format!("{session}.json"));
    pv_atif::write_atomic(&builder.finish(), &path).unwrap();
    std::fs::write(path.with_extension("atif-auth"), b"sidecar").unwrap();
    std::fs::write(path.with_extension("close-complete"), b"closed").unwrap();
}

/// Drain a child's stderr on a thread so the pipe never fills.
fn capture_stderr(child: &mut Child) -> Arc<Mutex<String>> {
    let buffer: Arc<Mutex<String>> = Arc::default();
    let mut stderr = child.stderr.take().unwrap();
    let sink = Arc::clone(&buffer);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(read) = stderr.read(&mut chunk) {
            if read == 0 {
                break;
            }
            sink.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&chunk[..read]));
        }
    });
    buffer
}

async fn wait_until(what: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn signal(child: &Child, name: &str) {
    let status = Command::new("kill")
        .args([name, &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill {name} failed");
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("pvctl did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_mode_uploads_new_trajectories_pulls_policies_and_stops_on_ctrl_c() {
    let (console_url, console) = start_console().await;
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("spool");
    std::fs::create_dir_all(spool.join("receipts")).unwrap();
    write_trajectory(&spool, "session-1");
    let token_file = dir.path().join("ingest.token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let bundle_file = dir.path().join("policies").join("bundle.json");
    let state_file = dir.path().join("sync-state.json");

    let mut child = Command::new(BIN)
        .args(["console-sync", "--watch", "--interval", "1", "--pull-policies"])
        .arg("--spool-dir")
        .arg(&spool)
        .arg("--console-url")
        .arg(&console_url)
        .arg("--deployment")
        .arg(DEPLOYMENT)
        .arg("--token-file")
        .arg(&token_file)
        .arg("--state-file")
        .arg(&state_file)
        .arg("--policy-bundle-file")
        .arg(&bundle_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pvctl");
    let stderr = capture_stderr(&mut child);

    // Pass 1: the existing trajectory is uploaded and the bundle written.
    let posted = |endpoint: &str| {
        console
            .lock()
            .unwrap()
            .posts
            .iter()
            .filter(|post| post.endpoint == endpoint)
            .count()
    };
    wait_until("the first events upload", Duration::from_secs(20), || {
        posted("events") >= 1
    })
    .await;
    wait_until("the bundle file", Duration::from_secs(20), || {
        bundle_file.exists()
    })
    .await;
    let bundle: Value = serde_json::from_slice(&std::fs::read(&bundle_file).unwrap()).unwrap();
    assert_eq!(bundle["etag"], BUNDLE_ETAG);
    assert_eq!(bundle["policies"][0]["name"], "runtime.no_wires");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&bundle_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the bundle file is owner-only");
    }

    // The daemon's answer: write the status file the way proofvisord
    // does, and expect the watcher to report it on its next pass.
    let status_file = {
        let mut name = bundle_file.as_os_str().to_owned();
        name.push(".status.json");
        std::path::PathBuf::from(name)
    };
    std::fs::write(
        &status_file,
        serde_json::to_vec(&json!({
            "etag": BUNDLE_ETAG,
            "appliedAt": "2026-11-01T12:00:00Z",
            "daemonVersion": "0.1.0-test",
            "applied": ["pol-1"],
            "unsupported": []
        }))
        .unwrap(),
    )
    .unwrap();

    // Pass 2 and later: a trajectory that appears while watching is
    // uploaded without a restart, and the status report reaches the
    // console once.
    write_trajectory(&spool, "session-2");
    wait_until("the second events upload", Duration::from_secs(20), || {
        posted("events") >= 2
    })
    .await;
    wait_until("the policy status report", Duration::from_secs(20), || {
        posted("policy-status") >= 1
    })
    .await;
    wait_until(
        "a conditional bundle request answered 304",
        Duration::from_secs(20),
        || console.lock().unwrap().not_modified >= 1,
    )
    .await;
    // One more full pass, to show nothing is re-uploaded or re-reported.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    signal(&child, "-INT");
    let status = wait_for_exit(&mut child, Duration::from_secs(15));
    assert!(status.success(), "Ctrl-C must end watch mode cleanly: {status:?}");

    let console = console.lock().unwrap();
    for post in &console.posts {
        assert_eq!(
            post.authorization.as_deref(),
            Some(&*format!("Bearer {TOKEN}")),
            "{post:?}"
        );
        assert_eq!(post.deployment.as_deref(), Some(DEPLOYMENT), "{post:?}");
    }
    let sessions: Vec<&Value> = console
        .posts
        .iter()
        .filter(|post| post.endpoint == "sessions")
        .map(|post| &post.body)
        .collect();
    // Sessions are an idempotent upsert and are re-announced on every
    // pass (that is how the console learns a session closed later);
    // events and receipts are the costly part and must go out once.
    assert!(
        sessions.len() >= 2,
        "both trajectories are announced: {sessions:?}"
    );
    let uploaded: Vec<String> = sessions.iter().map(|body| body.to_string()).collect();
    assert!(
        uploaded.iter().any(|body| body.contains("session-1")),
        "{uploaded:?}"
    );
    assert!(
        uploaded.iter().any(|body| body.contains("session-2")),
        "{uploaded:?}"
    );
    let events = console
        .posts
        .iter()
        .filter(|post| post.endpoint == "events")
        .count();
    assert_eq!(
        events, 2,
        "event batches are uploaded once per trajectory, never re-sent"
    );
    let reports: Vec<&Post> = console
        .posts
        .iter()
        .filter(|post| post.endpoint == "policy-status")
        .collect();
    assert_eq!(
        reports.len(),
        1,
        "an unchanged status is reported once: {reports:?}"
    );
    assert_eq!(reports[0].body["etag"], BUNDLE_ETAG);
    assert_eq!(reports[0].body["applied"][0], "pol-1");
    assert!(
        reports[0].body.get("error").is_none(),
        "the daemon's private error field never leaves the host"
    );
    assert!(
        console.bundle_requests >= 2,
        "the bundle is re-checked every pass"
    );

    let stderr = stderr.lock().unwrap();
    assert!(
        !stderr.contains("warning:"),
        "watch mode must run without warnings:\n{stderr}"
    );
    assert!(stderr.contains("policy bundle"), "{stderr}");
    assert!(stderr.contains("policy status reported"), "{stderr}");

    let state: Value = serde_json::from_slice(&std::fs::read(&state_file).unwrap()).unwrap();
    assert!(
        state.to_string().contains("session-2"),
        "the state file records what was synced: {state}"
    );
}

#[test]
fn watch_mode_refuses_a_zero_interval_and_pull_policies_needs_a_bundle_file() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "t\n").unwrap();
    let base = |extra: &[&str]| {
        let mut command = Command::new(BIN);
        command
            .args([
                "console-sync",
                "--console-url",
                "http://127.0.0.1:9",
                "--deployment",
                "d",
            ])
            .arg("--token-file")
            .arg(&token_file)
            .arg("--spool-dir")
            .arg(dir.path())
            .args(extra)
            .env_remove("PV_POLICY_BUNDLE_FILE");
        command.output().expect("spawn pvctl")
    };

    let zero = base(&["--watch", "--interval", "0"]);
    assert!(!zero.status.success());
    assert!(
        String::from_utf8_lossy(&zero.stderr).contains("at least 1 second"),
        "{}",
        String::from_utf8_lossy(&zero.stderr)
    );

    let no_bundle = base(&["--pull-policies"]);
    assert!(!no_bundle.status.success());
    assert!(
        String::from_utf8_lossy(&no_bundle.stderr).contains("--policy-bundle-file"),
        "{}",
        String::from_utf8_lossy(&no_bundle.stderr)
    );
}
