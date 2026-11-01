//! End-to-end test for `pvctl sidecar` with the real binary.
//!
//! The in-process unit test in `sidecar.rs` proves the Cloud Foundry
//! assertion exchange with fixture certificates. This suite runs the
//! shipped binary the way the buildpack does (a settings file, no flags)
//! and checks the operator-visible contract: the application's own
//! bearer token never reaches the gateway, the sidecar's token from the
//! credential file does, streamed and buffered responses pass through,
//! a non-loopback listen address is refused, and SIGTERM stops it
//! cleanly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use axum::body::Body;
use axum::http::{HeaderValue, Request, Response};
use axum::response::IntoResponse as _;
use serde_json::{json, Value};
use std::io::Read as _;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_pvctl");
const AGENT_TOKEN: &str = "agent-token-from-the-credential-file";
const SDK_TOKEN: &str = "sk-placeholder-from-the-sdk";

/// What the fake gateway saw per request.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    authorization: Option<String>,
    everything: String,
}

async fn fake_gateway(seen: Arc<Mutex<Vec<Seen>>>) -> String {
    let app = axum::Router::new().fallback(move |request: Request<Body>| {
        let seen = Arc::clone(&seen);
        async move {
            let path = request.uri().path().to_owned();
            let headers = request.headers().clone();
            let body = axum::body::to_bytes(request.into_body(), 1 << 20).await.unwrap();
            let mut everything = String::new();
            for (name, value) in &headers {
                everything.push_str(name.as_str());
                everything.push_str(": ");
                everything.push_str(value.to_str().unwrap_or("<non-text>"));
                everything.push('\n');
            }
            everything.push_str(&String::from_utf8_lossy(&body));
            seen.lock().unwrap().push(Seen {
                path: path.clone(),
                authorization: headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                everything,
            });
            if path == "/v1/chat/completions" {
                let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                if request["stream"] == true {
                    let chunks = [
                        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
                        "data: [DONE]\n\n",
                    ];
                    let stream = futures::stream::iter(chunks.map(|chunk| Ok::<_, std::io::Error>(chunk.to_owned())));
                    let mut response = Response::new(Body::from_stream(stream));
                    response
                        .headers_mut()
                        .insert("content-type", HeaderValue::from_static("text/event-stream"));
                    return response;
                }
                return axum::Json(json!({
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                }))
                .into_response();
            }
            let mut response = axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": {}})).into_response();
            response
                .headers_mut()
                .insert("mcp-session-id", HeaderValue::from_static("gateway-session"));
            response
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

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

async fn wait_for_listener(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the sidecar never started listening on {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("pvctl sidecar did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sidecar_binary_swaps_the_application_token_for_its_own_and_streams_through() {
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let gateway = fake_gateway(Arc::clone(&seen)).await;
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("agent.token");
    std::fs::write(&token_file, format!("{AGENT_TOKEN}\n")).unwrap();
    let port = free_loopback_port();
    let settings = dir.path().join("sidecar.json");
    std::fs::write(
        &settings,
        serde_json::to_vec(&json!({
            "gateway": gateway,
            "audience": "proofvisor",
            "listen": format!("127.0.0.1:{port}"),
            "credential": format!("token-file:{}", token_file.display()),
        }))
        .unwrap(),
    )
    .unwrap();

    let mut child = Command::new(BIN)
        .arg("sidecar")
        .arg("--config")
        .arg(&settings)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pvctl sidecar");
    let stderr = capture_stderr(&mut child);
    wait_for_listener(port).await;

    let client = reqwest::Client::new();
    let sidecar = format!("http://127.0.0.1:{port}");

    let buffered = client
        .post(format!("{sidecar}/v1/chat/completions"))
        .bearer_auth(SDK_TOKEN)
        .json(&json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(buffered.status(), 200);
    let completion: Value = buffered.json().await.unwrap();
    assert_eq!(completion["choices"][0]["message"]["content"], "ok");

    let streamed = client
        .post(format!("{sidecar}/v1/chat/completions"))
        .bearer_auth(SDK_TOKEN)
        .json(&json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(streamed.status(), 200);
    assert_eq!(streamed.headers()["content-type"], "text/event-stream");
    let body = streamed.text().await.unwrap();
    assert!(body.ends_with("data: [DONE]\n\n"), "{body}");

    let mcp = client
        .post(format!("{sidecar}/mcp"))
        .header("mcp-session-id", "client-session")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(mcp.status(), 200);
    assert_eq!(mcp.headers()["mcp-session-id"], "gateway-session");

    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(seen[0].path, "/v1/chat/completions");
        assert_eq!(seen[2].path, "/mcp");
        for request in seen.iter() {
            assert_eq!(
                request.authorization.as_deref(),
                Some(&*format!("Bearer {AGENT_TOKEN}")),
                "every forwarded request carries the sidecar's own token: {request:?}"
            );
            assert!(
                !request.everything.contains(SDK_TOKEN),
                "the application's placeholder token must never reach the gateway: {}",
                request.everything
            );
        }
        assert!(seen[2].everything.contains("mcp-session-id: client-session"));
    }

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let exit = wait_for_exit(&mut child, Duration::from_secs(15));
    assert!(exit.success(), "SIGTERM must stop the sidecar cleanly: {exit:?}");
    let stderr = stderr.lock().unwrap();
    assert!(
        stderr.contains(&format!("listening on http://127.0.0.1:{port}")),
        "{stderr}"
    );
}

#[test]
fn the_sidecar_refuses_a_non_loopback_listen_address() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("agent.token");
    std::fs::write(&token_file, "t\n").unwrap();
    let output = Command::new(BIN)
        .args([
            "sidecar",
            "--gateway",
            "http://127.0.0.1:9",
            "--listen",
            "0.0.0.0:0",
            "--credential",
        ])
        .arg(format!("token-file:{}", token_file.display()))
        .output()
        .expect("spawn pvctl sidecar");
    assert!(!output.status.success(), "a wildcard bind must be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("loopback"), "{stderr}");
}

#[test]
fn the_sidecar_needs_a_gateway() {
    let output = Command::new(BIN)
        .args(["sidecar", "--credential", "token-file:/dev/null"])
        .env_remove("PV_GATEWAY_URL")
        .env_remove("AV_GATEWAY_URL")
        .output()
        .expect("spawn pvctl sidecar");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("gateway URL is required"), "{stderr}");
}
