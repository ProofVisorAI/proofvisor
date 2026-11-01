//! End-to-end tests for the native Anthropic and Gemini adapters.
//!
//! The unit tests in `provider/` pin each field mapping in isolation.
//! These tests drive a stock OpenAI-shaped request through the live
//! gateway against loopback servers that speak the Anthropic Messages
//! and Gemini `generateContent` wire formats, and check both sides: what
//! the provider received (path, credential header, translated body) and
//! what the OpenAI client got back (shape, choices, tool calls, finish
//! reasons, usage, errors).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::response::IntoResponse;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type Request = axum::http::Request<axum::body::Body>;

const API_KEY: &str = "sk-native-test-key";

/// One request the mock provider received.
#[derive(Debug, Clone)]
struct Seen {
    path_and_query: String,
    headers: axum::http::HeaderMap,
    body: Value,
}

/// A scripted native provider: answers the n-th request with the n-th
/// response (the last one repeats) and records every request.
#[derive(Clone)]
struct MockProvider {
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl MockProvider {
    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// How one scripted reply is sent.
#[derive(Clone)]
enum Reply {
    Json(u16, Value),
    Sse(String),
}

async fn mock_provider(replies: Vec<Reply>) -> (String, MockProvider) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));
    let mock = MockProvider {
        seen: Arc::clone(&seen),
    };
    let replies = Arc::new(replies);
    let app = axum::Router::new().fallback(move |request: Request| {
        let seen = Arc::clone(&seen);
        let counter = Arc::clone(&counter);
        let replies = Arc::clone(&replies);
        async move {
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
            seen.lock().unwrap().push(Seen {
                path_and_query: parts
                    .uri
                    .path_and_query()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                headers: parts.headers,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            });
            let position = counter.fetch_add(1, Ordering::AcqRel);
            let reply = replies.get(position).or_else(|| replies.last()).cloned().unwrap();
            match reply {
                Reply::Json(status, value) => {
                    let mut response = (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        axum::Json(value),
                    )
                        .into_response();
                    if status == 429 {
                        response
                            .headers_mut()
                            .insert("retry-after", axum::http::HeaderValue::from_static("7"));
                    }
                    response
                }
                Reply::Sse(frames) => {
                    ([(axum::http::header::CONTENT_TYPE, "text/event-stream")], frames).into_response()
                }
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, mock)
}

fn gateway(provider: &str, upstream: &str) -> Arc<pv_harness::AppState> {
    let mut config = common::leaked_test_config();
    config.upstream_url = upstream.to_owned();
    config.provider = provider.to_owned();
    let key_dir = tempfile::tempdir().unwrap();
    config.upstream_api_key_file = Some(common::owner_only_file(key_dir.path(), "key", API_KEY));
    std::mem::forget(key_dir);
    let sandbox = common::sandbox_for(&config);
    common::app_state(config, sandbox, Arc::new(common::CountingBus::default()), 9)
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

struct Answer {
    status: axum::http::StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|error| panic!("not JSON ({error}): {}", self.body))
    }

    /// The `data:` payloads of an SSE body, without the `[DONE]` marker.
    fn chunks(&self) -> Vec<Value> {
        assert!(
            self.body.trim_end().ends_with("data: [DONE]"),
            "an OpenAI stream ends with [DONE]: {}",
            self.body
        );
        self.body
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter(|data| *data != "[DONE]")
            .map(|data| serde_json::from_str(data).unwrap())
            .collect()
    }
}

async fn send(state: &Arc<pv_harness::AppState>, request: Request) -> Answer {
    let router = pv_harness::build_router((**state).clone());
    let response = tower::ServiceExt::oneshot(router, request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 22).await.unwrap();
    Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn weather_tool() -> Value {
    json!([{
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Weather for a city",
            "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
        },
    }])
}

// ── Anthropic ───────────────────────────────────────────────────

fn anthropic_message(text: &str, input: u64, output: u64) -> Value {
    json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": input, "output_tokens": output},
    })
}

#[tokio::test]
async fn anthropic_buffered_tool_call_round_trips_as_openai() {
    let (url, mock) = mock_provider(vec![Reply::Json(
        200,
        json!({
            "id": "msg_tool",
            "type": "message",
            "role": "assistant",
            "model": "claude-test",
            "content": [
                {"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}},
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 30, "output_tokens": 12},
        }),
    )])
    .await;
    let state = gateway("anthropic", &url);
    let payload = json!({
        "model": "claude-test",
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "Weather in Paris?"},
        ],
        "tools": weather_tool(),
        "tool_choice": "auto",
        "stop": "END",
    });
    let answer = send(&state, chat_request("anthropic-buffered-tool", &payload)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let seen = mock.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.path_and_query, "/v1/messages");
    assert_eq!(request.headers["x-api-key"], API_KEY, "raw key, no Bearer scheme");
    assert!(request.headers.get("authorization").is_none());
    assert_eq!(request.headers["anthropic-version"], "2023-06-01");
    assert_eq!(request.body["system"], "Be brief.");
    assert_eq!(
        request.body["max_tokens"], 4096,
        "provider_default_max_tokens applies"
    );
    assert_eq!(request.body["stop_sequences"], json!(["END"]));
    assert_eq!(request.body["tools"][0]["name"], "get_weather");
    assert_eq!(request.body["tools"][0]["input_schema"]["type"], "object");
    assert_eq!(request.body["messages"][0]["role"], "user");

    let completion = answer.json();
    assert_eq!(completion["object"], "chat.completion");
    let choice = &completion["choices"][0];
    assert_eq!(choice["index"], 0);
    assert_eq!(choice["message"]["role"], "assistant");
    assert_eq!(choice["message"]["content"], "Checking.");
    assert_eq!(choice["message"]["tool_calls"][0]["id"], "toolu_1");
    assert_eq!(choice["message"]["tool_calls"][0]["type"], "function");
    assert_eq!(
        choice["message"]["tool_calls"][0]["function"]["name"],
        "get_weather"
    );
    let arguments: Value = serde_json::from_str(
        choice["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments are a JSON string, as in OpenAI"),
    )
    .unwrap();
    assert_eq!(arguments, json!({"city": "Paris"}));
    assert_eq!(choice["finish_reason"], "tool_calls");
    assert_eq!(completion["usage"]["prompt_tokens"], 30);
    assert_eq!(completion["usage"]["completion_tokens"], 12);
    assert_eq!(completion["usage"]["total_tokens"], 42);
}

#[tokio::test]
async fn anthropic_n2_fans_out_and_merges_choices_and_usage() {
    let (url, mock) = mock_provider(vec![
        Reply::Json(200, anthropic_message("first", 10, 3)),
        Reply::Json(200, anthropic_message("second", 10, 5)),
    ])
    .await;
    let state = gateway("anthropic", &url);
    let payload = json!({
        "model": "claude-test",
        "n": 2,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
    });
    let answer = send(&state, chat_request("anthropic-n2", &payload)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let seen = mock.requests();
    assert_eq!(
        seen.len(),
        2,
        "Anthropic has no n: one upstream request per choice"
    );
    for request in &seen {
        assert!(request.body.get("n").is_none(), "n never reaches Anthropic");
        assert_eq!(request.body["max_tokens"], 64);
    }

    let completion = answer.json();
    let choices = completion["choices"].as_array().unwrap();
    assert_eq!(choices.len(), 2);
    let mut texts: Vec<(u64, String)> = choices
        .iter()
        .map(|choice| {
            (
                choice["index"].as_u64().unwrap(),
                choice["message"]["content"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    texts.sort();
    assert_eq!(texts[0].0, 0);
    assert_eq!(texts[1].0, 1);
    let mut contents: Vec<String> = texts.into_iter().map(|(_, text)| text).collect();
    contents.sort();
    assert_eq!(contents, vec!["first".to_owned(), "second".to_owned()]);
    // Every choice is billed by the provider, so usage adds up.
    assert_eq!(completion["usage"]["prompt_tokens"], 20);
    assert_eq!(completion["usage"]["completion_tokens"], 8);
}

fn anthropic_stream(text: &str, output: u64) -> String {
    format!(
        concat!(
            "event: message_start\n",
            "data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg\",\"model\":\"claude-test\",\"usage\":{{\"input_tokens\":9,\"output_tokens\":1}}}}}}\n\n",
            "event: content_block_start\n",
            "data: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n",
            "event: content_block_delta\n",
            "data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n",
            "event: content_block_stop\n",
            "data: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n",
            "event: message_delta\n",
            "data: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"max_tokens\"}},\"usage\":{{\"output_tokens\":{output}}}}}\n\n",
            "event: message_stop\n",
            "data: {{\"type\":\"message_stop\"}}\n\n",
        ),
        text = text,
        output = output,
    )
}

#[tokio::test]
async fn anthropic_n2_stream_interleaves_indexed_choices_with_one_finish_each() {
    let (url, mock) = mock_provider(vec![
        Reply::Sse(anthropic_stream("alpha", 4)),
        Reply::Sse(anthropic_stream("beta", 6)),
    ])
    .await;
    let state = gateway("anthropic", &url);
    let payload = json!({
        "model": "claude-test",
        "n": 2,
        "stream": true,
        "stream_options": {"include_usage": true},
        "messages": [{"role": "user", "content": "hi"}],
    });
    let answer = send(&state, chat_request("anthropic-n2-stream", &payload)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(mock.requests().len(), 2);
    assert!(mock
        .requests()
        .iter()
        .all(|request| request.body["stream"] == true));

    let chunks = answer.chunks();
    assert!(chunks
        .iter()
        .all(|chunk| chunk["object"] == "chat.completion.chunk"));
    let mut text = [String::new(), String::new()];
    let mut finishes = [0usize; 2];
    for chunk in &chunks {
        for choice in chunk["choices"].as_array().unwrap() {
            let index = usize::try_from(choice["index"].as_u64().unwrap()).unwrap();
            if let Some(content) = choice["delta"]["content"].as_str() {
                text[index].push_str(content);
            }
            if let Some(reason) = choice["finish_reason"].as_str() {
                assert_eq!(reason, "length", "max_tokens maps to length");
                finishes[index] += 1;
            }
        }
    }
    let mut seen_text = text.to_vec();
    seen_text.sort();
    assert_eq!(seen_text, vec!["alpha".to_owned(), "beta".to_owned()]);
    assert_eq!(finishes, [1, 1], "exactly one finish per choice");
    let usage = chunks.last().unwrap();
    assert_eq!(usage["choices"], json!([]), "the usage chunk carries no choices");
    assert_eq!(usage["usage"]["prompt_tokens"], 18);
    assert_eq!(usage["usage"]["completion_tokens"], 10);
}

#[tokio::test]
async fn anthropic_error_becomes_an_openai_error_with_the_same_status() {
    let (url, _mock) = mock_provider(vec![Reply::Json(
        429,
        json!({"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}),
    )])
    .await;
    let state = gateway("anthropic", &url);
    let answer = send(&state, chat_request("anthropic-429", &common::chat("hi"))).await;
    assert_eq!(answer.status, 429, "{}", answer.body);
    assert_eq!(answer.headers["retry-after"], "7", "Retry-After is relayed");
    let error = answer.json();
    assert_eq!(error["error"]["message"], "slow down");
    assert_eq!(error["error"]["type"], "rate_limit_error");
    assert_eq!(error["error"]["code"], "rate_limit_error");
}

#[tokio::test]
async fn anthropic_json_mode_is_refused_before_reaching_the_provider() {
    let (url, mock) = mock_provider(vec![Reply::Json(200, anthropic_message("x", 1, 1))]).await;
    let state = gateway("anthropic", &url);
    let mut payload = common::chat("hi");
    payload["response_format"] = json!({"type": "json_object"});
    let answer = send(&state, chat_request("anthropic-json-mode", &payload)).await;
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert!(answer.body.contains("response_format"), "{}", answer.body);
    assert!(
        mock.requests().is_empty(),
        "a refused request never reaches the provider"
    );
}

// ── Gemini ──────────────────────────────────────────────────────

#[tokio::test]
async fn gemini_buffered_n2_uses_candidate_count_and_maps_finish_reasons() {
    let (url, mock) = mock_provider(vec![Reply::Json(
        200,
        json!({
            "candidates": [
                {"index": 0, "content": {"role": "model", "parts": [{"text": "one"}]}, "finishReason": "STOP"},
                {"index": 1, "content": {"role": "model", "parts": [{"text": "two"}]}, "finishReason": "MAX_TOKENS"},
            ],
            "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 7, "totalTokenCount": 18},
            "modelVersion": "gemini-test",
        }),
    )])
    .await;
    let state = gateway("gemini", &url);
    let payload = json!({
        "model": "gemini-test",
        "n": 2,
        "temperature": 0.5,
        "max_tokens": 50,
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "hi"},
        ],
    });
    let answer = send(&state, chat_request("gemini-n2", &payload)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let seen = mock.requests();
    assert_eq!(seen.len(), 1, "Gemini returns every candidate in one response");
    let request = &seen[0];
    assert_eq!(
        request.path_and_query,
        "/v1beta/models/gemini-test:generateContent"
    );
    assert_eq!(request.headers["x-goog-api-key"], API_KEY);
    assert!(request.headers.get("authorization").is_none());
    assert_eq!(request.body["generationConfig"]["candidateCount"], 2);
    assert_eq!(request.body["generationConfig"]["maxOutputTokens"], 50);
    assert_eq!(request.body["generationConfig"]["temperature"], 0.5);
    assert_eq!(request.body["systemInstruction"]["parts"][0]["text"], "Be brief.");
    assert_eq!(request.body["contents"][0]["role"], "user");

    let completion = answer.json();
    assert_eq!(completion["object"], "chat.completion");
    let choices = completion["choices"].as_array().unwrap();
    assert_eq!(choices.len(), 2);
    assert_eq!(choices[0]["index"], 0);
    assert_eq!(choices[0]["message"]["content"], "one");
    assert_eq!(choices[0]["finish_reason"], "stop");
    assert_eq!(choices[1]["index"], 1);
    assert_eq!(choices[1]["message"]["content"], "two");
    assert_eq!(choices[1]["finish_reason"], "length");
    assert_eq!(completion["usage"]["prompt_tokens"], 11);
    assert_eq!(completion["usage"]["completion_tokens"], 7);
}

#[tokio::test]
async fn gemini_stream_function_call_becomes_openai_tool_call_chunks() {
    let frames = concat!(
        "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Oslo\"}}}]}}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":3}}\n\n",
        "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":3}}\n\n",
    );
    let (url, mock) = mock_provider(vec![Reply::Sse(frames.to_owned())]).await;
    let state = gateway("gemini", &url);
    let payload = json!({
        "model": "gemini-test",
        "stream": true,
        "messages": [{"role": "user", "content": "Weather in Oslo?"}],
        "tools": weather_tool(),
        "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
    });
    let answer = send(&state, chat_request("gemini-stream-tool", &payload)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let request = &mock.requests()[0];
    assert_eq!(
        request.path_and_query,
        "/v1beta/models/gemini-test:streamGenerateContent?alt=sse"
    );
    assert_eq!(
        request.body["tools"][0]["functionDeclarations"][0]["name"],
        "get_weather"
    );
    assert_eq!(request.body["toolConfig"]["functionCallingConfig"]["mode"], "ANY");
    assert_eq!(
        request.body["toolConfig"]["functionCallingConfig"]["allowedFunctionNames"],
        json!(["get_weather"])
    );

    let chunks = answer.chunks();
    let mut name = None;
    let mut arguments = String::new();
    let mut finish = None;
    for chunk in &chunks {
        assert_eq!(chunk["object"], "chat.completion.chunk");
        for choice in chunk["choices"].as_array().unwrap() {
            if let Some(calls) = choice["delta"]["tool_calls"].as_array() {
                for call in calls {
                    assert_eq!(call["index"], 0);
                    if let Some(found) = call["function"]["name"].as_str() {
                        name = Some(found.to_owned());
                    }
                    if let Some(part) = call["function"]["arguments"].as_str() {
                        arguments.push_str(part);
                    }
                }
            }
            if let Some(reason) = choice["finish_reason"].as_str() {
                finish = Some(reason.to_owned());
            }
        }
    }
    assert_eq!(name.as_deref(), Some("get_weather"));
    assert_eq!(
        serde_json::from_str::<Value>(&arguments).unwrap(),
        json!({"city": "Oslo"})
    );
    assert_eq!(
        finish.as_deref(),
        Some("tool_calls"),
        "a functionCall with STOP is a tool call to an OpenAI client"
    );
}

#[tokio::test]
async fn gemini_error_status_becomes_an_openai_error() {
    let (url, _mock) = mock_provider(vec![Reply::Json(
        400,
        json!({"error": {"code": 400, "message": "API key not valid", "status": "INVALID_ARGUMENT"}}),
    )])
    .await;
    let state = gateway("gemini", &url);
    let answer = send(&state, chat_request("gemini-400", &common::chat("hi"))).await;
    assert_eq!(answer.status, 400, "{}", answer.body);
    let error = answer.json();
    assert_eq!(error["error"]["message"], "API key not valid");
    assert_eq!(error["error"]["type"], "invalid_request_error");
    assert_eq!(error["error"]["code"], "INVALID_ARGUMENT");
}
