//! Provider adapter seam.
//!
//! The client always speaks OpenAI chat completions to the proxy. The
//! `provider` config value selects how that request reaches the
//! upstream and how the upstream answer comes back:
//!
//! * `"openai"` (the default) forwards the request body unchanged to
//!   `upstream_url` + `upstream_chat_path` and relays the response
//!   bytes as they are. This also fits every OpenAI-compatible server
//!   (vLLM, LiteLLM, Groq, Together, DeepSeek, OpenRouter, Ollama,
//!   LM Studio, llama.cpp, xAI, Mistral, Azure OpenAI).
//! * `"anthropic"` translates the request into the Anthropic Messages
//!   API (`POST /v1/messages`, `x-api-key`, `anthropic-version`) and
//!   translates the answer — buffered JSON or named SSE events — back
//!   into OpenAI chat-completion objects and chunks. See
//!   [`anthropic`].
//! * `"gemini"` translates the request into Gemini
//!   `generateContent` / `streamGenerateContent?alt=sse` and the
//!   answer back into OpenAI shape. See [`gemini`].
//!
//! Because every translated response is OpenAI-shaped by the time it
//! reaches the relay in `routes.rs`, the audit capture (token
//! accounting, tool-call reassembly, stop reasons, receipts) runs one
//! parser — `routes::parse_provider_chunk` — for all three providers.
//! Native usage that the OpenAI shape cannot express directly is
//! carried in the OpenAI usage sub-objects the parser already reads
//! (`prompt_tokens_details.cached_tokens`,
//! `completion_tokens_details.reasoning_tokens`).

pub(crate) mod anthropic;
pub(crate) mod gemini;

use axum::body::Bytes;
use futures::stream::{BoxStream, SelectAll};
use futures::{Stream, StreamExt};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

/// One upstream provider's wire dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderKind {
    /// OpenAI chat completions, forwarded and relayed unchanged.
    OpenAi,
    /// Anthropic Messages API, translated both ways.
    Anthropic,
    /// Google Gemini `generateContent`, translated both ways.
    Gemini,
}

impl ProviderKind {
    /// Stable name, matching the `provider` config value.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
        }
    }

    /// The header that carries the API key on this provider's native
    /// API, used when the operator left `upstream_auth_header` and
    /// `upstream_auth_scheme` at their OpenAI defaults. The key is
    /// sent raw (no scheme prefix). `None` keeps the configured
    /// `authorization: Bearer <key>` behaviour.
    pub(crate) fn native_auth_header(self) -> Option<&'static str> {
        match self {
            Self::OpenAi => None,
            Self::Anthropic => Some("x-api-key"),
            Self::Gemini => Some("x-goog-api-key"),
        }
    }

    /// True when requests and responses are translated rather than
    /// relayed byte for byte.
    pub(crate) fn translates(self) -> bool {
        !matches!(self, Self::OpenAi)
    }
}

/// Look up the provider for a configured `provider` value. `None`
/// means unsupported — config validation names the supported set so
/// the daemon refuses at boot, not mid-stream.
pub(crate) fn adapter_for(provider: &str) -> Option<ProviderKind> {
    match provider {
        "openai" => Some(ProviderKind::OpenAi),
        "anthropic" => Some(ProviderKind::Anthropic),
        "gemini" => Some(ProviderKind::Gemini),
        _ => None,
    }
}

/// The provider names `adapter_for` accepts, for config-validation
/// error messages.
pub(crate) const SUPPORTED_PROVIDERS: &[&str] = &["openai", "anthropic", "gemini"];

/// Upper bound on `n` (choices per request). Gemini caps
/// `candidateCount` at 8, and the Anthropic adapter issues one
/// upstream request per choice, so the same bound applies everywhere
/// for predictable fan-out.
pub(crate) const MAX_CHOICES: u64 = 8;

/// The Anthropic API version every translated request pins.
pub(crate) const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Read `n` from an OpenAI request: absent or `null` means one choice;
/// anything else must be an integer in `1..=MAX_CHOICES`. Fails closed
/// on `2.0`, `"2"`, `0`, negatives and oversized values — OpenAI-
/// compatible servers lax-coerce some of those into real multi-choice
/// requests.
pub(crate) fn choice_count(payload: &Value) -> Result<u64, String> {
    match payload.get("n") {
        None | Some(Value::Null) => Ok(1),
        Some(n) => match n.as_u64() {
            Some(count) if n.is_u64() && (1..=MAX_CHOICES).contains(&count) => Ok(count),
            _ => Err(format!(
                "n must be an integer between 1 and {MAX_CHOICES}, got {n}"
            )),
        },
    }
}

/// Whether the client asked for `stream: true`.
pub(crate) fn wants_stream(payload: &Value) -> bool {
    payload.get("stream").and_then(Value::as_bool).unwrap_or(false)
}

/// Whether the client asked for the final usage chunk
/// (`stream_options.include_usage`).
pub(crate) fn wants_usage_chunk(payload: &Value) -> bool {
    payload
        .pointer("/stream_options/include_usage")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Current Unix time in seconds, for the `created` field.
pub(crate) fn created_now() -> u64 {
    pv_core::time::now_ms() / 1000
}

/// Fresh OpenAI-style completion id when the upstream supplies none.
pub(crate) fn fresh_completion_id() -> String {
    format!("chatcmpl-{}", pv_core::new_event_uid())
}

/// Fresh OpenAI-style tool-call id when the upstream supplies none.
pub(crate) fn fresh_tool_call_id() -> String {
    format!("call_{}", pv_core::new_event_uid())
}

/// Text of an OpenAI message `content` field: a string, or the
/// concatenated `text` parts of a content array. `None` for null or
/// missing content.
pub(crate) fn content_text(content: Option<&Value>) -> Option<String> {
    match content {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Array(parts)) => {
            let mut text = String::new();
            for part in parts {
                if let Some(piece) = part.get("text").and_then(Value::as_str) {
                    text.push_str(piece);
                }
            }
            Some(text)
        }
        _ => None,
    }
}

/// Split an OpenAI-style `data:<mime>;base64,<payload>` URL into its
/// media type and base64 payload. `None` for anything else (remote
/// URLs, non-base64 data URLs).
pub(crate) fn base64_data_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let meta = meta.strip_suffix(";base64")?;
    let media_type = if meta.is_empty() { "application/octet-stream" } else { meta };
    Some((media_type.to_owned(), data.to_owned()))
}

/// Parse an OpenAI `function.arguments` string into the JSON object
/// the native tool APIs require. An empty string means "no
/// arguments". Non-object JSON and unparsable text are refused: both
/// native APIs reject them and a silent rewrite would attest a call
/// the model never made.
pub(crate) fn arguments_object(arguments: Option<&Value>) -> Result<Value, String> {
    let raw = match arguments {
        None | Some(Value::Null) => return Ok(json!({})),
        Some(Value::String(raw)) => raw.trim(),
        Some(Value::Object(object)) => return Ok(Value::Object(object.clone())),
        Some(other) => {
            return Err(format!(
                "tool call arguments must be a JSON-encoded string, got {other}"
            ))
        }
    };
    if raw.is_empty() {
        return Ok(json!({}));
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(value @ Value::Object(_)) => Ok(value),
        Ok(_) => Err("tool call arguments must encode a JSON object".to_owned()),
        Err(error) => Err(format!("tool call arguments are not valid JSON: {error}")),
    }
}

/// `max_completion_tokens` (preferred) or `max_tokens` from an OpenAI
/// request, when either is a positive integer.
pub(crate) fn requested_max_tokens(payload: &Value) -> Option<u64> {
    ["max_completion_tokens", "max_tokens"]
        .into_iter()
        .find_map(|field| payload.get(field).and_then(Value::as_u64).filter(|n| *n > 0))
}

/// `stop` as a list of stop sequences (a bare string becomes a
/// one-element list).
pub(crate) fn stop_sequences(payload: &Value) -> Vec<Value> {
    match payload.get("stop") {
        Some(Value::String(stop)) => vec![Value::String(stop.clone())],
        Some(Value::Array(stops)) => stops.iter().filter(|s| s.is_string()).cloned().collect(),
        _ => Vec::new(),
    }
}

/// Token usage gathered from a native response, in OpenAI terms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UsageTotals {
    pub(crate) prompt_tokens: Option<u64>,
    pub(crate) completion_tokens: Option<u64>,
    pub(crate) cached_tokens: Option<u64>,
    pub(crate) reasoning_tokens: Option<u64>,
}

impl UsageTotals {
    /// True when the upstream reported anything at all.
    pub(crate) fn is_known(&self) -> bool {
        self.prompt_tokens.is_some() || self.completion_tokens.is_some()
    }

    /// Fold another response's usage into this one (every choice of a
    /// multi-choice request is billed, so the totals add up).
    pub(crate) fn add(&mut self, other: &UsageTotals) {
        fn add_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
            match (a, b) {
                (None, None) => None,
                (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
            }
        }
        self.prompt_tokens = add_opt(self.prompt_tokens, other.prompt_tokens);
        self.completion_tokens = add_opt(self.completion_tokens, other.completion_tokens);
        self.cached_tokens = add_opt(self.cached_tokens, other.cached_tokens);
        self.reasoning_tokens = add_opt(self.reasoning_tokens, other.reasoning_tokens);
    }

    /// The OpenAI `usage` object.
    pub(crate) fn to_openai(&self) -> Value {
        let prompt = self.prompt_tokens.unwrap_or(0);
        let completion = self.completion_tokens.unwrap_or(0);
        let mut usage = json!({
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt.saturating_add(completion),
        });
        if let Some(cached) = self.cached_tokens {
            set(&mut usage, "prompt_tokens_details", json!({ "cached_tokens": cached }));
        }
        if let Some(reasoning) = self.reasoning_tokens {
            set(&mut usage, "completion_tokens_details", json!({ "reasoning_tokens": reasoning }));
        }
        usage
    }
}

/// Read one non-negative integer field of a native usage object. Null
/// and absent are "unknown"; anything else must be a JCS-safe
/// non-negative integer.
pub(crate) fn usage_u64(value: Option<&Value>, field: &str) -> Result<Option<u64>, String> {
    crate::routes::provider_u64(value, field)
}

/// Set `key` on a JSON object value (no-op when `value` is not an
/// object). Keeps the translators free of panicking index syntax.
pub(crate) fn set(value: &mut Value, key: &str, item: Value) {
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_owned(), item);
    }
}

/// One SSE frame (or a bare JSON body) split into its parts.
pub(crate) struct SseFrame {
    /// True when any SSE field line was seen (`data:`, `event:`,
    /// `id:`, `retry:` or a comment). False means `data` is the raw
    /// body text.
    pub(crate) is_sse: bool,
    /// The `event:` name, empty when unset.
    pub(crate) event: String,
    /// Joined `data:` lines (or the raw text). `None` when the frame
    /// carries nothing attributable (keepalive, comment-only).
    pub(crate) data: Option<String>,
}

/// Split one SSE frame per the EventSource spec: strip one leading
/// BOM, collect `data:` lines (one optional leading space each),
/// track the `event:` name. Non-SSE text is returned whole.
pub(crate) fn split_sse_frame(raw: &str) -> SseFrame {
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let mut is_sse = false;
    let mut event = String::new();
    let mut data: Vec<&str> = Vec::new();
    for line in raw.split(['\r', '\n']) {
        if let Some(value) = line.strip_prefix("data:") {
            is_sse = true;
            data.push(value.strip_prefix(' ').unwrap_or(value));
        } else if let Some(value) = line.strip_prefix("event:") {
            is_sse = true;
            event = value.strip_prefix(' ').unwrap_or(value).to_owned();
        } else if line == "data" || line.starts_with("id:") || line.starts_with("retry:") || line.starts_with(':') {
            is_sse = true;
        }
    }
    let data = if is_sse {
        if data.iter().all(|entry| entry.trim().is_empty()) {
            None
        } else {
            Some(data.join("\n"))
        }
    } else {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    };
    SseFrame { is_sse, event, data }
}

/// Build one OpenAI `chat.completion.chunk` carrying a single choice
/// delta.
pub(crate) fn chunk(
    id: &str,
    model: &str,
    created: u64,
    index: u64,
    delta: Value,
    finish_reason: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": index,
            "delta": delta,
            "finish_reason": finish_reason,
        }],
    })
}

/// Build the standalone final usage chunk (`choices: []`).
pub(crate) fn usage_chunk(id: &str, model: &str, created: u64, usage: &UsageTotals) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [],
        "usage": usage.to_openai(),
    })
}

/// Serialize one chunk as an SSE `data:` frame.
pub(crate) fn sse_bytes(value: &Value) -> Bytes {
    let mut frame = String::from("data: ");
    frame.push_str(&value.to_string());
    frame.push_str("\n\n");
    Bytes::from(frame)
}

/// The `data: [DONE]` terminator.
pub(crate) fn done_bytes() -> Bytes {
    Bytes::from_static(b"data: [DONE]\n\n")
}

/// Translate a native error body into the OpenAI error envelope
/// `{"error": {"message", "type", "param", "code"}}`. `type` follows
/// OpenAI's taxonomy by HTTP status; `code` carries the upstream's
/// own error type or status string so the native diagnostic survives.
pub(crate) fn openai_error_envelope(provider: ProviderKind, status: u16, body: &[u8]) -> Value {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let error = parsed.as_ref().and_then(|value| value.get("error"));
    let message = error
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "upstream {} responded with HTTP {status} and no JSON error body",
                provider.name()
            )
        });
    let native_code = error
        .and_then(|error| error.get("type").or_else(|| error.get("status")))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let kind = match status {
        400 | 404 | 405 | 409 | 413 | 422 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        429 => "rate_limit_error",
        _ => "api_error",
    };
    json!({
        "error": {
            "message": message,
            "type": kind,
            "param": Value::Null,
            "code": native_code.map_or(Value::Number(status.into()), Value::String),
        }
    })
}

/// Output of a streaming translator for one native frame.
pub(crate) enum TranslatedItem {
    /// One OpenAI chunk to relay.
    Chunk(Value),
    /// The stream ended cleanly; carries the usage it reported.
    End(UsageTotals),
}

/// A stateful translator from one native SSE stream to OpenAI chunks.
pub(crate) trait StreamTranslator: Send {
    /// Translate one complete SSE frame (or the unterminated tail at
    /// EOF). An `Err` fails the stream with the given reason.
    fn frame(&mut self, raw: &str) -> Result<Vec<Value>, String>;
    /// Called once at end of stream; returns trailing chunks and the
    /// usage the stream reported.
    fn finish(&mut self) -> Result<(Vec<Value>, UsageTotals), String>;
}

/// The longest unterminated SSE frame the translator will buffer.
const MAX_TRANSLATE_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Wraps one upstream byte stream and runs a [`StreamTranslator`] over
/// its SSE frames.
pub(crate) struct TranslatingStream {
    inner: BoxStream<'static, Result<Bytes, std::io::Error>>,
    translator: Box<dyn StreamTranslator>,
    buffer: Vec<u8>,
    queued: VecDeque<TranslatedItem>,
    finished: bool,
}

impl TranslatingStream {
    pub(crate) fn new(
        inner: BoxStream<'static, Result<Bytes, std::io::Error>>,
        translator: Box<dyn StreamTranslator>,
    ) -> Self {
        Self {
            inner,
            translator,
            buffer: Vec::new(),
            queued: VecDeque::new(),
            finished: false,
        }
    }

    fn absorb(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.buffer.extend_from_slice(bytes);
        while let Some(end) = crate::routes::sse_frame_end(&self.buffer) {
            let frame: Vec<u8> = self.buffer.drain(..end).collect();
            let frame = std::str::from_utf8(&frame).map_err(|error| format!("upstream SSE frame is not UTF-8: {error}"))?;
            for chunk in self.translator.frame(frame)? {
                self.queued.push_back(TranslatedItem::Chunk(chunk));
            }
        }
        if self.buffer.len() > MAX_TRANSLATE_FRAME_BYTES {
            return Err("unterminated upstream SSE frame exceeds limit".to_owned());
        }
        Ok(())
    }

    fn end(&mut self) -> Result<(), String> {
        let tail = std::mem::take(&mut self.buffer);
        if !tail.is_empty() {
            let tail = std::str::from_utf8(&tail).map_err(|error| format!("upstream body is not UTF-8: {error}"))?;
            for chunk in self.translator.frame(tail)? {
                self.queued.push_back(TranslatedItem::Chunk(chunk));
            }
        }
        let (chunks, usage) = self.translator.finish()?;
        for chunk in chunks {
            self.queued.push_back(TranslatedItem::Chunk(chunk));
        }
        self.queued.push_back(TranslatedItem::End(usage));
        Ok(())
    }
}

impl Stream for TranslatingStream {
    type Item = Result<TranslatedItem, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(item) = self.queued.pop_front() {
                return Poll::Ready(Some(Ok(item)));
            }
            if self.finished {
                return Poll::Ready(None);
            }
            match self.inner.as_mut().poll_next(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => {
                    if let Err(reason) = self.absorb(&bytes) {
                        self.finished = true;
                        return Poll::Ready(Some(Err(std::io::Error::other(reason))));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    self.finished = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.finished = true;
                    if let Err(reason) = self.end() {
                        return Poll::Ready(Some(Err(std::io::Error::other(reason))));
                    }
                }
            }
        }
    }
}

/// Merges the per-choice translated streams of one request into a
/// single OpenAI SSE stream: chunks interleave as they arrive (each
/// already carries its `choices[].index`), usage is summed over every
/// sub-stream, and the stream ends with the usage and `data: [DONE]`.
///
/// Usage placement follows what the client asked for. With
/// `stream_options.include_usage` the final usage chunk is the
/// standalone `choices: []` chunk OpenAI emits. Without it, chunks
/// that carry a `finish_reason` are held until every sub-stream ends
/// and the summed usage rides on the last of them, so a client that
/// never opted into usage chunks still sees only chunks with a
/// choice — and the audit capture still records provider-true token
/// counts instead of estimates.
pub(crate) struct MergedOpenAiStream {
    inner: SelectAll<TranslatingStream>,
    include_usage: bool,
    id: String,
    model: String,
    created: u64,
    usage: UsageTotals,
    held_finishes: Vec<Value>,
    output: VecDeque<Bytes>,
    done: bool,
}

impl MergedOpenAiStream {
    pub(crate) fn new(
        streams: Vec<TranslatingStream>,
        include_usage: bool,
        id: String,
        model: String,
        created: u64,
    ) -> Self {
        Self {
            inner: futures::stream::select_all(streams),
            include_usage,
            id,
            model,
            created,
            usage: UsageTotals::default(),
            held_finishes: Vec::new(),
            output: VecDeque::new(),
            done: false,
        }
    }

    fn finalize(&mut self) {
        let held = std::mem::take(&mut self.held_finishes);
        let count = held.len();
        if self.include_usage || count == 0 {
            for finish in held {
                self.output.push_back(sse_bytes(&finish));
            }
            if self.usage.is_known() {
                self.output
                    .push_back(sse_bytes(&usage_chunk(&self.id, &self.model, self.created, &self.usage)));
            }
        } else {
            for (position, mut finish) in held.into_iter().enumerate() {
                if position + 1 == count && self.usage.is_known() {
                    set(&mut finish, "usage", self.usage.to_openai());
                }
                self.output.push_back(sse_bytes(&finish));
            }
        }
        self.output.push_back(done_bytes());
        self.done = true;
    }
}

impl Stream for MergedOpenAiStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(bytes) = self.output.pop_front() {
                return Poll::Ready(Some(Ok(bytes)));
            }
            if self.done {
                return Poll::Ready(None);
            }
            match self.inner.poll_next_unpin(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(TranslatedItem::Chunk(chunk)))) => {
                    let has_finish = chunk
                        .pointer("/choices/0/finish_reason")
                        .is_some_and(|reason| !reason.is_null());
                    if has_finish && !self.include_usage {
                        self.held_finishes.push(chunk);
                    } else {
                        self.output.push_back(sse_bytes(&chunk));
                    }
                }
                Poll::Ready(Some(Ok(TranslatedItem::End(usage)))) => {
                    self.usage.add(&usage);
                }
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    self.output.clear();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => self.finalize(),
            }
        }
    }
}

/// Merge the non-streaming completions of a multi-choice fan-out into
/// one OpenAI `chat.completion`: choices renumbered in order, usage
/// summed, id/model/created from the first.
pub(crate) fn merge_completions(mut completions: Vec<Value>) -> Result<Value, String> {
    if completions.is_empty() {
        return Err("no upstream completion to merge".to_owned());
    }
    let mut merged = completions.remove(0);
    let mut usage = usage_from_openai(merged.get("usage"))?;
    let mut choices = merged
        .get("choices")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for completion in completions {
        usage.add(&usage_from_openai(completion.get("usage"))?);
        if let Some(extra) = completion.get("choices").and_then(Value::as_array) {
            choices.extend(extra.iter().cloned());
        }
    }
    for (position, choice) in choices.iter_mut().enumerate() {
        set(choice, "index", json!(position));
    }
    set(&mut merged, "choices", Value::Array(choices));
    set(&mut merged, "usage", usage.to_openai());
    Ok(merged)
}

/// Read an OpenAI `usage` object back into totals (for merging).
fn usage_from_openai(usage: Option<&Value>) -> Result<UsageTotals, String> {
    let Some(usage) = usage.filter(|usage| !usage.is_null()) else {
        return Ok(UsageTotals::default());
    };
    Ok(UsageTotals {
        prompt_tokens: usage_u64(usage.get("prompt_tokens"), "prompt_tokens")?,
        completion_tokens: usage_u64(usage.get("completion_tokens"), "completion_tokens")?,
        cached_tokens: usage_u64(usage.pointer("/prompt_tokens_details/cached_tokens"), "cached_tokens")?,
        reasoning_tokens: usage_u64(
            usage.pointer("/completion_tokens_details/reasoning_tokens"),
            "reasoning_tokens",
        )?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::panic
    )]

    use super::*;

    #[test]
    fn provider_lookup_and_native_auth() {
        assert!(adapter_for("google").is_none(), "the Gemini dialect registers as \"gemini\"");
        assert!(adapter_for("").is_none());
        for name in SUPPORTED_PROVIDERS {
            let kind = adapter_for(name).unwrap();
            assert_eq!(kind.name(), *name);
        }
        assert_eq!(ProviderKind::OpenAi.native_auth_header(), None);
        assert_eq!(ProviderKind::Anthropic.native_auth_header(), Some("x-api-key"));
        assert_eq!(ProviderKind::Gemini.native_auth_header(), Some("x-goog-api-key"));
        assert!(!ProviderKind::OpenAi.translates());
        assert!(ProviderKind::Anthropic.translates() && ProviderKind::Gemini.translates());
    }

    #[test]
    fn choice_count_accepts_integers_in_range_only() {
        assert_eq!(choice_count(&json!({})).unwrap(), 1);
        assert_eq!(choice_count(&json!({"n": null})).unwrap(), 1);
        assert_eq!(choice_count(&json!({"n": 1})).unwrap(), 1);
        assert_eq!(choice_count(&json!({"n": 8})).unwrap(), 8);
        for bad in [json!(0), json!(9), json!(2.0), json!("2"), json!(-1), json!(true)] {
            assert!(choice_count(&json!({"n": bad})).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn helpers_read_openai_request_fields() {
        assert_eq!(
            content_text(Some(&json!([{"type":"text","text":"a"},{"type":"image_url"},{"type":"text","text":"b"}]))),
            Some("ab".to_owned())
        );
        assert_eq!(content_text(Some(&json!("plain"))), Some("plain".to_owned()));
        assert_eq!(content_text(Some(&Value::Null)), None);
        assert_eq!(
            base64_data_url("data:image/png;base64,AAAA"),
            Some(("image/png".to_owned(), "AAAA".to_owned()))
        );
        assert_eq!(base64_data_url("https://example.org/a.png"), None);
        assert_eq!(base64_data_url("data:text/plain,hello"), None);
        assert_eq!(arguments_object(Some(&json!(""))).unwrap(), json!({}));
        assert_eq!(arguments_object(None).unwrap(), json!({}));
        assert_eq!(arguments_object(Some(&json!("{\"a\":1}"))).unwrap(), json!({"a": 1}));
        assert!(arguments_object(Some(&json!("[1]"))).is_err());
        assert!(arguments_object(Some(&json!("{nope"))).is_err());
        assert_eq!(requested_max_tokens(&json!({"max_tokens": 5})), Some(5));
        assert_eq!(
            requested_max_tokens(&json!({"max_tokens": 5, "max_completion_tokens": 7})),
            Some(7)
        );
        assert_eq!(requested_max_tokens(&json!({"max_tokens": 0})), None);
        assert_eq!(stop_sequences(&json!({"stop": "x"})), vec![json!("x")]);
        assert_eq!(stop_sequences(&json!({"stop": ["x", 1, "y"]})), vec![json!("x"), json!("y")]);
        assert!(wants_stream(&json!({"stream": true})) && !wants_stream(&json!({})));
        assert!(wants_usage_chunk(&json!({"stream_options": {"include_usage": true}})));
    }

    #[test]
    fn usage_totals_sum_and_render() {
        let mut total = UsageTotals {
            prompt_tokens: Some(10),
            completion_tokens: Some(3),
            cached_tokens: Some(4),
            reasoning_tokens: None,
        };
        total.add(&UsageTotals {
            prompt_tokens: Some(5),
            completion_tokens: None,
            cached_tokens: None,
            reasoning_tokens: Some(2),
        });
        assert_eq!(
            total.to_openai(),
            json!({
                "prompt_tokens": 15,
                "completion_tokens": 3,
                "total_tokens": 18,
                "prompt_tokens_details": {"cached_tokens": 4},
                "completion_tokens_details": {"reasoning_tokens": 2},
            })
        );
        assert!(!UsageTotals::default().is_known());
    }

    #[test]
    fn sse_frame_splitting_handles_bom_events_and_keepalives() {
        let frame = split_sse_frame("\u{feff}event: message_start\ndata: {\"a\":1}\ndata: more\n\n");
        assert!(frame.is_sse);
        assert_eq!(frame.event, "message_start");
        assert_eq!(frame.data.as_deref(), Some("{\"a\":1}\nmore"));
        assert!(split_sse_frame(": keepalive\n\n").data.is_none());
        assert!(split_sse_frame("event: ping\ndata:\n\n").data.is_none());
        let body = split_sse_frame("  {\"type\":\"message\"}  ");
        assert!(!body.is_sse);
        assert_eq!(body.data.as_deref(), Some("{\"type\":\"message\"}"));
    }

    #[test]
    fn error_envelope_follows_openai_taxonomy_and_keeps_native_code() {
        let anthropic = openai_error_envelope(
            ProviderKind::Anthropic,
            429,
            br#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#,
        );
        assert_eq!(anthropic["error"]["message"], "slow down");
        assert_eq!(anthropic["error"]["type"], "rate_limit_error");
        assert_eq!(anthropic["error"]["code"], "rate_limit_error");
        let gemini = openai_error_envelope(
            ProviderKind::Gemini,
            400,
            br#"{"error":{"code":400,"message":"bad","status":"INVALID_ARGUMENT"}}"#,
        );
        assert_eq!(gemini["error"]["type"], "invalid_request_error");
        assert_eq!(gemini["error"]["code"], "INVALID_ARGUMENT");
        let html = openai_error_envelope(ProviderKind::Anthropic, 503, b"<html>busy</html>");
        assert_eq!(html["error"]["type"], "api_error");
        assert_eq!(html["error"]["code"], 503);
        assert!(!html["error"]["message"].as_str().unwrap().contains("<html>"));
    }

    #[test]
    fn merge_completions_renumbers_choices_and_sums_usage() {
        let a = json!({"id":"x","object":"chat.completion","created":1,"model":"m",
            "choices":[{"index":0,"message":{"role":"assistant","content":"a"},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}});
        let b = json!({"id":"y","object":"chat.completion","created":2,"model":"m",
            "choices":[{"index":0,"message":{"role":"assistant","content":"b"},"finish_reason":"length"}],
            "usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"prompt_tokens_details":{"cached_tokens":3}}});
        let merged = merge_completions(vec![a, b]).unwrap();
        assert_eq!(merged["id"], "x");
        assert_eq!(merged["choices"].as_array().unwrap().len(), 2);
        assert_eq!(merged["choices"][1]["index"], 1);
        assert_eq!(merged["choices"][1]["message"]["content"], "b");
        assert_eq!(merged["usage"]["prompt_tokens"], 20);
        assert_eq!(merged["usage"]["completion_tokens"], 3);
        assert_eq!(merged["usage"]["total_tokens"], 23);
        assert_eq!(merged["usage"]["prompt_tokens_details"]["cached_tokens"], 3);
        assert!(merge_completions(Vec::new()).is_err());
    }

    /// A translator that echoes its frames as content deltas and
    /// finishes on "END", for exercising the stream plumbing.
    struct Echo {
        index: u64,
        completion: u64,
    }

    impl StreamTranslator for Echo {
        fn frame(&mut self, raw: &str) -> Result<Vec<Value>, String> {
            let frame = split_sse_frame(raw);
            let Some(data) = frame.data else { return Ok(Vec::new()) };
            if data == "FAIL" {
                return Err("upstream said fail".to_owned());
            }
            if data == "END" {
                return Ok(vec![chunk("id", "m", 1, self.index, json!({}), Some("stop"))]);
            }
            self.completion += 1;
            Ok(vec![chunk("id", "m", 1, self.index, json!({"content": data}), None)])
        }
        fn finish(&mut self) -> Result<(Vec<Value>, UsageTotals), String> {
            Ok((
                Vec::new(),
                UsageTotals {
                    prompt_tokens: Some(10),
                    completion_tokens: Some(self.completion),
                    cached_tokens: None,
                    reasoning_tokens: None,
                },
            ))
        }
    }

    fn byte_stream(frames: &[&str]) -> BoxStream<'static, Result<Bytes, std::io::Error>> {
        let owned: Vec<Result<Bytes, std::io::Error>> =
            frames.iter().map(|frame| Ok(Bytes::from((*frame).to_owned()))).collect();
        futures::stream::iter(owned).boxed()
    }

    async fn collect(stream: MergedOpenAiStream) -> Result<Vec<Value>, std::io::Error> {
        let mut frames = Vec::new();
        let mut stream = stream;
        while let Some(item) = stream.next().await {
            let bytes = item?;
            let text = std::str::from_utf8(&bytes).unwrap();
            for frame in text.split("\n\n").filter(|frame| !frame.is_empty()) {
                let data = frame.strip_prefix("data: ").unwrap();
                if data == "[DONE]" {
                    frames.push(json!("[DONE]"));
                } else {
                    frames.push(serde_json::from_str(data).unwrap());
                }
            }
        }
        Ok(frames)
    }

    #[tokio::test]
    async fn merged_stream_interleaves_choices_and_sums_usage_with_standalone_chunk() {
        let first = TranslatingStream::new(
            byte_stream(&["data: a1\n\n", "data: a2\n\ndata: END\n\n"]),
            Box::new(Echo { index: 0, completion: 0 }),
        );
        let second = TranslatingStream::new(
            byte_stream(&["data: b1\n\n", "data: END\n\n"]),
            Box::new(Echo { index: 1, completion: 0 }),
        );
        let merged = MergedOpenAiStream::new(vec![first, second], true, "id".into(), "m".into(), 1);
        let frames = collect(merged).await.unwrap();
        let finishes = frames
            .iter()
            .filter(|frame| frame.pointer("/choices/0/finish_reason").is_some_and(|r| r == "stop"))
            .count();
        assert_eq!(finishes, 2, "one finish per choice: {frames:?}");
        let usage = &frames[frames.len() - 2];
        assert_eq!(usage["choices"], json!([]));
        assert_eq!(usage["usage"]["prompt_tokens"], 20, "both requests bill their prompt");
        assert_eq!(usage["usage"]["completion_tokens"], 3);
        assert_eq!(frames[frames.len() - 1], json!("[DONE]"));
        let indexes: std::collections::BTreeSet<u64> = frames
            .iter()
            .filter_map(|frame| frame.pointer("/choices/0/index").and_then(Value::as_u64))
            .collect();
        assert_eq!(indexes, [0u64, 1].into_iter().collect());
    }

    #[tokio::test]
    async fn merged_stream_without_include_usage_folds_usage_into_last_finish() {
        let only = TranslatingStream::new(
            byte_stream(&["data: a1\n\n", "data: END\n\n"]),
            Box::new(Echo { index: 0, completion: 0 }),
        );
        let merged = MergedOpenAiStream::new(vec![only], false, "id".into(), "m".into(), 1);
        let frames = collect(merged).await.unwrap();
        assert_eq!(frames.len(), 3, "content, finish-with-usage, DONE: {frames:?}");
        assert_eq!(frames[0]["choices"][0]["delta"]["content"], "a1");
        assert!(frames[0].get("usage").is_none());
        assert_eq!(frames[1]["choices"][0]["finish_reason"], "stop");
        assert_eq!(frames[1]["usage"]["completion_tokens"], 1);
        assert_eq!(frames[2], json!("[DONE]"));
    }

    #[tokio::test]
    async fn merged_stream_propagates_translator_failures() {
        let failing = TranslatingStream::new(
            byte_stream(&["data: a1\n\n", "data: FAIL\n\n"]),
            Box::new(Echo { index: 0, completion: 0 }),
        );
        let merged = MergedOpenAiStream::new(vec![failing], true, "id".into(), "m".into(), 1);
        let error = collect(merged).await.unwrap_err();
        assert!(error.to_string().contains("upstream said fail"), "{error}");
    }

    #[tokio::test]
    async fn translating_stream_feeds_unterminated_tail_at_eof() {
        let tail = TranslatingStream::new(
            byte_stream(&["data: a1\n\ndata: END"]),
            Box::new(Echo { index: 0, completion: 0 }),
        );
        let merged = MergedOpenAiStream::new(vec![tail], true, "id".into(), "m".into(), 1);
        let frames = collect(merged).await.unwrap();
        assert_eq!(frames[1]["choices"][0]["finish_reason"], "stop");
    }
}
