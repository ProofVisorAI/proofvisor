//! Anthropic Messages API translation, both directions.
//!
//! Request (OpenAI chat completion → `POST /v1/messages`):
//!
//! * every `system` (and `developer`) message is concatenated into the
//!   top-level `system` string, separated by blank lines;
//! * `user` content becomes text blocks, with base64 `data:` image
//!   URLs as base64 image sources and `http(s)` image URLs as URL
//!   image sources;
//! * `assistant` text becomes a text block and each `tool_calls` entry
//!   a `tool_use` block (`arguments` parsed into the `input` object);
//! * consecutive `tool` messages become `tool_result` blocks grouped
//!   into one user turn;
//! * `tools` → `name`/`description`/`input_schema`; `tool_choice` →
//!   `auto`/`none`/`any`/`tool`, with `parallel_tool_calls: false` as
//!   `disable_parallel_tool_use`;
//! * `max_tokens` is mandatory for Anthropic: the request's
//!   `max_completion_tokens` or `max_tokens` is used, else the
//!   configured `provider_default_max_tokens`;
//! * `temperature`, `top_p`, `stop` → `stop_sequences`, `stream`, and
//!   `user` → `metadata.user_id` carry over. `n` is handled by the
//!   pipeline (one upstream request per choice) and never sent.
//!
//! Refused with a 400, because answering without them would silently
//! give the client something other than what it asked for:
//! `logprobs`/`top_logprobs`, and `response_format` of type
//! `json_object` or `json_schema` (the Messages API has no JSON mode;
//! `{"type": "text"}` is accepted).
//!
//! Dropped because the Messages API has no equivalent and they only
//! steer sampling: `seed`, `presence_penalty`, `frequency_penalty`,
//! `logit_bias`, `store`, `service_tier`, per-message `name` fields.
//!
//! Response: content blocks → `choices[0].message.content` (text) and
//! `tool_calls` (`tool_use` → `id`, `function.name`, JSON-encoded
//! `arguments`); `thinking` blocks → `reasoning_content`; `stop_reason`
//! → `finish_reason` (`end_turn`/`stop_sequence` → `stop`,
//! `max_tokens`/`model_context_window_exceeded` → `length`,
//! `tool_use`/`pause_turn` → `tool_calls`, `refusal` →
//! `content_filter`); usage `input_tokens` + cache creation + cache
//! read → `prompt_tokens` (cache read also as
//! `prompt_tokens_details.cached_tokens`), `output_tokens` →
//! `completion_tokens`.

use super::{
    arguments_object, base64_data_url, chunk, content_text, requested_max_tokens, set, split_sse_frame,
    stop_sequences, usage_u64, StreamTranslator, UsageTotals,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The Messages API path on `upstream_url`.
pub(crate) const MESSAGES_PATH: &str = "/v1/messages";

/// Build the Messages API body for one OpenAI chat request. The
/// result never carries `n`; multi-choice requests fan out upstream.
pub(crate) fn build_request(payload: &Value, default_max_tokens: u64) -> Result<Value, String> {
    let model = payload
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty())
        .ok_or_else(|| "model is required".to_owned())?;
    let messages = payload
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "messages must be an array".to_owned())?;
    super::refuse_logprobs(payload)?;
    match payload.pointer("/response_format/type").and_then(Value::as_str) {
        None | Some("text") => {}
        Some(other) => {
            return Err(format!(
                "response_format {other:?} is not available from Anthropic; ask for JSON in the prompt or use a tool"
            ));
        }
    }

    let mut system: Vec<String> = Vec::new();
    let mut turns: Vec<Value> = Vec::new();
    let mut pending_results: Vec<Value> = Vec::new();
    let flush_results = |pending: &mut Vec<Value>, turns: &mut Vec<Value>| {
        if !pending.is_empty() {
            turns.push(json!({"role": "user", "content": std::mem::take(pending)}));
        }
    };
    for message in messages {
        let role = message.get("role").and_then(Value::as_str).unwrap_or_default();
        match role {
            "system" | "developer" => {
                flush_results(&mut pending_results, &mut turns);
                if let Some(text) = content_text(message.get("content")) {
                    if !text.is_empty() {
                        system.push(text);
                    }
                }
            }
            "user" => {
                flush_results(&mut pending_results, &mut turns);
                let blocks = user_blocks(message.get("content"))?;
                if !blocks.is_empty() {
                    turns.push(json!({"role": "user", "content": blocks}));
                }
            }
            "assistant" => {
                flush_results(&mut pending_results, &mut turns);
                let mut blocks: Vec<Value> = Vec::new();
                if let Some(text) = content_text(message.get("content")) {
                    if !text.is_empty() {
                        blocks.push(json!({"type": "text", "text": text}));
                    }
                }
                if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        let id = call
                            .get("id")
                            .and_then(Value::as_str)
                            .ok_or_else(|| "assistant tool_calls entries need an id".to_owned())?;
                        let name = call
                            .pointer("/function/name")
                            .and_then(Value::as_str)
                            .ok_or_else(|| "assistant tool_calls entries need function.name".to_owned())?;
                        let input = arguments_object(call.pointer("/function/arguments"))?;
                        blocks.push(json!({"type": "tool_use", "id": id, "name": name, "input": input}));
                    }
                }
                if !blocks.is_empty() {
                    turns.push(json!({"role": "assistant", "content": blocks}));
                }
            }
            "tool" => {
                let id = message
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "tool messages need a tool_call_id".to_owned())?;
                let content = match message.get("content") {
                    Some(Value::Array(parts)) => Value::Array(
                        parts
                            .iter()
                            .filter_map(|part| part.get("text").and_then(Value::as_str))
                            .map(|text| json!({"type": "text", "text": text}))
                            .collect(),
                    ),
                    other => Value::String(content_text(other).unwrap_or_default()),
                };
                pending_results.push(json!({"type": "tool_result", "tool_use_id": id, "content": content}));
            }
            other => return Err(format!("unsupported message role {other:?}")),
        }
    }
    flush_results(&mut pending_results, &mut turns);

    let mut body = json!({
        "model": model,
        "max_tokens": requested_max_tokens(payload).unwrap_or(default_max_tokens),
        "messages": turns,
    });
    if !system.is_empty() {
        set(&mut body, "system", Value::String(system.join("\n\n")));
    }
    for field in ["temperature", "top_p"] {
        if let Some(value) = payload.get(field).filter(|value| value.is_number()) {
            set(&mut body, field, value.clone());
        }
    }
    let stops = stop_sequences(payload);
    if !stops.is_empty() {
        set(&mut body, "stop_sequences", Value::Array(stops));
    }
    if payload.get("stream").and_then(Value::as_bool) == Some(true) {
        set(&mut body, "stream", Value::Bool(true));
    }
    if let Some(user) = payload.get("user").and_then(Value::as_str) {
        set(&mut body, "metadata", json!({"user_id": user}));
    }
    let tools = tool_definitions(payload.get("tools"))?;
    if !tools.is_empty() {
        set(&mut body, "tools", Value::Array(tools));
        if let Some(choice) = tool_choice(payload)? {
            set(&mut body, "tool_choice", choice);
        }
    }
    Ok(body)
}

/// OpenAI user content → Anthropic content blocks.
fn user_blocks(content: Option<&Value>) -> Result<Vec<Value>, String> {
    let mut blocks = Vec::new();
    match content {
        Some(Value::String(text)) => {
            if !text.is_empty() {
                blocks.push(json!({"type": "text", "text": text}));
            }
        }
        Some(Value::Array(parts)) => {
            for part in parts {
                match part.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "text" => {
                        if let Some(text) = part.get("text").and_then(Value::as_str) {
                            if !text.is_empty() {
                                blocks.push(json!({"type": "text", "text": text}));
                            }
                        }
                    }
                    "image_url" => {
                        let url = part
                            .pointer("/image_url/url")
                            .or_else(|| part.get("image_url"))
                            .and_then(Value::as_str)
                            .ok_or_else(|| "image_url parts need image_url.url".to_owned())?;
                        let source = if let Some((media_type, data)) = base64_data_url(url) {
                            json!({"type": "base64", "media_type": media_type, "data": data})
                        } else if url.starts_with("https://") || url.starts_with("http://") {
                            json!({"type": "url", "url": url})
                        } else {
                            return Err("image_url must be a base64 data URL or an http(s) URL".to_owned());
                        };
                        blocks.push(json!({"type": "image", "source": source}));
                    }
                    other => return Err(format!("unsupported content part type {other:?}")),
                }
            }
        }
        None | Some(Value::Null) => {}
        Some(_) => return Err("message content must be a string or an array of parts".to_owned()),
    }
    Ok(blocks)
}

/// OpenAI `tools` → Anthropic tool definitions.
fn tool_definitions(tools: Option<&Value>) -> Result<Vec<Value>, String> {
    let Some(Value::Array(tools)) = tools else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(tools.len());
    for tool in tools {
        if tool.get("type").and_then(Value::as_str) != Some("function") {
            return Err("only tools of type \"function\" are supported".to_owned());
        }
        let function = tool
            .get("function")
            .ok_or_else(|| "function tools need a function object".to_owned())?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "function tools need a name".to_owned())?;
        let mut definition = json!({
            "name": name,
            "input_schema": function
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
        });
        if let Some(description) = function.get("description").and_then(Value::as_str) {
            set(
                &mut definition,
                "description",
                Value::String(description.to_owned()),
            );
        }
        out.push(definition);
    }
    Ok(out)
}

/// OpenAI `tool_choice` (+ `parallel_tool_calls`) → Anthropic
/// `tool_choice`.
fn tool_choice(payload: &Value) -> Result<Option<Value>, String> {
    let disable_parallel = payload.get("parallel_tool_calls").and_then(Value::as_bool) == Some(false);
    let mut choice = match payload.get("tool_choice") {
        None | Some(Value::Null) => {
            if disable_parallel {
                json!({"type": "auto"})
            } else {
                return Ok(None);
            }
        }
        Some(Value::String(mode)) => match mode.as_str() {
            "auto" => json!({"type": "auto"}),
            "none" => json!({"type": "none"}),
            "required" => json!({"type": "any"}),
            other => return Err(format!("unsupported tool_choice {other:?}")),
        },
        Some(object) => {
            let name = object
                .pointer("/function/name")
                .and_then(Value::as_str)
                .ok_or_else(|| "tool_choice objects need function.name".to_owned())?;
            json!({"type": "tool", "name": name})
        }
    };
    if disable_parallel && choice.get("type").and_then(Value::as_str) != Some("none") {
        set(&mut choice, "disable_parallel_tool_use", Value::Bool(true));
    }
    Ok(Some(choice))
}

/// Anthropic `stop_reason` → OpenAI `finish_reason`. A turn that
/// carries tool calls finishes with `tool_calls` even when Anthropic
/// said `end_turn`, matching OpenAI semantics.
pub(crate) fn map_stop_reason(native: &str, has_tool_calls: bool) -> String {
    let mapped = match native {
        "end_turn" | "stop_sequence" => "stop",
        "max_tokens" | "model_context_window_exceeded" => "length",
        "tool_use" | "pause_turn" => "tool_calls",
        "refusal" => "content_filter",
        other => other,
    };
    if mapped == "stop" && has_tool_calls {
        return "tool_calls".to_owned();
    }
    mapped.to_owned()
}

/// Anthropic `usage` → totals. `input_tokens` excludes the cache-
/// accounted input, so the true prompt volume is the sum of all three
/// input counters.
pub(crate) fn usage_totals(usage: Option<&Value>) -> Result<UsageTotals, String> {
    let Some(usage) = usage.filter(|usage| !usage.is_null()) else {
        return Ok(UsageTotals::default());
    };
    let input = usage_u64(usage.get("input_tokens"), "input_tokens")?;
    let creation = usage_u64(
        usage.get("cache_creation_input_tokens"),
        "cache_creation_input_tokens",
    )?;
    let read = usage_u64(usage.get("cache_read_input_tokens"), "cache_read_input_tokens")?;
    let prompt_tokens = match (input, creation, read) {
        (None, None, None) => None,
        (a, b, c) => {
            let sum = a
                .unwrap_or(0)
                .saturating_add(b.unwrap_or(0))
                .saturating_add(c.unwrap_or(0));
            if sum > pv_core::error::JCS_SAFE_MAX {
                return Err("upstream input token sum exceeds JCS-safe bounds".to_owned());
            }
            Some(sum)
        }
    };
    Ok(UsageTotals {
        prompt_tokens,
        completion_tokens: usage_u64(usage.get("output_tokens"), "output_tokens")?,
        cached_tokens: read,
        reasoning_tokens: None,
    })
}

/// Text, reasoning and tool calls gathered from a content-block array.
struct Gathered {
    text: String,
    reasoning: String,
    tool_calls: Vec<Value>,
}

fn gather_blocks(content: Option<&Value>) -> Result<Gathered, String> {
    let mut gathered = Gathered {
        text: String::new(),
        reasoning: String::new(),
        tool_calls: Vec::new(),
    };
    let Some(Value::Array(blocks)) = content else {
        return Ok(gathered);
    };
    for block in blocks {
        match block.get("type").and_then(Value::as_str).unwrap_or_default() {
            "text" => {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    gathered.text.push_str(text);
                }
            }
            "thinking" => {
                if let Some(text) = block.get("thinking").and_then(Value::as_str) {
                    gathered.reasoning.push_str(text);
                }
            }
            "tool_use" => {
                let input = block
                    .get("input")
                    .filter(|input| !input.is_null())
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let arguments = serde_json::to_string(&input)
                    .map_err(|error| format!("tool input is not serializable: {error}"))?;
                gathered.tool_calls.push(json!({
                    "id": block.get("id").and_then(Value::as_str).map_or_else(super::fresh_tool_call_id, str::to_owned),
                    "type": "function",
                    "function": {
                        "name": block.get("name").and_then(Value::as_str).unwrap_or("unknown"),
                        "arguments": arguments,
                    },
                }));
            }
            // redacted_thinking, server_tool_use results, citations:
            // nothing the OpenAI shape can carry.
            _ => {}
        }
    }
    Ok(gathered)
}

/// Translate one buffered Messages API response into an OpenAI
/// `chat.completion` with a single choice at `index`.
pub(crate) fn translate_message(body: &Value, id: &str, created: u64, index: u64) -> Result<Value, String> {
    if body.get("type").and_then(Value::as_str) == Some("error") {
        return Err(format!(
            "upstream error: {}",
            body.pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("(no message)")
        ));
    }
    let gathered = gather_blocks(body.get("content"))?;
    let finish_reason = body
        .get("stop_reason")
        .and_then(Value::as_str)
        .map(|reason| map_stop_reason(reason, !gathered.tool_calls.is_empty()));
    let mut message = json!({"role": "assistant"});
    if gathered.text.is_empty() && !gathered.tool_calls.is_empty() {
        set(&mut message, "content", Value::Null);
    } else {
        set(&mut message, "content", Value::String(gathered.text));
    }
    if !gathered.reasoning.is_empty() {
        set(
            &mut message,
            "reasoning_content",
            Value::String(gathered.reasoning),
        );
    }
    if !gathered.tool_calls.is_empty() {
        set(&mut message, "tool_calls", Value::Array(gathered.tool_calls));
    }
    Ok(json!({
        "id": id,
        "object": "chat.completion",
        "created": created,
        "model": body.get("model").and_then(Value::as_str).unwrap_or(""),
        "choices": [{
            "index": index,
            "message": message,
            "logprobs": Value::Null,
            "finish_reason": finish_reason,
        }],
        "usage": usage_totals(body.get("usage"))?.to_openai(),
    }))
}

/// Stateful translator for one Anthropic SSE stream, emitting chunks
/// for one OpenAI choice.
pub(crate) struct AnthropicStreamTranslator {
    index: u64,
    id: String,
    model: String,
    created: u64,
    usage: UsageTotals,
    /// Content-block index → OpenAI tool-call index within the choice.
    tool_slots: BTreeMap<u64, u64>,
    next_tool_index: u64,
    saw_tool_call: bool,
    started: bool,
}

impl AnthropicStreamTranslator {
    pub(crate) fn new(index: u64, id: String, fallback_model: String, created: u64) -> Self {
        Self {
            index,
            id,
            model: fallback_model,
            created,
            usage: UsageTotals::default(),
            tool_slots: BTreeMap::new(),
            next_tool_index: 0,
            saw_tool_call: false,
            started: false,
        }
    }

    fn emit(&mut self, mut delta: Value, finish_reason: Option<&str>) -> Value {
        if !self.started {
            self.started = true;
            set(&mut delta, "role", Value::String("assistant".to_owned()));
            if delta.get("content").is_none() {
                set(&mut delta, "content", Value::String(String::new()));
            }
        }
        chunk(
            &self.id,
            &self.model,
            self.created,
            self.index,
            delta,
            finish_reason,
        )
    }

    fn tool_start(&mut self, block_index: u64, block: &Value) -> Value {
        let slot = self.next_tool_index;
        self.next_tool_index = self.next_tool_index.saturating_add(1);
        self.tool_slots.insert(block_index, slot);
        self.saw_tool_call = true;
        let id = block
            .get("id")
            .and_then(Value::as_str)
            .map_or_else(super::fresh_tool_call_id, str::to_owned);
        let name = block.get("name").and_then(Value::as_str).unwrap_or("unknown");
        self.emit(
            json!({"tool_calls": [{"index": slot, "id": id, "type": "function", "function": {"name": name, "arguments": ""}}]}),
            None,
        )
    }

    /// A whole `message` document inside a stream (some gateways send
    /// one): emit it as chunks.
    fn whole_message(&mut self, body: &Value) -> Result<Vec<Value>, String> {
        let gathered = gather_blocks(body.get("content"))?;
        if let Some(model) = body.get("model").and_then(Value::as_str) {
            self.model = model.to_owned();
        }
        let mut chunks = Vec::new();
        if !gathered.text.is_empty() {
            chunks.push(self.emit(json!({"content": gathered.text}), None));
        }
        if !gathered.reasoning.is_empty() {
            chunks.push(self.emit(json!({"reasoning_content": gathered.reasoning}), None));
        }
        for mut call in gathered.tool_calls {
            let slot = self.next_tool_index;
            self.next_tool_index = self.next_tool_index.saturating_add(1);
            set(&mut call, "index", json!(slot));
            self.saw_tool_call = true;
            chunks.push(self.emit(json!({"tool_calls": [call]}), None));
        }
        if let Some(reason) = body.get("stop_reason").and_then(Value::as_str) {
            let mapped = map_stop_reason(reason, self.saw_tool_call);
            chunks.push(self.emit(json!({}), Some(&mapped)));
        }
        self.usage.add(&usage_totals(body.get("usage"))?);
        Ok(chunks)
    }
}

impl StreamTranslator for AnthropicStreamTranslator {
    fn frame(&mut self, raw: &str) -> Result<Vec<Value>, String> {
        let frame = split_sse_frame(raw);
        let Some(data) = frame.data else {
            return Ok(Vec::new());
        };
        if data.trim() == "[DONE]" {
            return Ok(Vec::new());
        }
        let value: Value =
            serde_json::from_str(&data).map_err(|error| format!("invalid upstream JSON frame: {error}"))?;
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        // The SSE event name and the payload's `type` are redundant in
        // this dialect; require agreement so a frame cannot smuggle an
        // error payload under a content event name (or vice versa).
        // `message` is the SSE default event name and is treated as
        // unset.
        if frame.is_sse && !frame.event.is_empty() && frame.event != "message" && frame.event != kind {
            return Err(format!(
                "upstream SSE event name {:?} does not match payload type {kind:?}",
                frame.event
            ));
        }
        match kind.as_str() {
            "ping" | "message_stop" | "content_block_stop" => Ok(Vec::new()),
            "error" => Err(format!(
                "upstream streamed an error event: {}",
                value
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("(no message)")
            )),
            "message_start" => {
                if let Some(model) = value.pointer("/message/model").and_then(Value::as_str) {
                    self.model = model.to_owned();
                }
                // message_start reports the prompt side; output_tokens
                // here is a placeholder that message_delta supersedes.
                let start = usage_totals(value.pointer("/message/usage"))?;
                self.usage.prompt_tokens = start.prompt_tokens;
                self.usage.cached_tokens = start.cached_tokens;
                if self.usage.completion_tokens.is_none() {
                    self.usage.completion_tokens = start.completion_tokens;
                }
                Ok(vec![self.emit(json!({"content": ""}), None)])
            }
            "content_block_start" => {
                let block_index = usage_u64(value.get("index"), "content block index")?
                    .ok_or_else(|| "upstream content block has no index".to_owned())?;
                let block = value
                    .get("content_block")
                    .ok_or_else(|| "content_block_start has no content_block".to_owned())?;
                match block.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "text" => Ok(block
                        .get("text")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(|text| self.emit(json!({"content": text}), None))
                        .into_iter()
                        .collect()),
                    "thinking" => Ok(block
                        .get("thinking")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(|text| self.emit(json!({"reasoning_content": text}), None))
                        .into_iter()
                        .collect()),
                    "tool_use" => Ok(vec![self.tool_start(block_index, block)]),
                    _ => Ok(Vec::new()),
                }
            }
            "content_block_delta" => {
                let block_index = usage_u64(value.get("index"), "content block index")?
                    .ok_or_else(|| "upstream content block has no index".to_owned())?;
                let delta = value
                    .get("delta")
                    .ok_or_else(|| "content_block_delta has no delta".to_owned())?;
                match delta.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "text_delta" => {
                        let text = delta.get("text").and_then(Value::as_str).unwrap_or_default();
                        Ok(vec![self.emit(json!({"content": text}), None)])
                    }
                    "thinking_delta" => {
                        let text = delta.get("thinking").and_then(Value::as_str).unwrap_or_default();
                        Ok(vec![self.emit(json!({"reasoning_content": text}), None)])
                    }
                    "input_json_delta" => {
                        let slot = *self.tool_slots.get(&block_index).ok_or_else(|| {
                            format!("input_json_delta for unknown content block {block_index}")
                        })?;
                        let partial = delta
                            .get("partial_json")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        Ok(vec![self.emit(
                            json!({"tool_calls": [{"index": slot, "function": {"arguments": partial}}]}),
                            None,
                        )])
                    }
                    // signature_delta and friends: nothing to relay.
                    _ => Ok(Vec::new()),
                }
            }
            "message_delta" => {
                let delta_usage = usage_totals(value.get("usage"))?;
                if delta_usage.completion_tokens.is_some() {
                    self.usage.completion_tokens = delta_usage.completion_tokens;
                }
                // Some gateways also repeat the input side here.
                if delta_usage.prompt_tokens.is_some() {
                    self.usage.prompt_tokens = delta_usage.prompt_tokens;
                    self.usage.cached_tokens = delta_usage.cached_tokens;
                }
                match value.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    Some(reason) if !reason.is_empty() => {
                        let mapped = map_stop_reason(reason, self.saw_tool_call);
                        Ok(vec![self.emit(json!({}), Some(&mapped))])
                    }
                    _ => Ok(Vec::new()),
                }
            }
            "message" => self.whole_message(&value),
            // Unknown event types carry nothing this translation can
            // express; Anthropic documents that clients must ignore
            // them.
            _ => Ok(Vec::new()),
        }
    }

    fn finish(&mut self) -> Result<(Vec<Value>, UsageTotals), String> {
        Ok((Vec::new(), self.usage))
    }
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

    fn frames(translator: &mut AnthropicStreamTranslator, raw: &[&str]) -> Vec<Value> {
        raw.iter()
            .flat_map(|frame| translator.frame(frame).unwrap())
            .collect()
    }

    #[test]
    fn request_maps_system_messages_tools_and_sampling_fields() {
        let payload = json!({
            "model": "claude-sonnet-4-5",
            "messages": [
                {"role": "system", "content": "Be terse."},
                {"role": "developer", "content": [{"type": "text", "text": "Answer in French."}]},
                {"role": "user", "content": "Bonjour"},
            ],
            "temperature": 0.2,
            "top_p": 0.9,
            "stop": ["END"],
            "stream": true,
            "user": "user-42",
            "max_completion_tokens": 77,
            "max_tokens": 5,
            "n": 3,
            "seed": 7,
            "tools": [{"type": "function", "function": {"name": "lookup", "description": "Look", "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}}}],
            "tool_choice": "required",
            "parallel_tool_calls": false,
        });
        let body = build_request(&payload, 4096).unwrap();
        assert_eq!(body["model"], "claude-sonnet-4-5");
        assert_eq!(body["system"], "Be terse.\n\nAnswer in French.");
        assert_eq!(
            body["max_tokens"], 77,
            "max_completion_tokens wins over max_tokens"
        );
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["top_p"], 0.9);
        assert_eq!(body["stop_sequences"], json!(["END"]));
        assert_eq!(body["stream"], true);
        assert_eq!(body["metadata"]["user_id"], "user-42");
        assert_eq!(
            body["messages"],
            json!([{"role": "user", "content": [{"type": "text", "text": "Bonjour"}]}])
        );
        assert_eq!(body["tools"][0]["name"], "lookup");
        assert_eq!(body["tools"][0]["description"], "Look");
        assert_eq!(
            body["tools"][0]["input_schema"]["properties"]["q"]["type"],
            "string"
        );
        assert_eq!(
            body["tool_choice"],
            json!({"type": "any", "disable_parallel_tool_use": true})
        );
        assert!(
            body.get("n").is_none() && body.get("seed").is_none(),
            "n and seed never reach Anthropic"
        );
    }

    #[test]
    fn request_applies_default_max_tokens_and_tool_choice_variants() {
        let base = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
        assert_eq!(build_request(&base, 4096).unwrap()["max_tokens"], 4096);
        assert_eq!(
            build_request(&json!({"model": "m", "messages": [], "max_tokens": 12}), 4096).unwrap()
                ["max_tokens"],
            12
        );
        let tools = json!([{"type": "function", "function": {"name": "f"}}]);
        for (choice, expected) in [
            (json!("auto"), json!({"type": "auto"})),
            (json!("none"), json!({"type": "none"})),
            (
                json!({"type": "function", "function": {"name": "f"}}),
                json!({"type": "tool", "name": "f"}),
            ),
        ] {
            let mut payload = base.clone();
            set(&mut payload, "tools", tools.clone());
            set(&mut payload, "tool_choice", choice);
            assert_eq!(build_request(&payload, 1).unwrap()["tool_choice"], expected);
        }
        // tool_choice without tools is dropped; a tool without a
        // schema gets an empty object schema.
        let mut payload = base.clone();
        set(&mut payload, "tool_choice", json!("auto"));
        assert!(build_request(&payload, 1).unwrap().get("tool_choice").is_none());
        let mut payload = base;
        set(&mut payload, "tools", tools);
        assert_eq!(
            build_request(&payload, 1).unwrap()["tools"][0]["input_schema"],
            json!({"type": "object", "properties": {}})
        );
        assert!(
            build_request(&json!({"messages": []}), 1).is_err(),
            "model is required"
        );
        assert!(build_request(
            &json!({"model": "m", "messages": [{"role": "function", "content": "x"}]}),
            1
        )
        .is_err());
    }

    #[test]
    fn request_maps_tool_calls_tool_results_and_images() {
        let payload = json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "What is in this image?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBOR"}},
                    {"type": "image_url", "image_url": {"url": "https://example.org/cat.jpg"}},
                ]},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{\"x\":1}"}},
                    {"id": "call_2", "type": "function", "function": {"name": "b", "arguments": ""}},
                ]},
                {"role": "tool", "tool_call_id": "call_1", "content": "one"},
                {"role": "tool", "tool_call_id": "call_2", "content": [{"type": "text", "text": "two"}]},
                {"role": "user", "content": "thanks"},
            ],
        });
        let body = build_request(&payload, 1).unwrap();
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(
            messages.len(),
            4,
            "user, assistant, grouped tool results, user: {messages:?}"
        );
        assert_eq!(
            messages[0]["content"][1],
            json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}})
        );
        assert_eq!(
            messages[0]["content"][2]["source"],
            json!({"type": "url", "url": "https://example.org/cat.jpg"})
        );
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(
            messages[1]["content"][0],
            json!({"type": "tool_use", "id": "call_1", "name": "a", "input": {"x": 1}})
        );
        assert_eq!(
            messages[1]["content"][1]["input"],
            json!({}),
            "empty arguments become an empty object"
        );
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(
            messages[2]["content"][0],
            json!({"type": "tool_result", "tool_use_id": "call_1", "content": "one"})
        );
        assert_eq!(
            messages[2]["content"][1]["content"],
            json!([{"type": "text", "text": "two"}])
        );
        assert_eq!(messages[3]["content"][0]["text"], "thanks");

        let bad_args = json!({"model": "m", "messages": [{"role": "assistant", "tool_calls": [{"id": "c", "function": {"name": "a", "arguments": "{nope"}}]}]});
        assert!(
            build_request(&bad_args, 1).is_err(),
            "invalid JSON arguments are refused, not rewritten"
        );
        let bad_image = json!({"model": "m", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "ftp://x"}}]}]});
        assert!(build_request(&bad_image, 1).is_err());
        let no_id = json!({"model": "m", "messages": [{"role": "tool", "content": "x"}]});
        assert!(build_request(&no_id, 1).is_err());
    }

    #[test]
    fn non_streaming_response_maps_text_tool_calls_usage_and_stop_reasons() {
        let body = json!({
            "id": "msg_01",
            "type": "message",
            "model": "claude-sonnet-4-5",
            "content": [
                {"type": "thinking", "thinking": "plan"},
                {"type": "text", "text": "Hi "},
                {"type": "text", "text": "there"},
                {"type": "tool_use", "id": "toolu_1", "name": "read", "input": {"path": "x"}},
                {"type": "tool_use", "id": "toolu_2", "name": "noop", "input": {}},
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 9, "cache_creation_input_tokens": 2, "cache_read_input_tokens": 3, "output_tokens": 12},
        });
        let completion = translate_message(&body, "chatcmpl-x", 1700, 0).unwrap();
        assert_eq!(completion["id"], "chatcmpl-x");
        assert_eq!(completion["object"], "chat.completion");
        assert_eq!(completion["created"], 1700);
        assert_eq!(completion["model"], "claude-sonnet-4-5");
        let choice = &completion["choices"][0];
        assert_eq!(choice["index"], 0);
        assert_eq!(choice["finish_reason"], "tool_calls");
        assert_eq!(choice["message"]["role"], "assistant");
        assert_eq!(choice["message"]["content"], "Hi there");
        assert_eq!(choice["message"]["reasoning_content"], "plan");
        assert_eq!(
            choice["message"]["tool_calls"][0],
            json!({"id": "toolu_1", "type": "function", "function": {"name": "read", "arguments": "{\"path\":\"x\"}"}})
        );
        assert_eq!(choice["message"]["tool_calls"][1]["function"]["arguments"], "{}");
        assert_eq!(
            completion["usage"],
            json!({
                "prompt_tokens": 14,
                "completion_tokens": 12,
                "total_tokens": 26,
                "prompt_tokens_details": {"cached_tokens": 3},
            })
        );

        // Tool-only turn: content is null, like OpenAI.
        let tool_only = json!({"type": "message", "content": [{"type": "tool_use", "id": "t", "name": "f", "input": {}}], "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}});
        let choice = &translate_message(&tool_only, "id", 0, 0).unwrap()["choices"][0];
        assert!(choice["message"]["content"].is_null());
        assert_eq!(
            choice["finish_reason"], "tool_calls",
            "end_turn with tool calls finishes as tool_calls"
        );

        // Empty content: an empty string, finish reason preserved.
        let empty = json!({"type": "message", "content": [], "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 0}});
        let choice = &translate_message(&empty, "id", 0, 2).unwrap()["choices"][0];
        assert_eq!(choice["index"], 2);
        assert_eq!(choice["message"]["content"], "");
        assert_eq!(choice["finish_reason"], "stop");

        for (native, expected) in [
            ("end_turn", "stop"),
            ("stop_sequence", "stop"),
            ("max_tokens", "length"),
            ("model_context_window_exceeded", "length"),
            ("tool_use", "tool_calls"),
            ("pause_turn", "tool_calls"),
            ("refusal", "content_filter"),
            ("mystery", "mystery"),
        ] {
            assert_eq!(map_stop_reason(native, false), expected, "{native}");
        }
        assert!(translate_message(
            &json!({"type": "error", "error": {"message": "nope"}}),
            "id",
            0,
            0
        )
        .is_err());
        assert!(translate_message(
            &json!({"type": "message", "content": [], "usage": {"output_tokens": -1}}),
            "id",
            0,
            0
        )
        .is_err());
    }

    #[test]
    fn streaming_translation_emits_openai_chunks_with_tool_arguments_and_finish() {
        let mut translator = AnthropicStreamTranslator::new(0, "chatcmpl-s".into(), "fallback".into(), 5);
        let chunks = frames(&mut translator, &[
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1,\"cache_read_input_tokens\":7}}}\n\n",
            "event: ping\ndata: {\"type\": \"ping\"}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\",\"input\":{}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"NYC\\\"}\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":15}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ]);
        for chunk in &chunks {
            assert_eq!(chunk["object"], "chat.completion.chunk");
            assert_eq!(chunk["id"], "chatcmpl-s");
            assert_eq!(chunk["model"], "claude-sonnet-4-5");
            assert_eq!(chunk["created"], 5);
            assert_eq!(chunk["choices"][0]["index"], 0);
        }
        assert_eq!(
            chunks[0]["choices"][0]["delta"],
            json!({"role": "assistant", "content": ""})
        );
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "Hello");
        assert!(
            chunks[1]["choices"][0]["delta"].get("role").is_none(),
            "role only on the first chunk"
        );
        assert_eq!(chunks[2]["choices"][0]["delta"]["reasoning_content"], "hmm");
        assert_eq!(
            chunks[3]["choices"][0]["delta"]["tool_calls"][0],
            json!({"index": 0, "id": "toolu_1", "type": "function", "function": {"name": "get_weather", "arguments": ""}})
        );
        assert_eq!(
            chunks[4]["choices"][0]["delta"]["tool_calls"][0],
            json!({"index": 0, "function": {"arguments": "{\"city\":"}})
        );
        assert_eq!(
            chunks[5]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "\"NYC\"}"
        );
        assert_eq!(chunks[6]["choices"][0]["delta"], json!({}));
        assert_eq!(chunks[6]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chunks.len(), 7, "{chunks:?}");
        let (trailing, usage) = translator.finish().unwrap();
        assert!(trailing.is_empty());
        assert_eq!(usage.prompt_tokens, Some(32), "input + cache read");
        assert_eq!(usage.cached_tokens, Some(7));
        assert_eq!(
            usage.completion_tokens,
            Some(15),
            "message_delta supersedes the message_start placeholder"
        );
    }

    #[test]
    fn streaming_translation_handles_refusal_bare_data_and_errors() {
        let mut translator = AnthropicStreamTranslator::new(1, "id".into(), "m".into(), 0);
        // Data-only frames (no event: line) are accepted; the SSE
        // default `event: message` too.
        let chunks = frames(&mut translator, &[
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\"},\"usage\":{\"output_tokens\":2}}\n\n",
        ]);
        assert_eq!(chunks[0]["choices"][0]["index"], 1);
        assert_eq!(
            chunks[0]["choices"][0]["delta"]["role"], "assistant",
            "role is added when message_start never came"
        );
        assert_eq!(chunks[1]["choices"][0]["finish_reason"], "content_filter");
        assert!(translator
            .frame("event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"overloaded\"}}\n\n")
            .unwrap_err()
            .contains("overloaded"));
        assert!(translator.frame("event: content_block_delta\ndata: {\"type\":\"error\",\"error\":{\"message\":\"smuggled\"}}\n\n").is_err());
        assert!(translator.frame("data: {\"type\":\"content_block_delta\",\"index\":9,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\"}}\n\n").is_err(), "argument deltas for an unknown block are refused");
        assert!(translator.frame("data: {not json\n\n").is_err());
        assert!(translator.frame(": keepalive\n\n").unwrap().is_empty());
        assert!(translator.frame("data: [DONE]\n\n").unwrap().is_empty());
        assert!(translator
            .frame("event: future_event\ndata: {\"type\":\"future_event\"}\n\n")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn whole_message_in_a_stream_becomes_chunks() {
        let mut translator = AnthropicStreamTranslator::new(0, "id".into(), "m".into(), 0);
        let chunks = translator
            .frame(r#"{"type":"message","model":"claude","content":[{"type":"text","text":"Hi"},{"type":"tool_use","id":"t","name":"f","input":{"a":1}}],"stop_reason":"tool_use","usage":{"input_tokens":3,"output_tokens":4}}"#)
            .unwrap();
        assert_eq!(chunks[0]["choices"][0]["delta"]["content"], "Hi");
        assert_eq!(
            chunks[1]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "{\"a\":1}"
        );
        assert_eq!(chunks[2]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(translator.finish().unwrap().1.completion_tokens, Some(4));
    }

    #[test]
    fn requests_the_provider_cannot_honour_are_refused() {
        let base = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
        for (field, value) in [
            ("logprobs", json!(true)),
            ("top_logprobs", json!(3)),
            ("response_format", json!({"type": "grammar"})),
        ] {
            let mut payload = base.clone();
            payload[field] = value;
            assert!(build_request(&payload, 4096).is_err(), "{field} must be refused");
        }
        let mut payload = base.clone();
        payload["logprobs"] = json!(false);
        payload["response_format"] = json!({"type": "text"});
        assert!(
            build_request(&payload, 4096).is_ok(),
            "logprobs:false and a text format are harmless"
        );
    }

    #[test]
    fn json_output_modes_are_refused_because_anthropic_has_none() {
        for kind in ["json_object", "json_schema"] {
            let payload = json!({
                "model": "m",
                "messages": [{"role": "user", "content": "hi"}],
                "response_format": {"type": kind},
            });
            let error = build_request(&payload, 4096).unwrap_err();
            assert!(error.contains(kind), "{error}");
        }
    }
}
