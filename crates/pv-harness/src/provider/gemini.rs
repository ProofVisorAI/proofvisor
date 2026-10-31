//! Google Gemini `generateContent` translation, both directions.
//!
//! Request (OpenAI chat completion →
//! `POST /v1beta/models/{model}:generateContent`, or
//! `:streamGenerateContent?alt=sse` when streaming):
//!
//! * `system`/`developer` messages → `systemInstruction.parts`;
//! * `user` content → `contents[]` with role `user`: text parts and
//!   `inlineData` for base64 `data:` image URLs (Gemini has no remote
//!   image URL input, so other URLs are refused);
//! * `assistant` → role `model`: text parts and `functionCall` parts
//!   (`arguments` parsed into `args`);
//! * consecutive `tool` messages → one role-`user` content of
//!   `functionResponse` parts; the function `name` is recovered from
//!   the assistant `tool_calls` entry with the same id, and the tool
//!   output becomes `response` (a JSON object as is, anything else as
//!   `{"result": <text>}`);
//! * `tools` → `tools[0].functionDeclarations` with the JSON schema in
//!   `parametersJsonSchema`; `tool_choice` →
//!   `toolConfig.functionCallingConfig` (`auto`→AUTO, `none`→NONE,
//!   `required`→ANY, named → ANY + `allowedFunctionNames`);
//! * `generationConfig`: `temperature`, `topP`, `maxOutputTokens`
//!   (`max_completion_tokens` or `max_tokens`), `stopSequences`,
//!   `candidateCount` (= `n` when above 1), `seed`,
//!   `presencePenalty`, `frequencyPenalty`, and `response_format` →
//!   `responseMimeType` (+ `responseJsonSchema`).
//!
//! Dropped: `user`, `logit_bias`, `logprobs`, `top_logprobs`, `store`,
//! `service_tier`, per-message `name`, tool-call ids (Gemini
//! correlates function responses by name).
//!
//! Response: `candidates[]` → `choices[]` keyed by candidate `index`;
//! text parts → `content` (parts flagged `thought` →
//! `reasoning_content`); `functionCall` parts → `tool_calls`;
//! `finishReason` → `finish_reason` (STOP → `stop`, or `tool_calls`
//! when the candidate carried function calls; MAX_TOKENS → `length`;
//! SAFETY/RECITATION/BLOCKLIST/PROHIBITED_CONTENT/SPII/IMAGE_SAFETY →
//! `content_filter`; MALFORMED_FUNCTION_CALL/UNEXPECTED_TOOL_CALL →
//! `tool_calls`); `usageMetadata.promptTokenCount` → `prompt_tokens`,
//! `candidatesTokenCount` + `thoughtsTokenCount` → `completion_tokens`
//! (thoughts also as `completion_tokens_details.reasoning_tokens`),
//! `cachedContentTokenCount` → `prompt_tokens_details.cached_tokens`.
//! A `promptFeedback.blockReason` with no candidates becomes one
//! empty choice finishing with `content_filter`.

use super::{
    arguments_object, base64_data_url, chunk, content_text, fresh_tool_call_id, requested_max_tokens, set,
    split_sse_frame, stop_sequences, usage_u64, StreamTranslator, UsageTotals,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

/// The request path for `model`. The model id must be a plain path
/// segment; a `models/` prefix is tolerated and stripped.
pub(crate) fn request_path(model: &str, stream: bool) -> Result<String, String> {
    let model = model.strip_prefix("models/").unwrap_or(model);
    if model.is_empty()
        || model.len() > 200
        || !model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "model {model:?} is not a valid Gemini model id (letters, digits, '-', '_' and '.' only)"
        ));
    }
    Ok(if stream {
        format!("/v1beta/models/{model}:streamGenerateContent?alt=sse")
    } else {
        format!("/v1beta/models/{model}:generateContent")
    })
}

/// Build the `generateContent` body for one OpenAI chat request.
pub(crate) fn build_request(payload: &Value) -> Result<Value, String> {
    let messages = payload
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "messages must be an array".to_owned())?;
    let mut system_parts: Vec<Value> = Vec::new();
    let mut contents: Vec<Value> = Vec::new();
    let mut pending_responses: Vec<Value> = Vec::new();
    let mut tool_names: HashMap<String, String> = HashMap::new();
    let flush_responses = |pending: &mut Vec<Value>, contents: &mut Vec<Value>| {
        if !pending.is_empty() {
            contents.push(json!({"role": "user", "parts": std::mem::take(pending)}));
        }
    };
    for message in messages {
        let role = message.get("role").and_then(Value::as_str).unwrap_or_default();
        match role {
            "system" | "developer" => {
                flush_responses(&mut pending_responses, &mut contents);
                if let Some(text) = content_text(message.get("content")) {
                    if !text.is_empty() {
                        system_parts.push(json!({"text": text}));
                    }
                }
            }
            "user" => {
                flush_responses(&mut pending_responses, &mut contents);
                let parts = user_parts(message.get("content"))?;
                if !parts.is_empty() {
                    contents.push(json!({"role": "user", "parts": parts}));
                }
            }
            "assistant" => {
                flush_responses(&mut pending_responses, &mut contents);
                let mut parts: Vec<Value> = Vec::new();
                if let Some(text) = content_text(message.get("content")) {
                    if !text.is_empty() {
                        parts.push(json!({"text": text}));
                    }
                }
                if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        let name = call
                            .pointer("/function/name")
                            .and_then(Value::as_str)
                            .ok_or_else(|| "assistant tool_calls entries need function.name".to_owned())?;
                        if let Some(id) = call.get("id").and_then(Value::as_str) {
                            tool_names.insert(id.to_owned(), name.to_owned());
                        }
                        let args = arguments_object(call.pointer("/function/arguments"))?;
                        parts.push(json!({"functionCall": {"name": name, "args": args}}));
                    }
                }
                if !parts.is_empty() {
                    contents.push(json!({"role": "model", "parts": parts}));
                }
            }
            "tool" => {
                let id = message
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "tool messages need a tool_call_id".to_owned())?;
                let name = tool_names.get(id).cloned().unwrap_or_else(|| id.to_owned());
                let text = content_text(message.get("content")).unwrap_or_default();
                let response = match serde_json::from_str::<Value>(&text) {
                    Ok(value @ Value::Object(_)) => value,
                    _ => json!({"result": text}),
                };
                pending_responses.push(json!({"functionResponse": {"name": name, "response": response}}));
            }
            other => return Err(format!("unsupported message role {other:?}")),
        }
    }
    flush_responses(&mut pending_responses, &mut contents);

    let mut body = json!({"contents": contents});
    if !system_parts.is_empty() {
        set(&mut body, "systemInstruction", json!({"parts": system_parts}));
    }
    let mut generation = json!({});
    for (openai, gemini) in [
        ("temperature", "temperature"),
        ("top_p", "topP"),
        ("seed", "seed"),
        ("presence_penalty", "presencePenalty"),
        ("frequency_penalty", "frequencyPenalty"),
    ] {
        if let Some(value) = payload.get(openai).filter(|value| value.is_number()) {
            set(&mut generation, gemini, value.clone());
        }
    }
    if let Some(max) = requested_max_tokens(payload) {
        set(&mut generation, "maxOutputTokens", json!(max));
    }
    let stops = stop_sequences(payload);
    if !stops.is_empty() {
        set(&mut generation, "stopSequences", Value::Array(stops));
    }
    let choices = super::choice_count(payload)?;
    if choices > 1 {
        set(&mut generation, "candidateCount", json!(choices));
    }
    match payload.pointer("/response_format/type").and_then(Value::as_str) {
        Some("json_object") => set(&mut generation, "responseMimeType", json!("application/json")),
        Some("json_schema") => {
            set(&mut generation, "responseMimeType", json!("application/json"));
            if let Some(schema) = payload.pointer("/response_format/json_schema/schema") {
                set(&mut generation, "responseJsonSchema", schema.clone());
            }
        }
        _ => {}
    }
    if generation.as_object().is_some_and(|object| !object.is_empty()) {
        set(&mut body, "generationConfig", generation);
    }
    let declarations = function_declarations(payload.get("tools"))?;
    if !declarations.is_empty() {
        set(&mut body, "tools", json!([{"functionDeclarations": declarations}]));
        if let Some(config) = function_calling_config(payload.get("tool_choice"))? {
            set(&mut body, "toolConfig", json!({"functionCallingConfig": config}));
        }
    }
    Ok(body)
}

fn user_parts(content: Option<&Value>) -> Result<Vec<Value>, String> {
    let mut parts = Vec::new();
    match content {
        Some(Value::String(text)) => {
            if !text.is_empty() {
                parts.push(json!({"text": text}));
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                match item.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "text" => {
                        if let Some(text) = item.get("text").and_then(Value::as_str) {
                            if !text.is_empty() {
                                parts.push(json!({"text": text}));
                            }
                        }
                    }
                    "image_url" => {
                        let url = item
                            .pointer("/image_url/url")
                            .or_else(|| item.get("image_url"))
                            .and_then(Value::as_str)
                            .ok_or_else(|| "image_url parts need image_url.url".to_owned())?;
                        let (mime_type, data) = base64_data_url(url).ok_or_else(|| {
                            "Gemini accepts images only as base64 data URLs (data:<mime>;base64,...)".to_owned()
                        })?;
                        parts.push(json!({"inlineData": {"mimeType": mime_type, "data": data}}));
                    }
                    other => return Err(format!("unsupported content part type {other:?}")),
                }
            }
        }
        None | Some(Value::Null) => {}
        Some(_) => return Err("message content must be a string or an array of parts".to_owned()),
    }
    Ok(parts)
}

fn function_declarations(tools: Option<&Value>) -> Result<Vec<Value>, String> {
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
        let mut declaration = json!({"name": name});
        if let Some(description) = function.get("description").and_then(Value::as_str) {
            set(&mut declaration, "description", Value::String(description.to_owned()));
        }
        if let Some(parameters) = function.get("parameters").filter(|parameters| parameters.is_object()) {
            set(&mut declaration, "parametersJsonSchema", parameters.clone());
        }
        out.push(declaration);
    }
    Ok(out)
}

fn function_calling_config(choice: Option<&Value>) -> Result<Option<Value>, String> {
    Ok(match choice {
        None | Some(Value::Null) => None,
        Some(Value::String(mode)) => match mode.as_str() {
            "auto" => Some(json!({"mode": "AUTO"})),
            "none" => Some(json!({"mode": "NONE"})),
            "required" => Some(json!({"mode": "ANY"})),
            other => return Err(format!("unsupported tool_choice {other:?}")),
        },
        Some(object) => {
            let name = object
                .pointer("/function/name")
                .and_then(Value::as_str)
                .ok_or_else(|| "tool_choice objects need function.name".to_owned())?;
            Some(json!({"mode": "ANY", "allowedFunctionNames": [name]}))
        }
    })
}

/// Gemini `finishReason` → OpenAI `finish_reason`.
pub(crate) fn map_finish_reason(native: &str, has_tool_calls: bool) -> String {
    match native {
        "STOP" => {
            if has_tool_calls {
                "tool_calls".to_owned()
            } else {
                "stop".to_owned()
            }
        }
        "MAX_TOKENS" => "length".to_owned(),
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" | "IMAGE_SAFETY" => {
            "content_filter".to_owned()
        }
        "MALFORMED_FUNCTION_CALL" | "UNEXPECTED_TOOL_CALL" => "tool_calls".to_owned(),
        other => other.to_ascii_lowercase(),
    }
}

/// Gemini `usageMetadata` → totals. Thinking tokens are billed output
/// beside the visible candidate text, so both count as completion.
pub(crate) fn usage_totals(usage: Option<&Value>) -> Result<UsageTotals, String> {
    let Some(usage) = usage.filter(|usage| !usage.is_null()) else {
        return Ok(UsageTotals::default());
    };
    let candidates = usage_u64(usage.get("candidatesTokenCount"), "candidatesTokenCount")?;
    let thoughts = usage_u64(usage.get("thoughtsTokenCount"), "thoughtsTokenCount")?;
    let completion_tokens = match (candidates, thoughts) {
        (None, None) => None,
        (a, b) => {
            let sum = a.unwrap_or(0).saturating_add(b.unwrap_or(0));
            if sum > pv_core::error::JCS_SAFE_MAX {
                return Err("upstream completion token sum exceeds JCS-safe bounds".to_owned());
            }
            Some(sum)
        }
    };
    Ok(UsageTotals {
        prompt_tokens: usage_u64(usage.get("promptTokenCount"), "promptTokenCount")?,
        completion_tokens,
        cached_tokens: usage_u64(usage.get("cachedContentTokenCount"), "cachedContentTokenCount")?,
        reasoning_tokens: thoughts,
    })
}

/// Text, reasoning and tool calls gathered from one candidate's parts.
struct Gathered {
    text: String,
    reasoning: String,
    tool_calls: Vec<Value>,
}

fn gather_parts(candidate: &Value) -> Result<Gathered, String> {
    let mut gathered = Gathered {
        text: String::new(),
        reasoning: String::new(),
        tool_calls: Vec::new(),
    };
    let parts = match candidate.pointer("/content/parts") {
        Some(Value::Array(parts)) => parts.as_slice(),
        Some(Value::Null) | None => &[],
        Some(_) => return Err("upstream content parts is not an array".to_owned()),
    };
    for part in parts {
        if let Some(text) = part.get("text").and_then(Value::as_str) {
            if part.get("thought").and_then(Value::as_bool).unwrap_or(false) {
                gathered.reasoning.push_str(text);
            } else {
                gathered.text.push_str(text);
            }
        }
        if let Some(call) = part.get("functionCall").filter(|call| !call.is_null()) {
            let args = call.get("args").filter(|args| !args.is_null()).cloned().unwrap_or_else(|| json!({}));
            let arguments =
                serde_json::to_string(&args).map_err(|error| format!("function args are not serializable: {error}"))?;
            gathered.tool_calls.push(json!({
                "id": call.get("id").and_then(Value::as_str).map_or_else(fresh_tool_call_id, str::to_owned),
                "type": "function",
                "function": {
                    "name": call.get("name").and_then(Value::as_str).unwrap_or("unknown"),
                    "arguments": arguments,
                },
            }));
        }
        // inlineData, executableCode, codeExecutionResult: nothing the
        // OpenAI chat shape can carry.
    }
    Ok(gathered)
}

fn candidate_index(candidate: &Value, position: usize) -> u64 {
    candidate
        .get("index")
        .and_then(Value::as_u64)
        .or_else(|| u64::try_from(position).ok())
        .unwrap_or(u64::MAX)
}

/// Translate one buffered `generateContent` response into an OpenAI
/// `chat.completion`.
pub(crate) fn translate_response(body: &Value, id: &str, created: u64, fallback_model: &str) -> Result<Value, String> {
    if let Some(error) = body.get("error").filter(|error| !error.is_null()) {
        return Err(format!(
            "upstream error: {}",
            error.get("message").and_then(Value::as_str).unwrap_or("(no message)")
        ));
    }
    let candidates = match body.get("candidates") {
        Some(Value::Array(candidates)) => candidates.as_slice(),
        Some(Value::Null) | None => &[],
        Some(_) => return Err("upstream candidates is not an array".to_owned()),
    };
    let mut choices: BTreeMap<u64, Value> = BTreeMap::new();
    for (position, candidate) in candidates.iter().enumerate() {
        let index = candidate_index(candidate, position);
        let gathered = gather_parts(candidate)?;
        let finish_reason = candidate
            .get("finishReason")
            .and_then(Value::as_str)
            .filter(|reason| !reason.is_empty())
            .map(|reason| map_finish_reason(reason, !gathered.tool_calls.is_empty()));
        let mut message = json!({"role": "assistant"});
        if gathered.text.is_empty() && !gathered.tool_calls.is_empty() {
            set(&mut message, "content", Value::Null);
        } else {
            set(&mut message, "content", Value::String(gathered.text));
        }
        if !gathered.reasoning.is_empty() {
            set(&mut message, "reasoning_content", Value::String(gathered.reasoning));
        }
        if !gathered.tool_calls.is_empty() {
            set(&mut message, "tool_calls", Value::Array(gathered.tool_calls));
        }
        choices.insert(
            index,
            json!({"index": index, "message": message, "logprobs": Value::Null, "finish_reason": finish_reason}),
        );
    }
    if choices.is_empty() {
        if body
            .pointer("/promptFeedback/blockReason")
            .and_then(Value::as_str)
            .is_some_and(|reason| !reason.is_empty())
        {
            choices.insert(
                0,
                json!({"index": 0, "message": {"role": "assistant", "content": Value::Null}, "logprobs": Value::Null, "finish_reason": "content_filter"}),
            );
        } else {
            return Err("upstream response carried no candidates".to_owned());
        }
    }
    Ok(json!({
        "id": id,
        "object": "chat.completion",
        "created": created,
        "model": body.get("modelVersion").and_then(Value::as_str).unwrap_or(fallback_model),
        "choices": choices.into_values().collect::<Vec<_>>(),
        "usage": usage_totals(body.get("usageMetadata"))?.to_openai(),
    }))
}

#[derive(Default)]
struct CandidateState {
    started: bool,
    next_tool_index: u64,
    saw_tool_call: bool,
    finished: bool,
}

/// Stateful translator for one Gemini `alt=sse` stream. Every frame is
/// a whole `GenerateContentResponse`; each candidate maps to the
/// OpenAI choice with the same index.
pub(crate) struct GeminiStreamTranslator {
    id: String,
    model: String,
    created: u64,
    usage: UsageTotals,
    candidates: BTreeMap<u64, CandidateState>,
    blocked: bool,
}

impl GeminiStreamTranslator {
    pub(crate) fn new(id: String, fallback_model: String, created: u64) -> Self {
        Self {
            id,
            model: fallback_model,
            created,
            usage: UsageTotals::default(),
            candidates: BTreeMap::new(),
            blocked: false,
        }
    }

    fn emit(&mut self, index: u64, mut delta: Value, finish_reason: Option<&str>) -> Value {
        let state = self.candidates.entry(index).or_default();
        if !state.started {
            state.started = true;
            set(&mut delta, "role", Value::String("assistant".to_owned()));
            if delta.get("content").is_none() {
                set(&mut delta, "content", Value::String(String::new()));
            }
        }
        chunk(&self.id, &self.model, self.created, index, delta, finish_reason)
    }
}

impl StreamTranslator for GeminiStreamTranslator {
    fn frame(&mut self, raw: &str) -> Result<Vec<Value>, String> {
        let frame = split_sse_frame(raw);
        let Some(data) = frame.data else {
            return Ok(Vec::new());
        };
        if data.trim() == "[DONE]" {
            return Ok(Vec::new());
        }
        if frame.is_sse && !frame.event.is_empty() && frame.event != "message" {
            return Err(format!(
                "upstream SSE frame carries event type {:?}; Gemini streams use unnamed data frames",
                frame.event
            ));
        }
        let value: Value =
            serde_json::from_str(&data).map_err(|error| format!("invalid upstream JSON frame: {error}"))?;
        if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
            let message = error.get("message").and_then(Value::as_str).unwrap_or("(no message)");
            let status = error.get("status").and_then(Value::as_str).unwrap_or("");
            return Err(if status.is_empty() {
                format!("upstream stream error: {message}")
            } else {
                format!("upstream stream error [{status}]: {message}")
            });
        }
        if let Some(model) = value.get("modelVersion").and_then(Value::as_str) {
            self.model = model.to_owned();
        }
        // usageMetadata is cumulative; the latest frame wins.
        let usage = usage_totals(value.get("usageMetadata"))?;
        if usage.is_known() {
            self.usage = usage;
        }
        let candidates = match value.get("candidates") {
            Some(Value::Array(candidates)) => candidates.as_slice(),
            Some(Value::Null) | None => &[],
            Some(_) => return Err("upstream candidates is not an array".to_owned()),
        };
        let mut chunks = Vec::new();
        for (position, candidate) in candidates.iter().enumerate() {
            let index = candidate_index(candidate, position);
            let gathered = gather_parts(candidate)?;
            if !gathered.text.is_empty() {
                chunks.push(self.emit(index, json!({"content": gathered.text}), None));
            }
            if !gathered.reasoning.is_empty() {
                chunks.push(self.emit(index, json!({"reasoning_content": gathered.reasoning}), None));
            }
            for mut call in gathered.tool_calls {
                let slot = {
                    let state = self.candidates.entry(index).or_default();
                    let slot = state.next_tool_index;
                    state.next_tool_index = state.next_tool_index.saturating_add(1);
                    state.saw_tool_call = true;
                    slot
                };
                set(&mut call, "index", json!(slot));
                chunks.push(self.emit(index, json!({"tool_calls": [call]}), None));
            }
            if let Some(reason) = candidate
                .get("finishReason")
                .and_then(Value::as_str)
                .filter(|reason| !reason.is_empty())
            {
                let (already, saw_tool_call) = {
                    let state = self.candidates.entry(index).or_default();
                    let already = state.finished;
                    state.finished = true;
                    (already, state.saw_tool_call)
                };
                if !already {
                    let mapped = map_finish_reason(reason, saw_tool_call);
                    chunks.push(self.emit(index, json!({}), Some(&mapped)));
                }
            }
        }
        if candidates.is_empty()
            && !self.blocked
            && value
                .pointer("/promptFeedback/blockReason")
                .and_then(Value::as_str)
                .is_some_and(|reason| !reason.is_empty())
        {
            self.blocked = true;
            chunks.push(self.emit(0, json!({}), Some("content_filter")));
        }
        Ok(chunks)
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

    #[test]
    fn request_path_validates_the_model_segment() {
        assert_eq!(
            request_path("gemini-2.0-flash", false).unwrap(),
            "/v1beta/models/gemini-2.0-flash:generateContent"
        );
        assert_eq!(
            request_path("models/gemini-2.5-pro", true).unwrap(),
            "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"
        );
        for bad in ["", "a/b", "x?y", "m:generateContent", "sp ace"] {
            assert!(request_path(bad, false).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn request_maps_system_contents_tools_and_generation_config() {
        let payload = json!({
            "model": "gemini-2.0-flash",
            "messages": [
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": [
                    {"type": "text", "text": "Describe"},
                    {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,/9j/"}},
                ]},
                {"role": "assistant", "content": "Looking.", "tool_calls": [
                    {"id": "call_a", "type": "function", "function": {"name": "find", "arguments": "{\"q\":\"cat\"}"}},
                ]},
                {"role": "tool", "tool_call_id": "call_a", "content": "{\"hits\": 3}"},
                {"role": "tool", "tool_call_id": "call_missing", "content": "plain text"},
                {"role": "user", "content": "ok"},
            ],
            "temperature": 0.5,
            "top_p": 0.8,
            "max_tokens": 64,
            "stop": "END",
            "n": 2,
            "seed": 3,
            "presence_penalty": 0.1,
            "frequency_penalty": 0.2,
            "response_format": {"type": "json_object"},
            "tools": [{"type": "function", "function": {"name": "find", "description": "Find things", "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}}}],
            "tool_choice": {"type": "function", "function": {"name": "find"}},
            "user": "u1",
        });
        let body = build_request(&payload).unwrap();
        assert_eq!(body["systemInstruction"]["parts"], json!([{"text": "Be brief."}]));
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 4, "{contents:?}");
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[0]["parts"][0], json!({"text": "Describe"}));
        assert_eq!(contents[0]["parts"][1], json!({"inlineData": {"mimeType": "image/jpeg", "data": "/9j/"}}));
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(contents[1]["parts"][0], json!({"text": "Looking."}));
        assert_eq!(contents[1]["parts"][1], json!({"functionCall": {"name": "find", "args": {"q": "cat"}}}));
        assert_eq!(contents[2]["role"], "user");
        assert_eq!(contents[2]["parts"][0], json!({"functionResponse": {"name": "find", "response": {"hits": 3}}}));
        assert_eq!(
            contents[2]["parts"][1],
            json!({"functionResponse": {"name": "call_missing", "response": {"result": "plain text"}}}),
            "unknown ids fall back to the id as name and wrap text in an object"
        );
        assert_eq!(contents[3]["parts"][0]["text"], "ok");
        assert_eq!(body["generationConfig"], json!({
            "temperature": 0.5,
            "topP": 0.8,
            "seed": 3,
            "presencePenalty": 0.1,
            "frequencyPenalty": 0.2,
            "maxOutputTokens": 64,
            "stopSequences": ["END"],
            "candidateCount": 2,
            "responseMimeType": "application/json",
        }));
        assert_eq!(body["tools"][0]["functionDeclarations"][0]["name"], "find");
        assert_eq!(body["tools"][0]["functionDeclarations"][0]["description"], "Find things");
        assert_eq!(body["tools"][0]["functionDeclarations"][0]["parametersJsonSchema"]["properties"]["q"]["type"], "string");
        assert_eq!(body["toolConfig"]["functionCallingConfig"], json!({"mode": "ANY", "allowedFunctionNames": ["find"]}));
        assert!(body.get("user").is_none() && body.get("n").is_none());

        let base = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}], "tools": [{"type": "function", "function": {"name": "f"}}]});
        for (choice, mode) in [("auto", "AUTO"), ("none", "NONE"), ("required", "ANY")] {
            let mut payload = base.clone();
            set(&mut payload, "tool_choice", json!(choice));
            assert_eq!(build_request(&payload).unwrap()["toolConfig"]["functionCallingConfig"]["mode"], mode);
        }
        let plain = build_request(&json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})).unwrap();
        assert!(plain.get("generationConfig").is_none() && plain.get("tools").is_none());
        let remote_image = json!({"model": "m", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://x/y.png"}}]}]});
        assert!(build_request(&remote_image).is_err(), "Gemini has no remote image URL input");
        assert!(build_request(&json!({"model": "m", "messages": [{"role": "tool", "content": "x"}]})).is_err());
        assert!(build_request(&json!({"model": "m", "messages": [], "n": 9})).is_err());
    }

    #[test]
    fn non_streaming_response_maps_candidates_parts_finish_reasons_and_usage() {
        let body = json!({
            "candidates": [
                {"index": 1, "content": {"role": "model", "parts": [{"text": "second"}]}, "finishReason": "MAX_TOKENS"},
                {"index": 0, "content": {"role": "model", "parts": [
                    {"text": "think", "thought": true},
                    {"text": "first"},
                    {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}},
                    {"functionCall": {"name": "noop"}},
                ]}, "finishReason": "STOP"},
            ],
            "usageMetadata": {"promptTokenCount": 25, "candidatesTokenCount": 10, "thoughtsTokenCount": 100, "cachedContentTokenCount": 5},
            "modelVersion": "gemini-2.0-flash-001",
        });
        let completion = translate_response(&body, "chatcmpl-g", 9, "gemini-2.0-flash").unwrap();
        assert_eq!(completion["object"], "chat.completion");
        assert_eq!(completion["model"], "gemini-2.0-flash-001");
        let choices = completion["choices"].as_array().unwrap();
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0]["index"], 0, "choices are ordered by candidate index");
        assert_eq!(choices[0]["message"]["content"], "first");
        assert_eq!(choices[0]["message"]["reasoning_content"], "think");
        assert_eq!(choices[0]["message"]["tool_calls"][0]["function"], json!({"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}));
        assert_eq!(choices[0]["message"]["tool_calls"][1]["function"]["arguments"], "{}");
        assert!(choices[0]["message"]["tool_calls"][0]["id"].as_str().unwrap().starts_with("call_"));
        assert_eq!(choices[0]["finish_reason"], "tool_calls", "STOP with function calls finishes as tool_calls");
        assert_eq!(choices[1]["index"], 1);
        assert_eq!(choices[1]["message"]["content"], "second");
        assert_eq!(choices[1]["finish_reason"], "length");
        assert_eq!(completion["usage"], json!({
            "prompt_tokens": 25,
            "completion_tokens": 110,
            "total_tokens": 135,
            "prompt_tokens_details": {"cached_tokens": 5},
            "completion_tokens_details": {"reasoning_tokens": 100},
        }));

        let blocked = translate_response(&json!({"promptFeedback": {"blockReason": "SAFETY"}}), "id", 0, "m").unwrap();
        assert_eq!(blocked["choices"][0]["finish_reason"], "content_filter");
        assert!(blocked["choices"][0]["message"]["content"].is_null());
        let empty = translate_response(&json!({"candidates": [{"index": 0, "content": {"parts": []}, "finishReason": "STOP"}]}), "id", 0, "m").unwrap();
        assert_eq!(empty["choices"][0]["message"]["content"], "");
        assert_eq!(empty["choices"][0]["finish_reason"], "stop");
        assert!(translate_response(&json!({}), "id", 0, "m").is_err(), "no candidates and no block is a failure");
        assert!(translate_response(&json!({"error": {"message": "bad"}}), "id", 0, "m").is_err());
        for (native, expected) in [
            ("STOP", "stop"),
            ("MAX_TOKENS", "length"),
            ("SAFETY", "content_filter"),
            ("RECITATION", "content_filter"),
            ("BLOCKLIST", "content_filter"),
            ("PROHIBITED_CONTENT", "content_filter"),
            ("SPII", "content_filter"),
            ("MALFORMED_FUNCTION_CALL", "tool_calls"),
            ("UNEXPECTED_TOOL_CALL", "tool_calls"),
            ("LANGUAGE", "language"),
        ] {
            assert_eq!(map_finish_reason(native, false), expected, "{native}");
        }
    }

    #[test]
    fn streaming_translation_emits_per_candidate_chunks_and_cumulative_usage() {
        let mut translator = GeminiStreamTranslator::new("chatcmpl-g".into(), "gemini-2.0-flash".into(), 3);
        let first = translator
            .frame("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}],\"role\":\"model\"},\"index\":0},{\"content\":{\"parts\":[{\"text\":\"Salut\"}]},\"index\":1}],\"usageMetadata\":{\"promptTokenCount\":25,\"candidatesTokenCount\":2},\"modelVersion\":\"gemini-2.0-flash-001\"}\n\n")
            .unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0]["choices"][0]["index"], 0);
        assert_eq!(first[0]["choices"][0]["delta"], json!({"role": "assistant", "content": "Hello"}));
        assert_eq!(first[1]["choices"][0]["index"], 1);
        assert_eq!(first[1]["choices"][0]["delta"]["content"], "Salut");
        assert_eq!(first[0]["model"], "gemini-2.0-flash-001");
        let second = translator
            .frame("data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Paris\"}}}]},\"index\":0},{\"content\":{\"parts\":[{\"text\":\"!\"}]},\"finishReason\":\"STOP\",\"index\":1}],\"usageMetadata\":{\"promptTokenCount\":25,\"candidatesTokenCount\":12,\"thoughtsTokenCount\":3}}\n\n")
            .unwrap();
        assert_eq!(second[0]["choices"][0]["delta"]["tool_calls"][0]["index"], 0);
        assert_eq!(second[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"], "{\"city\":\"Paris\"}");
        assert!(second[0]["choices"][0]["delta"].get("role").is_none());
        assert_eq!(second[1]["choices"][0]["delta"]["content"], "!");
        assert_eq!(second[2]["choices"][0]["index"], 1);
        assert_eq!(second[2]["choices"][0]["finish_reason"], "stop");
        let third = translator
            .frame("data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"get_time\"}}]},\"finishReason\":\"STOP\",\"index\":0}]}\n\n")
            .unwrap();
        assert_eq!(third[0]["choices"][0]["delta"]["tool_calls"][0]["index"], 1, "second call gets the next slot");
        assert_eq!(third[1]["choices"][0]["finish_reason"], "tool_calls", "STOP after function calls finishes as tool_calls");
        let (_, usage) = translator.finish().unwrap();
        assert_eq!(usage.prompt_tokens, Some(25));
        assert_eq!(usage.completion_tokens, Some(15), "candidates + thoughts from the latest frame");
        assert_eq!(usage.reasoning_tokens, Some(3));
    }

    #[test]
    fn streaming_translation_handles_blocks_errors_and_keepalives() {
        let mut translator = GeminiStreamTranslator::new("id".into(), "m".into(), 0);
        let blocked = translator
            .frame("data: {\"promptFeedback\":{\"blockReason\":\"SAFETY\"}}\n\n")
            .unwrap();
        assert_eq!(blocked[0]["choices"][0]["finish_reason"], "content_filter");
        assert!(translator.frame("data: {\"promptFeedback\":{\"blockReason\":\"SAFETY\"}}\n\n").unwrap().is_empty(), "the block is reported once");
        assert!(translator.frame(": keepalive\n\n").unwrap().is_empty());
        assert!(translator.frame("data: [DONE]\n\n").unwrap().is_empty());
        let error = translator
            .frame("data: {\"error\":{\"code\":429,\"message\":\"resource exhausted\",\"status\":\"RESOURCE_EXHAUSTED\"}}\n\n")
            .unwrap_err();
        assert!(error.contains("RESOURCE_EXHAUSTED") && error.contains("resource exhausted"), "{error}");
        assert!(translator.frame("event: custom\ndata: {\"candidates\":[]}\n\n").is_err(), "named frames are not Gemini");
        assert!(translator.frame("data: {not json\n\n").is_err());
        assert!(translator.frame("data: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":\"x\"}}]}\n\n").is_err());
    }
}
