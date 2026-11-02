# OpenAI Compatibility

ProofVisor is an OpenAI-compatible reverse proxy. Any client that
speaks the `POST /v1/chat/completions` protocol (OpenAI Python SDK,
LangChain, LlamaIndex, curl) can point at the harness by changing its
base URL:

```python
client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],  # your NHI bearer, if require_identity is true
    base_url="http://localhost:8484/v1",
)
```

With OpenAI SDK 1.x you can set the environment variable
`OPENAI_BASE_URL=http://localhost:8484/v1` instead of passing `base_url`.

This document explains exactly what "compatible" means — the
supported surface, the intentional differences, and the failure modes
so you can reason about incidents without reading the full route
handler.

## Upstream provider dialects

The client-facing surface is always the OpenAI protocol. The
*upstream* wire dialect is selected by the `provider` config key
(round-51 §4.2, S3):

| `provider` | Upstream dialect | Also fits |
| --- | --- | --- |
| `"openai"` (default) | OpenAI Chat Completions | vLLM, LiteLLM, Groq, Together, DeepSeek, OpenRouter, Ollama, LM Studio, llama.cpp, xAI, Mistral, Azure OpenAI |
| `"anthropic"` | Anthropic Messages API (`POST /v1/messages`), translated both ways | — |
| `"gemini"` | Google Gemini `generateContent` / `streamGenerateContent`, translated both ways | — |

With `provider = "openai"` the request body is forwarded unchanged to
`upstream_url` + `upstream_chat_path`. With `anthropic` or `gemini` the
harness translates the OpenAI request into the provider's native API,
sends it there, and translates the answer back, so an OpenAI client
receives an ordinary `chat.completion` object or a stream of
`chat.completion.chunk` frames ending with `data: [DONE]`. The audit
chain (receipts, ATIF trajectories, stop-reason taxonomy, provider-true
token totals) is built from the translated OpenAI frames and therefore
has the same shape for every provider. Unsupported `provider` values are
refused at pre-flight by `pvctl config-validate` and at boot by the
daemon. The native adapters have been tested only against local
stand-ins, not against the live Anthropic or Gemini APIs.

### What the native adapters translate

| OpenAI request field | Anthropic | Gemini |
| --- | --- | --- |
| `system` / `developer` messages | joined into `system` | `systemInstruction.parts` |
| `user` / `assistant` messages | `messages` with content blocks | `contents` with roles `user` / `model` |
| image parts (`image_url`) | `image` block (base64 data URL or http(s) URL) | `inlineData` (base64 data URL) |
| assistant `tool_calls` | `tool_use` blocks | `functionCall` parts |
| `tool` messages | `tool_result` blocks, grouped into one user turn | `functionResponse` parts |
| `tools` (functions) | `tools` with `input_schema` | `tools[0].functionDeclarations` |
| `tool_choice` | `auto` / `none` / `any` / named `tool`; `parallel_tool_calls: false` → `disable_parallel_tool_use` | `toolConfig.functionCallingConfig` (`AUTO`, `NONE`, `ANY`, `allowedFunctionNames`) |
| `max_tokens` / `max_completion_tokens` | `max_tokens` (mandatory; `provider_default_max_tokens`, default 4096, when absent) | `generationConfig.maxOutputTokens` |
| `temperature`, `top_p`, `stop` | `temperature`, `top_p`, `stop_sequences` | `temperature`, `topP`, `stopSequences` |
| `seed`, `presence_penalty`, `frequency_penalty` | dropped (no equivalent) | `seed`, `presencePenalty`, `frequencyPenalty` |
| `response_format` | refused unless `{"type": "text"}` (no JSON mode) | `json_object` / `json_schema` → `responseMimeType` (+ `responseJsonSchema`) |
| `logprobs`, `top_logprobs` | refused | refused |
| `user` | `metadata.user_id` | dropped |
| `n` | one upstream request per choice (see below) | `generationConfig.candidateCount` |

A refused field returns HTTP 400 before any upstream call, because
answering without it would silently give the client something other
than what it asked for.

Responses map back as follows: text becomes `message.content` (or
`delta.content`), tool use becomes `tool_calls` with JSON-encoded
`arguments`, Anthropic `thinking` blocks become `reasoning_content`, and
usage becomes `usage.prompt_tokens` / `completion_tokens` /
`total_tokens`. A non-success upstream status is returned with the same
HTTP status and an OpenAI error envelope
(`{"error": {"message", "type", "param", "code"}}`); `Retry-After` is
relayed.

### Credentials

When `upstream_auth_header` and `upstream_auth_scheme` are left at their
defaults, the native adapters send the raw key in the provider's own
header: `x-api-key` (plus `anthropic-version: 2023-06-01`) for Anthropic
and `x-goog-api-key` for Gemini. In passthrough mode the client's
`Authorization: Bearer <key>` is moved into that header without the
scheme.

### Multiple choices (`n > 1`)

`n` is accepted from 1 to 8 and must be a plain integer; `2.0` or `"2"`
is refused. Each choice is audited separately (its own text, tool calls
and finish reason), not concatenated.

* **OpenAI dialect:** `n` is forwarded; the provider returns every
  choice.
* **Gemini:** `n` becomes `candidateCount`; one request returns every
  candidate, and the prompt is billed once.
* **Anthropic:** the Messages API has no `n`, so the harness sends `n`
  identical requests concurrently and merges the answers into one
  response with choices indexed `0..n-1`. When streaming, the chunks of
  all choices are interleaved, each carrying its `index`, and each
  choice ends with exactly one finish reason. The provider bills the
  prompt once per choice, so the reported usage is the sum over all
  choices, and budgets are charged that sum. If any of the requests
  fails, the whole request fails with that status.

Cross-provider stop-reason normalization deserves calling out
because the upstream dialects disagree. OpenAI emits
`finish_reason: "tool_calls"` and Anthropic emits `stop_reason:
"tool_use"` when the model decides to invoke tools; both map to
`StopReason::ToolUse` (id 3). Gemini does not — it emits
`finishReason: STOP` and expects the client to notice the
`functionCall` part in the candidate content. The harness normalizes
this at capture time: any session whose response carried tool-call
deltas and would otherwise attest `Stop` is attested `ToolUse`
instead, so downstream analytics grouping sessions by stop_reason
are provider-agnostic. Pinned by
`gemini_tool_call_with_finish_stop_attests_tool_use`.

Two more Anthropic-specific stop reasons are folded into the
canonical taxonomy:

* `stop_reason: "refusal"` (Claude Sonnet 4.5+) → `ContentFilter`
  (id 90). Semantically identical to OpenAI's `content_filter` and
  the SAFETY/RECITATION/BLOCKLIST/PROHIBITED_CONTENT/SPII cluster
  Gemini emits — the model refused to generate on safety grounds.
  Pinned by `anthropic_refusal_stop_reason_attests_content_filter`.
* `stop_reason: "model_context_window_exceeded"` → `MaxTokens`
  (id 2). Same semantic as OpenAI's `length` / Gemini's
  `MAX_TOKENS` — input + output overflowed the context window.
  Pinned by `anthropic_context_window_exceeded_attests_max_tokens`.

An operator dashboard filtering by `stop_reason == "Content Filter"`
or `"Length"` sees the same population regardless of the upstream
provider.

The rest of this document describes the client-facing OpenAI surface,
which does not change with the upstream dialect.

## Supported route

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/v1/chat/completions` | Full request/response, streaming SSE and non-streaming JSON. |

Every other route on the harness (`/v1/mcp`, `/mcp`,
`/v1/mcp/{backend}`, `/mcp/{backend}`, `/v1/sessions/{id}/promote`,
`/v1/sessions/{id}/close`, `/v1/token`, `/v1/revoke`, `/v1/introspect`,
`/admin/v1/revocations`, `/.well-known/jwks.json`, `/health`,
`/livez`, `/readyz`, `/metrics`, `/dashboard/*`) is ProofVisor
territory and is documented separately. `/v1/introspect` exists only
when `introspection_tokens` is configured, and `/admin/v1/revocations`
only when `operator_tokens` is configured. Only the chat route is
"OpenAI-compatible" in the strict sense.

### The `/v1` vs `/api/v1` split (round-51 §9.3)

The prefix split is deliberate, not accidental:

* **`/v1/*`** is the client-facing **agent API** — the surface an
  agent or SDK touches during a conversation: `/v1/chat/completions`
  (OpenAI-shaped), `/v1/mcp` (JSON-RPC tool gate; **also served at
  bare `/mcp`** for MCP SDK convention — both accept the same
  requests and share the same `max_request_bytes` cap), and the two
  session lifecycle verbs `/v1/sessions/{id}/close` and
  `/v1/sessions/{id}/promote`. Errors on the chat and session
  lifecycle routes use the OpenAI error body
  (`{"error":{"message","type","param","code"}}`) so SDK `e.code`
  handling works — including the 413 body-limit rejection. The MCP
  routes answer with JSON-RPC errors, and `/v1/token`, `/v1/revoke` and
  `/v1/introspect` follow their OAuth RFCs (8693, 7009 and 7662).
* **`/api/v1/*`** is the **operator API** behind the dashboard
  (`stats`, `sessions`, `sessions/{id}`), plus the unprefixed
  operational probes (`/health`, `/livez`, `/readyz`, `/metrics`).
  These return operator-shaped JSON, not OpenAI error bodies.

Success shapes on the lifecycle verbs are versioned operator
contracts, intentionally NOT OpenAI-shaped: `close` returns
`{"kind":"receipt",...}` / `{"kind":"atif",...}` /
`{"kind":"already_closed"}` and `promote` returns the bare signed
receipt object (the artifact itself, suitable for piping to
`pvctl receipt-verify`).

## Supported request fields

With `provider = "openai"`, passed through verbatim to the upstream
(the native adapters translate them as described above):

* `model` (required by the upstream, opaque to the harness)
* `messages` (system / user / assistant / tool)
* `stream` (boolean)
* `stream_options` (`include_usage`)
* `temperature`, `top_p`, `max_tokens`, `presence_penalty`,
  `frequency_penalty`, `stop`, `n`, `seed`
* `tools` (function-calling schema)
* `tool_choice`
* `response_format` (`{"type":"json_object"}`, `json_schema`)
* `logprobs`, `top_logprobs`
* `user` (opaque)
* `parallel_tool_calls`

Anything the harness doesn't recognize is forwarded unchanged. Adding
a new upstream-specific field does NOT require a code change here.

## Supported response fields

Streaming and non-streaming responses are re-emitted verbatim, with
one intentional filtering step:

* Only SSE frames with `event:` empty or `event: message` are
  captured for audit. A frame whose `event:` names something else
  and carries **non-empty** `data:` is refused: it would otherwise
  attribute forged content to the model output. A dataless named
  event (`event: ping\n\n`, `event: heartbeat\ndata:\n\n`) is
  treated as a keepalive and passes through without affecting audit
  (see round 51 §6.2 for the CVE-shaped rationale).

Both the strict-mode refusal and the keepalive pass-through are
covered by `parse_provider_chunk_refuses_non_message_sse_event_types`
and `parse_provider_chunk_treats_dataless_named_events_as_keepalives`.

## Context compression rewrites your payload (on by default)

`compression_enabled` defaults to **true**. Before forwarding, the
harness runs lossy compression passes over the `messages` array —
which means the bytes the provider receives are NOT byte-identical
to the bytes your client sent. This is the one deliberate exception
to "nothing else in your app moves":

| Pass | Engages at | Effect |
| --- | --- | --- |
| duplicate-system collapse | 512 approx tokens | Repeated identical system messages collapse to one |
| duplicate-message collapse | 512 approx tokens | Byte-identical repeated messages become `[pruned: N tokens (duplicate message), sha256:…]` stubs |
| stale-tool-output stub | 512 approx tokens | Verbose `tool` role messages whose tool_call has since been overtaken become size-bounded stubs; the linkage-preserving `tool_call_id` is kept |
| middle stubbing | 50,000 approx tokens | Middle-of-history messages are stubbed toward a target size; the first system message and the tail are preserved byte-identical |

Invariants the passes guarantee: message count order and roles are
preserved, the first system message and the `keep_tail` suffix are
byte-identical, and `tool_call_id` linkage survives (property-tested
in `pv-compress/tests/invariants.rs`). Every stub names the pruned
token count and the SHA-256 of the removed content, so the audit
trail records what was elided.

The signed receipt and the budget both use the **post-compression**
token count, so enforcement and attestation agree with what the
provider actually saw.

To forward payloads verbatim, set:

```toml
compression_enabled = false
```


## Intentional differences from openai.com

### 1. HTTP status codes

| Situation | OpenAI | ProofVisor |
| --- | --- | --- |
| Upstream rate limit | `429` | `429` (relayed from the upstream) |
| Console-pushed rate policy refusal | n/a | `403` |
| Post-compression session budget refusal | n/a | `403` (deliberately not 429, which SDKs auto-retry — the cap is permanent for the session) |
| Post-compression principal budget refusal | n/a | `403` |
| Semantic loop breaker refusal | n/a | `403` |
| Semantic loop breaker abort | n/a | `409` with `Connection: close` |
| Missing/invalid bearer | `401` | `401` (identity required) or `403` (scope missing) |
| Request body larger than `max_request_bytes` | `413` | `413` |
| Upstream 5xx | 5xx | forwarded, plus refund of pre-debited tokens |

### 2. Error bodies are OpenAI-shaped

Every 4xx/5xx from the chat and lifecycle routes carries
`{"error": {"message", "type", "param", "code"}}` — `type` follows
OpenAI's taxonomy (`invalid_request_error`, `authentication_error`,
`permission_error`, `rate_limit_error`, `api_error`) and `code` is
the numeric HTTP status, so stock SDK `e.type` / `e.code` dispatch
and retry classifiers behave correctly. 429/502/503/504 responses
additionally carry `Retry-After`; 401 carries `WWW-Authenticate`.

### 3. Streaming is a real SSE stream

The harness does NOT buffer streaming responses beyond a per-frame
window. Streaming clients receive bytes with roughly the same
latency as connecting directly to the upstream, plus a small per-frame
overhead for capture and budget checking.

### 4. `stream_options.include_usage` is honoured

The final SSE frame carries the true `usage` block, mirroring OpenAI.
Intermediate frames may carry `"usage": null` (vLLM/LiteLLM shim
behaviour) — the harness treats these as absent and does not feed
them to the accumulator.

### 5. Tool calls carry the audited `tool_call_id`

The audit record keeps the `tool_call_id` the upstream sent. When the
upstream omits one, the audit record uses a generated event id
instead. The response sent to the client is not modified.

## Session semantics

Chat requests carry two ProofVisor-specific headers:

| Header | Purpose |
| --- | --- |
| `X-PV-Session` | Client-chosen session id. Rotating this restarts the audit chain; the harness treats each `session_id` as an independent conversation. |
| `X-PV-Workflow` | `signed` or `unsigned`. Chooses whether the session's audit lands as a signed receipt (Kafka topic `agent.receipt`) or as an ATIF trajectory (spool + broker fold). |

If your client speaks OpenAI's protocol out of the box, it will not
set these. The harness defaults them from config
(`default_workflow`) and generates a fresh session id per request —
echoed back in the `X-PV-Session` **response** header, so you can
`pvctl receipt-locate` the audit artifact later.
The session then closes immediately after the response — one turn,
one audit event.

For long-lived multi-turn agent conversations, set the same
`X-PV-Session` on every request and either explicitly
`POST /v1/sessions/{id}/close` when done or rely on the idle-close sweeper
(`session_idle_close_s`).

## Unsupported OpenAI features

* `/v1/embeddings`, `/v1/audio/*`, `/v1/images/*`, `/v1/completions`
  (deprecated non-chat completion endpoint), `/v1/models`,
  `/v1/files`, `/v1/moderations`, `/v1/assistants`. The harness
  responds 404 to these; if you need them, front the harness with a
  path-based router.
* Fine-tuning APIs (`/v1/fine_tuning/*`). Same disposition.
* Assistants Threads/Runs APIs. Same disposition.

## Testing your client

The simplest smoke test:

```
curl -sS http://localhost:8484/v1/chat/completions \
     -H 'content-type: application/json' \
     -H "authorization: Bearer $OPENAI_API_KEY" \
     -d '{
       "model": "gpt-4o-mini",
       "messages": [{"role": "user", "content": "ping"}]
     }' | jq .
```

The response is an OpenAI-shaped `ChatCompletion` object. Your
audit event lands on the broker in parallel; verify it with
`pvctl event-tail --data-dir /path/to/bridge --topic agent.stop_reason`
(the `--data-dir` points at the harness's `bridge_data_dir`).
