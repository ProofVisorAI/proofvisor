# ProofVisor Configuration Reference

The harness reads its TOML from the first path that exists in this
order:

1. `$PV_CONFIG` (an absolute path to a specific file)
2. `./proofvisor.toml`
3. `./config/harness.toml`
4. `./agentvisor.toml` (the file name used before the ProofVisor rename)
5. `$HOME/.proofvisor/proofvisor.toml`, or `$HOME/.agentvisor/agentvisor.toml`
   when only the pre-rename file exists
6. built-in defaults

`config/harness.example.toml` is documentation only and is NOT
searched — see engineering review round 51 §9.4. If you were relying
on that rank swap, copy it to one of the searched paths.

`pvctl config-validate path/to/harness.toml` runs the same parser,
`validate()` gates, and JSON-schema fidelity checks that `proofvisord`
runs at startup and fails with the same diagnostics.

## Environment variables

Round-51 §9.4: these were previously documented nowhere outside the
source. All are optional.

| Variable | Read by | Meaning |
| --- | --- | --- |
| `PV_SIGNING_SEED_FILE` | `proofvisord` | Path to the 32-byte Ed25519 signing seed — **the root of the entire trust story**. Default `config/signing.seed` relative to the working directory. If the file is missing, a fresh seed is generated and a WARN names the new key id: every receipt signed after an unintended regeneration verifies only against the NEW key, so mount this from a Secret in production and treat the WARN as a compliance incident outside first boot. |
| `PV_CONFIG` | `proofvisord`, `pvctl` | Absolute path to the config file; rank 1 in the search order above. |
| `PV_UPSTREAM_URL` | `proofvisord` | Overrides `upstream_url` (useful in containers where the config file is baked). |
| `PV_LISTEN` | `proofvisord` | Overrides `listen`. |
| `PV_UPSTREAM_CHAT_PATH` | `proofvisord` | Overrides `upstream_chat_path`. |
| `PV_UPSTREAM_AUTH_HEADER` | `proofvisord` | Overrides `upstream_auth_header`. |
| `PV_UPSTREAM_AUTH_SCHEME` | `proofvisord` | Overrides `upstream_auth_scheme`. An empty value is kept and sends the raw key. |
| `PV_UPSTREAM_KEY_FILE` | `proofvisord` | Path to a file holding the upstream API key. Used only when the config sets neither `upstream_api_key_env` nor `upstream_api_key_file` and passthrough is off. |
| `PV_UPSTREAM_API_KEY` | `proofvisord` | The upstream API key itself. Used under the same conditions as `PV_UPSTREAM_KEY_FILE`; the file wins when both are set. |
| `PV_STATE_ENDPOINT` | `proofvisord` | Overrides `state_endpoint`. |
| `PV_BRIDGE_ENDPOINT` | `proofvisord` | Overrides `bridge_endpoint`. |
| `PV_QDRANT_URL` | `proofvisord` | Overrides `qdrant_url`. |
| `PV_STRICT_BUDGET` | `proofvisord` | `1`, `true`, `yes` or `on` turns on `strict_stage_budget`. |
| `PV_BEARER_TOKEN_FILE` | `pvctl` | Path to a file holding the NHI bearer used by `pvctl loadgen` and `pvctl session-promote`. |
| `PV_POLICY_BUNDLE_FILE` | `pvctl` | Default for `pvctl console-sync --policy-bundle-file`. |
| `RUST_LOG` | `proofvisord` | Tracing filter (default `info`). A parse failure falls back to `info` with a warning. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | `proofvisord` | OTLP trace export target. Requires a build with `--features otel`; a default-features binary warns loudly instead of silently ignoring them. |

Both `proofvisord` and `pvctl` also accept the pre-rename `AV_*` names: at
startup each `AV_*` variable is copied to its `PV_*` name when that name is
unset or empty, and a warning on stderr names the variables it copied.


## Networking

| Key | Default | Notes |
| --- | --- | --- |
| `listen` | `127.0.0.1:8484` | Bind address:port for HTTP. The 127.0.0.1 default is *deliberate*: the harness refuses to boot on a `0.0.0.0` bind when identity is not required (see below). |
| `allow_wildcard_bind` | `false` | Opt-in for `listen = "0.0.0.0:*"` when `require_identity = false`. Only set this when a network layer above the harness — Kubernetes NetworkPolicy, a service-mesh mTLS gateway, a corporate proxy ACL — controls who can reach the port. The container image sets this to `true`; it is expected that container users provide their own ingress ACL. |
| `require_identity` | `false` | Refuse any request without a valid NHI bearer. The **default is off** (development posture): the shipped safety net is the loopback `listen` default plus the wildcard-bind refusal. Set to `true` (with a JWKS/HMAC source) for any deployment reachable by anyone but the operator. |
| `identity_jwks_url` | none | JWKS URL for validating NHI tokens. Rotated JWKS entries are recognized within `identity_jwks_refresh_s` (default 300). |
| `identity_allowed_issuers` | `[]` | If non-empty, only tokens whose `iss` matches one of these are accepted. |
| `audience` | `agentvisor-ai` | Required token audience, and the `iss` of the intent and exchange tokens the daemon signs. The value predates the ProofVisor name and is kept so existing identity providers and backends keep working. |
| `enforce_identity_scopes` | `false` | Requires per-route scope claims. Applies only when `require_identity = true`. |
| `allowed_hosts` | `[]` (disabled) | Host-header allowlist (DNS-rebinding defense). Non-empty: requests whose `Host` (port stripped, case-insensitive) isn't listed are refused 403 before any handler. Leave empty for loopback binds or when the ingress enforces Host. |
| `chat_scope` / `session_close_scope` / `session_promote_scope` | `chat:write` / `session:close` / `session:promote` | Scope claims required on each route. |

## Dashboard

| Key | Default | Notes |
| --- | --- | --- |
| `dashboard_enabled` | `true` | Serves `/dashboard*` and `/api/v1/dashboard/*`. These endpoints are **unauthenticated** and mirror the in-memory session registry. The default-on posture is safe only because the `listen` default is loopback and config validation refuses a wildcard bind while the dashboard is on, even with `require_identity = true`, unless `allow_wildcard_bind = true`; front the harness with the same ingress control you use for `/metrics` before exposing it. |

## Upstream

| Key | Default | Notes |
| --- | --- | --- |
| `config_version` | `1` | Config format version; unknown versions are refused at boot. |
| `upstream_url` | required | Base URL of the model backend (OpenAI, vLLM, LiteLLM, Ollama, …). For `provider = "anthropic"` use `https://api.anthropic.com`; for `provider = "gemini"` use `https://generativelanguage.googleapis.com`. |
| `upstream_chat_path` | `/v1/chat/completions` | Path appended to `upstream_url` for chat traffic when `provider = "openai"`. The native adapters own their paths (`/v1/messages` for Anthropic, `/v1beta/models/{model}:generateContent` or `:streamGenerateContent?alt=sse` for Gemini) and ignore this key. |
| `provider` | `openai` | Upstream wire dialect; selects the `ProviderAdapter` that parses bodies and SSE chunks. `openai` also fits vLLM, LiteLLM, Groq, Together, DeepSeek, OpenRouter, Ollama, LM Studio, llama.cpp, xAI, Mistral and Azure OpenAI; `anthropic` and `gemini` select the native adapters, which translate each OpenAI request into the provider's own API and translate the response back into OpenAI chat-completion objects and chunks (see [OPENAI-COMPATIBILITY.md](OPENAI-COMPATIBILITY.md)). The native adapters have been tested only against local stand-ins, not against the live Anthropic or Gemini APIs. |
| `provider_default_max_tokens` | `4096` | Output-token limit sent to Anthropic when a request sets neither `max_tokens` nor `max_completion_tokens`; the Anthropic Messages API refuses requests without one. Must be at least 1. Other providers ignore it. |
| `upstream_authorization_passthrough` | `false` | Forward the client's `Authorization` header verbatim to the upstream. **Incompatible with `require_identity = true`** (the header carries the NHI identity token there, not an upstream credential) and with the static upstream key options — boot refuses those combinations. |
| `ignore_client_authorization` | `false` | Accept and DISCARD a client `Authorization` bearer when no identity validator is configured (stock OpenAI SDKs always send a placeholder key; without this a keyless dev upstream 401s the documented quickstart on request one). The header never reaches the upstream. Refused in combination with `require_identity = true` or `upstream_authorization_passthrough = true`. |
| `upstream_http2_prior_knowledge` | `false` | Skip HTTP/1 → HTTP/2 upgrade negotiation on the outbound connection. |
| `upstream_read_timeout_s` | `60` | Read-idle timeout for upstream requests. Each successful read restarts it; this does not limit total streamed-chat duration. The allowed range is 1–86400 seconds. |
| `mcp_request_timeout_s` | `60` | Total deadline for each outbound MCP HTTP request, from connection establishment through response-body completion, including after caller cancellation. The allowed range is 1–86400 seconds. It does not bound admission, audit work, or streamed chat. A timeout after response headers is recorded and audited as a replayable 502; a timeout before response headers leaves the execution uncertain, so a retry cannot repeat possible tool effects. |
| `shutdown_drain_timeout_s` | `max(30, max(upstream_read_timeout_s, mcp_request_timeout_s) + 5)` | Graceful-shutdown drain budget, using the network settings' defaults when unset. Long chat streams and audit work can exceed this budget; an explicit value overrides the derivation. |
| `shutdown_ready_drain_s` | `0` | Readiness-controlled pre-drain window: on SIGTERM, `/readyz` serves 503 while the listener keeps accepting for this long before the drain begins. Needed for every deployment target where the LB polls `/readyz` — this includes Kubernetes distroless images (no `/bin/sh` for a `preStop` sleep hook), docker-compose, systemd, and bare-VM LBs. The shipped k8s manifest sets this to `5`. |
| `upstream_api_key_env` / `upstream_api_key_file` | none | Where to pull the outbound API key from. `_file` wins over `_env` when both are set. |
| `upstream_auth_header` | `authorization` | Header carrying the upstream API key — `authorization` (OpenAI), `api-key` (Azure). When this key and `upstream_auth_scheme` are left at their defaults, the native adapters send the raw key in the provider's own header instead: `x-api-key` for Anthropic and `x-goog-api-key` for Gemini. |
| `upstream_auth_scheme` | `Bearer` | Prefix inserted before the key in the auth header; an empty string sends the raw key (Azure style). |
| `max_request_bytes` | `4194304` (4 MiB) | Maximum request body accepted on `/v1/chat/completions` and `/mcp`, matching the sandbox's payload cap so both routes carry the same effective limit. Raise for very-long-context models. |

## Workflows and receipts

| Key | Default | Notes |
| --- | --- | --- |
| `default_workflow` | `unsigned` | Workflow when the `X-PV-Workflow` header is absent. **`unsigned` produces ATIF trajectories but NO signed receipts** — every shipped config (example, container, docker, K8s) overrides this to `signed`; set it explicitly if you need verifiable receipts and cannot send the header. |
| `consequential_tools` | `["db_write", "payout", "merge", "deploy"]` | Tool names that require a signed workflow because they have real-world consequences. |
| `signed_workflow_scope` | unset | Scope a bearer token must hold to open a signed workflow (`X-PV-Workflow: signed`). Unset, any caller may pick the signed workflow, so `consequential_tools` only chooses the audit mode a consequential call runs under. Set to, for example, `workflow:signed` and a token without that scope is refused with `403` on a signed session, so it cannot reach a consequential tool at all. Applies when `enforce_identity_scopes` is on. |

## Identity (development HMAC)

| Key | Default | Notes |
| --- | --- | --- |
| `identity_hmac_secret_file` | none | File containing an HS256 development secret (owner-only permissions enforced). Development alternative to `identity_jwks_url`. |
| `identity_hmac_kid` | `dev-hmac` | Key id assigned to the development HMAC secret. |
| `identity_human_subject_pattern` | none | Regular expression every validated token's `sub` must match, so each agent identity is attributable to a human principal (for example `^user:`, or your identity provider's user-id prefix). A token whose subject does not match is refused with `401`; holder revocation still works for it. The pattern applies to requests, token-exchange subjects, and actor tokens. Anchor it: it matches anywhere in `sub`. |

## Tool proxy (`/v1/mcp`)

| Key | Default | Notes |
| --- | --- | --- |
| `tool_upstream_url` | none | Downstream MCP/REST tool server. When absent, `/v1/mcp` operates as a policy decision endpoint (allow/deny + audit, no forwarding). |
| `tool_upstream_bearer_env` / `tool_upstream_bearer_file` | none | Bearer credential for `tool_upstream_url` requests; `_file` is enforced owner-only on Unix. `pvctl doctor` checks whichever is configured. |
| `tool_schema_dir` | `config/tool-schemas` | Directory of one JSON Schema per tool, named `<tool>.json`. |
| `require_tool_schema` | `true` | Reject tool calls with no matching schema (fail closed). `false` skips the schema gate — policy and budget gates still apply. |
| `payout_field` | `amount_usd` | Tool-call argument field carrying a payout in USD, charged against `max_payout_usd_micros`. Set this to match YOUR tool schema — the cap only fires on calls carrying this exact field. |
| `wasm_policy_paths` | `["config/policies/payload_limit.wat"]` | WASM/WAT policy modules, evaluated in order. The default path resolves to an embedded built-in when no file exists on disk. A module that exports `evaluate_v2` instead of `evaluate` uses policy interface version 2: it also receives the semantic judge's outcomes and may return `2` to ask for human approval (see [Semantic judge](#semantic-judge-judge)); `config/policies/judge_thresholds.wat` is an example that applies the specification's thresholds (deny above 0.7, ask above 0.3). Modules exporting only `evaluate` behave exactly as before. |
| `tool_upstream_transport` | `json_rpc` | Wire protocol for `tool_upstream_url`: `json_rpc` sends one plain JSON-RPC POST per call (the historical behavior); `mcp` speaks the MCP Streamable HTTP transport described under [Backend routing](#backend-routing). `[[backends]]` entries choose their own `transport` and default to `mcp`. |
| `mcp_allowed_origins` | `[]` | Browser origins (`scheme://host[:port]`) allowed to call the daemon from a web page. A request to the MCP, chat completions, session lifecycle, token exchange or revocation routes that carries any other `Origin` header is refused with `403` (the MCP transport requires this, and it stops a hostile page from driving a loopback daemon cross-site). Agents run server-side and send no `Origin`, so the empty default refuses only browser pages. |

### MCP protocol on `/mcp`

`/mcp` and `/v1/mcp` are MCP servers for the
[Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
(protocol versions `2025-11-25`, `2025-06-18`, `2025-03-26`, and
`2024-11-05`), so a stock MCP client connects without code changes:

- `initialize` negotiates the protocol version (the client's version when
  supported, otherwise the latest) and returns an `MCP-Session-Id`. The id
  is an HMAC-signed value bound to the caller's identity (issuer and
  subject) and valid for 24 hours. It also names the audited session, so
  every call of one MCP session lands in one ProofVisor session. A request
  with an id that is forged, expired, or issued to another principal gets
  `404`, which tells the client to initialize again.
- `ping` returns an empty result. Notifications and client responses are
  acknowledged with `202`.
- `tools/list` returns, in one page, the tools of every backend the
  endpoint serves, and only tools the caller can call: names the tool gate
  accepts (lowercase ASCII without whitespace), routed to that backend,
  covered by the caller's scopes when `enforce_identity_scopes` is on, and
  permitted by the intent map, the missions, and the external AuthZEN PDP
  when one is configured. Withheld tools are counted in
  `pv_mcp_tools_withheld_total{reason}`; a backend whose discovery fails is
  counted in `pv_mcp_discovery_failures_total{backend}` and skipped.
  Backends on the `mcp` transport are asked with their own `tools/list`;
  `json_rpc` backends list their configured `tools`, with `inputSchema`
  and `description` taken from `tool_schema_dir`.
- `tools/call` runs through the audited tool path. A forwarded call needs
  a session: an `MCP-Session-Id`, or the `X-PV-Session` header.
- `GET` answers `405` (the gateway opens no server-to-client stream).
  `DELETE` with an `MCP-Session-Id` closes the audited session exactly like
  `POST /v1/sessions/{id}/close` (it requires `session_close_scope`).
- An unsupported `MCP-Protocol-Version` header is refused with `400`.

Every lifecycle message still requires the caller's identity when
`require_identity` is on. `/mcp/{backend}` and `/v1/mcp/{backend}` expose
the same protocol restricted to one backend: `tools/list` shows only that
backend's tools, and a `tools/call` for a tool routed elsewhere is an
audited denial with the code `NO_BACKEND` (policy `backend.route`).

## Budgets

There are **two** budget ledgers. Both share the same `pv_state::BudgetSpec`
shape (`{ max_tokens, max_tool_calls, max_total_tool_calls,
max_payout_usd_micros }`).

| Key | Default | Notes |
| --- | --- | --- |
| `budget` | permissive | Session-scoped budget. Debited per accepted request, refunded on upstream failure, checked **after** compression (see round 51 §6.3). |
| `principal_budget` | unset | Optional principal-scoped budget layered on top. Its key is derived from the validated NHI identity — same principal, same key across session-id rotation (round 51 §3.2). Refused-by-session refunds bring the principal ledger back to whole. |
| `allow_anonymous_principal_budget` | `false` | Opt-in for setting `principal_budget` while `require_identity = false`. Otherwise the harness refuses to boot — anonymous callers all share one key and DoS each other. |

## Console-pushed policy

| Key | Default | Notes |
| --- | --- | --- |
| `policy_bundle_file` | none | File that `pvctl console-sync --watch --pull-policies` writes the console's policy bundle to (owner-only; a group- or world-writable file is refused). The daemon applies it at boot and refuses to start if the file exists but cannot be applied, then polls it for changes and writes what it enforces to `<file>.status.json`, which `pvctl` reports to the console. Pushed policies only tighten the local config: `budget` caps merge with `[budget]` (the stricter cap wins), `allowlist` and `schema` rules run after the local policy chain and schemas, and `rate` policies limit model tokens per principal over a sliding window. `guardrail` policies whose body is the JSON spec (see [OPERATIONS.md](OPERATIONS.md#guardrail-policies)) refuse tool arguments, chat requests or model responses that match their deny patterns, and `transform` policies whose body is the JSON spec (see [OPERATIONS.md](OPERATIONS.md#transform-policies)) replace matches in tool arguments, chat requests or model responses before they are journaled or forwarded; a free-text guardrail or transform is documentation only. A newer file that cannot be applied leaves the rules in force unchanged. Unset: nothing is pulled. |
| `policy_bundle_poll_s` | `5` | Seconds between checks of `policy_bundle_file` (1–3600). |

## Storage

| Key | Default | Notes |
| --- | --- | --- |
| `atif_spool_dir` | `spool/atif` (relative to the working directory) | Where ATIF trajectories and their `.atif-auth` sidecars land. Backup with the same discipline you use for receipts. |
| `atif_retention_days` | unset | When set to a positive N, an hourly sweep removes **sealed** ATIF pairs (`.json` + `.atif-auth`) whose mtime is older than N days. Unpaired remnants are left for the reconciler's quarantine sweep. Leave the key unset (or set to `None` in TOML by omitting it) to disable in-process retention entirely; `0` is rejected by config validation because a zero-day window would prune every sealed pair on the first tick. See round 51 §8.1. |
| `bridge_data_dir` / `bridge_backend` / `bridge_endpoint` | `data/bridge` / `embedded` / unset | Broker configuration; either the embedded Bridge or an external one. |
| `bridge_manifest_path` | `manifests/bridge.example.yaml` | Declarative topic-schema manifest used by every Bridge backend; resolves to an embedded built-in when the default path has no file on disk. |
| `state_backend` / `state_endpoint` | `memory` / unset | State store: in-process memory or Redis. |

## Reconciler

| Key | Default | Notes |
| --- | --- | --- |
| `reconcile_tick_s` | `5` | How often the reconciler sweeps the spool for pending-close, orphan, and retention work. |
| `session_idle_close_s` | `900` | Idle-timeout after which an open session is force-closed. |

## Loop detection and embeddings

| Key | Default | Notes |
| --- | --- | --- |
| `[breaker]` | see `pv_loopdetect::BreakerConfig` | Loop-detection circuit-breaker thresholds. Tune only after reviewing `docs/reference/OPERATIONS.md`. |
| `embedder_backend` | `hash` | Embedding backend for loop detection: `hash` (dependency-free) or `onnx`. |
| `onnx_model_path` / `onnx_tokenizer_path` | none | Customer-supplied ONNX model and its paired Hugging Face `tokenizer.json`; required when `embedder_backend = "onnx"` (build with `--features onnx`). |
| `onnx_dimension` | `384` | ONNX model output width. |
| `vector_backend` | `memory` | Reasoning-vector persistence: `memory` or `qdrant` (build with `--features qdrant`). |
| `qdrant_url` | none | Qdrant base URL; required when `vector_backend = "qdrant"`. |
| `qdrant_collection` | `agent_steps` | Qdrant collection receiving reasoning vectors. |

## Delegation and token exchange

| Key | Default | Notes |
| --- | --- | --- |
| `max_delegation_depth` | `4` | Maximum combined depth of `parent_token` chain links and `act` claim nesting. Tokens exceeding this depth are rejected. |
| `token_exchange_enabled` | `false` | Enable the RFC 8693 token exchange endpoint at `/v1/token`. Boot refuses it unless `token_exchange_seed_file`, an identity source (`identity_jwks_url` or `identity_hmac_secret_file`), and at least one `[[backends]]` entry are configured. |
| `token_exchange_seed_file` | none | Ed25519 signing seed file for exchanged tokens and intent tokens (owner-only permissions enforced; must be distinct from the receipt signing seed). Its public key is served at `/.well-known/jwks.json` so backends can verify both kinds of token. |
| `token_exchange_ttl_s` | `300` | TTL in seconds for exchanged tokens. Capped at 900 to prevent indefinite delegation. |

The request may carry an RFC 8693 actor token (`actor_token` together
with `actor_token_type=urn:ietf:params:oauth:token-type:jwt`). The actor
token is validated like the subject token and must be undelegated (no
`parent_token` and no `act`). The issued token then keeps the subject's
`sub` (the human), names the actor's agent in `act.sub` and `azp`, moves
the subject's agent to `act.act.sub`, holds the scopes requested ∩ subject
∩ actor, never outlives either token, and counts two delegation links
against `max_delegation_depth`. Revoking the actor token revokes every
token obtained with it. `actor_token` without `actor_token_type` (or the
reverse), or another token type, is refused with `invalid_request`.

The exchange signs tokens only for audiences that name a configured
backend. A request for any other audience, or any request while no
backends exist, is refused with the RFC 8693 `invalid_target` error. A
subject token that fails validation is refused with `invalid_request`, and
the description is deliberately generic: it never names key ids, issuers,
or algorithms. When the revocation list cannot be read, the endpoint
answers `503` with `temporarily_unavailable` and `Retry-After`.

## Platform workload identity (Cloud Foundry)

With `[workload_identity]`, an application instance on Cloud Foundry can
obtain a ProofVisor agent token without any stored secret, by proving the
instance identity certificate the platform gives every container
(`CF_INSTANCE_CERT` / `CF_INSTANCE_KEY`, rotated before expiry). The
`pvctl sidecar` that the buildpack starts beside the application does this
automatically; see [the buildpack instructions](../../buildpack/README.md).
The settings are `workload_identity` (TOML `[workload_identity]`) and
`workload_identities` (TOML `[[workload_identities]]`).

| `[workload_identity]` key | Default | Notes |
| --- | --- | --- |
| `ca_file` | required | PEM bundle of the foundation's instance-identity root CA certificate(s). Ask the platform operator for the Diego instance identity CA. |
| `token_ttl_s` | `300` | Lifetime of issued agent tokens, 60 to 900 seconds. |

| `[[workload_identities]]` key | Default | Notes |
| --- | --- | --- |
| `name` | required | Unique name (ASCII letters, digits, `-`, `_`, `.`), used in metrics and logs. |
| `cf_app_guid` / `cf_space_guid` / `cf_org_guid` | none | At least one is required; every one that is set must match the instance certificate. |
| `sub` | required | The human principal this workload's agents act for; it becomes the token's `sub` and must match `identity_human_subject_pattern` when that is set. |
| `charter` | required | Agent charter recorded in the token and in every audit event. |
| `version` | `"1"` | Agent version recorded in the token. |
| `scopes` | required | Scopes granted to the workload's agents. |

The instance sends `/v1/token` an RFC 7523 assertion:
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<JWT>`.
The JWT is signed `RS256` with the instance key, carries the instance
certificate and its intermediates in `x5c`, and has `aud` = the gateway's
`audience`, `sub` = the instance GUID, a unique `jti`, and a lifetime of at
most 300 seconds. The gateway verifies the chain up to `ca_file` (with the
clientAuth extended key usage), the signature, the claims, and that the
`jti` was not used before (the replay cache is kept in memory per gateway
instance, so with several replicas an intercepted assertion could be
accepted once by each replica within its lifetime of at most 300 seconds); reads the app, space, and organization GUIDs from
the certificate subject; and picks the one `[[workload_identities]]` entry
that matches (none or several is refused). It answers with a standard token
response (`access_token`, `token_type`, `expires_in`, `scope`). An optional
`scope` parameter can only narrow the entry's scopes. Refusals use the
OAuth `invalid_grant` or `invalid_scope` errors with a generic description;
the reason is counted in `pv_workload_assertions_rejected_total{reason}`
and logged under the `proofvisor.workload` target, and issued tokens are
counted in `pv_workload_tokens_issued_total{workload}`.

The agent token is signed with `token_exchange_seed_file` (required), its
issuer is `<audience>#workload` (added to `identity_allowed_issuers` when an
allowlist is configured), and its claims are `sub` (the entry's human),
`instance_uid` (the instance GUID), `azp` (`cf-app:<app guid>`), `charter`,
`version`, `scopes`, a unique `jti`, and `exp`. The gateway's validator
trusts it on every route, and it can be revoked with `POST /v1/revoke` or by
operator revocation of its `jti` or instance GUID. To stop an application
from obtaining new tokens, remove its entry or stop the application.
`[workload_identity]` also makes the gateway build an identity validator
when no external identity provider is configured.

## Token revocation (`POST /v1/revoke`)

Send a form field `token=<jwt>` to revoke an inbound NHI token or a token
issued by this gateway. The optional `token_type_hint` is ignored. The
route is available when an identity validator is configured. Possession
of the token permits its revocation; invalid and already revoked tokens
receive the same empty `200` response with `Cache-Control: no-store`.
The gateway verifies the signature before writing any revocation entry.
Inbound delegation chains embed complete parent bearer tokens. A delegate
can therefore extract and use or revoke its parent token, which also
revokes sibling chains. Use this format only between mutually trusted
delegates; it does not isolate a parent credential from its delegates.
Exchanged tokens embed ancestor identifiers instead of parent credentials.
A correctly signed token scheduled to become valid within the bounded
15-minute scheduling window can also be revoked before activation.
An unknown signing key receives `503` so the caller can retry after key
rotation, rather than being told that a revocation succeeded.

An NHI revocation covers the token's full expiry tolerance. It also blocks
every child that includes the token in its delegation chain. Exchanged
tokens carry signed identifiers of their original ancestors, without
embedding their bearer credentials. Revoking an ancestor makes its
exchanged tokens inactive when a backend checks introspection.

With `state_backend = "redis"`, revocation entries and instance cutoffs
are shared across replicas and retained for 24 hours. With `"memory"`,
they belong to one process and are lost on restart. Memory entries are
swept after their final acceptance time. A storage failure returns `503`
with `Retry-After`; it never silently treats an unreadable list as empty.

Use a `rediss://` endpoint for certificate-verified Redis TLS. The hostname
must match the server certificate. The native trust store is used by default;
set `SSL_CERT_FILE` to a readable PEM CA bundle when Redis uses a private CA.
Include public roots needed by other clients that honor this environment
variable. Insecure TLS URLs are refused. All comma-separated Redis Cluster
seeds must use the same transport. The `redis` Cargo feature includes TLS
support; the production container enables it.

Redis revocation reads allow at most 32 concurrent calls per token namespace.
After three consecutive storage errors, a circuit breaker refuses reads
immediately for one second. One caller then checks whether storage has
recovered. A bounded local cache holds up to 100,000 known revocations per
namespace; it never caches permission to use a token. Known revoked tokens
remain refused during an outage. A locally requested revocation enters this
cache before the shared write, but a failed write still returns `503` and
must be retried to reach other replicas.

Monitor `pv_revocation_lookups_total{namespace,outcome}`,
`pv_revocation_breaker_opened_total{namespace}`,
`pv_revocation_list_available{namespace}`, and
`pv_revocation_local_entries{namespace}`. The `/readyz` response reports
`checks.revocation_available` and `checks.revocation_local_entries` without
changing its HTTP status for a revocation outage. Requests still fail
closed while storage is unavailable; reporting the outage does not remove
all replicas from service at once.

Each new holder revocation creates an `agent.identity` event and an
ordinary signed receipt. The event records the action, token identifier,
issuer, subject, and lifetime, but never the token or its parent tokens.
Repeated holder revocations do not create duplicate receipts. The receipt
can be checked with `pvctl receipt-verify` and the independent receipt
public key. The revocation takes effect even if audit capacity is
exhausted. Alert on `pv_tokens_revoked_unaudited_total{reason=...}` and
`pv_revocation_audit_close_failures_total`; these identify missing capture
and delayed receipt finalization. There is no atomic transaction between
the revocation store and the journal, so a process failure between those
writes can leave a revocation without a receipt.

| Key | Default | Notes |
| --- | --- | --- |
| `revocation_audit_per_minute` | `600` | Maximum revocation audit records per process per minute. It must be at least 1. This budget is separate from rejected-identity sampling. |
| `operator_tokens` | `[]` | Named SHA-256 digests of independent operator bearer secrets. Enables the administrative route described below. |
| `introspection_tokens` | `[]` | SHA-256 digests of independent backend bearer secrets, each bound to one configured backend name. Enables introspection. |

### Backend introspection (`POST /v1/introspect`)

A backend sends `token=<jwt>` as a form body and authenticates with its
own bearer secret. Store only the secret's SHA-256 digest in config:

```toml
[[introspection_tokens]]
backend = "customer-service"
sha256 = "<64 hexadecimal characters: SHA-256 of a random backend secret>"
```

The response follows [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html).
It returns `active: false` for a revoked, expired, forged, or wrong-audience
token. Only a token addressed to the authenticated backend may expose
claims. An unavailable revocation store returns `503`, which the backend
must treat as a refusal until it can retry. Use TLS for this endpoint
outside loopback, including when TLS terminates at an ingress proxy.

Backends that verify JWTs offline still accept a revoked token until its
expiry. Immediate revocation requires introspection on every call; caching
an active answer delays revocation by the cache duration. Backends must
also validate their intended token profile and the requested tool scope.
Forwarded MCP credentials use JWT header `typ = "av-tool+jwt"`. Tokens
from the optional public exchange endpoint use `typ = "JWT"`; intent
proofs use `typ = "av-intent+jwt"`. A tool backend must require the first
profile and must reject the other two as tool credentials. Checking only
the signature and audience is insufficient. Restrict network access to
tool backends to the gateway as an additional control.

### Operator revocation (`POST /admin/v1/revocations`)

The route exists only when `operator_tokens` is nonempty. Each operator
uses a separate random bearer secret of at least 32 characters. Agent
credentials and introspection credentials do not authorize this route.

```toml
[[operator_tokens]]
name = "incident-response"
sha256 = "<64 hexadecimal characters: SHA-256 of a random operator secret>"
```

Send exactly one target in a JSON body: `{"jti":"token-id"}` to revoke an
NHI token by identifier, `{"jti":"token-id","token_kind":"exchanged"}` to
revoke a gateway token, or `{"instance_uid":"agent-instance"}` to revoke
all tokens issued for that instance at or before the current time plus
the validator's clock tolerance. The cutoff only moves forward. Tokens
issued later remain usable. The operator does not need the original JWT. Identifier revocations are retained
for 24 hours; an issuer must never reuse a token identifier.
An instance cutoff also invalidates exchanged descendants through
introspection.

A successful response contains `revoked: true` and `audited`. If `audited`
is false, the revocation still took effect but its signed receipt was not
completed; inspect the audit metrics and logs. Every operator action, including a repeat of an earlier command, identifies
the configured operator in its signed event. There is no undo operation.

The CLI exposes `pvctl token-revoke` and `pvctl instance-revoke`. It reads
an owner-only credential file from `--operator-token-file` or
`PV_OPERATOR_TOKEN_FILE`, or falls back to `PV_OPERATOR_TOKEN`. It trims
surrounding whitespace before hashing the bearer; configure the digest of
the secret itself, without a trailing newline.

```sh
pvctl token-revoke --jti token-id --operator-token-file /run/secrets/operator-token \
  --url https://gateway.example.com
pvctl token-revoke --jti exchanged-token-id --token-kind exchanged \
  --operator-token-file /run/secrets/operator-token --url https://gateway.example.com
pvctl instance-revoke --instance-uid agent-instance \
  --operator-token-file /run/secrets/operator-token --url https://gateway.example.com
```

The CLI refuses redirects and HTTP destinations outside loopback. Repeat
`--url` to contact each independent memory-backed replica; one failed
replica makes the command fail even if others succeeded. A Redis-backed
fleet shares its revocation state, so one healthy replica suffices. Use
TLS outside loopback and keep the administrative route behind the
operator network. Never pass the bearer itself as a command-line argument.

## Intent mapping and missions

| Key | Default | Notes |
| --- | --- | --- |
| `intent_map` | `{}` | Maps tool names to business intents (TOML `[intent_map]`, e.g. `db_write = "data.mutate"`). When `require_intent_mapping` is true, tools not in the map are denied with `UNMAPPED_TOOL`. |
| `require_intent_mapping` | `false` | When true, every tool call must have a configured intent mapping. |
| `mission` | none | Active mission constraint for every caller (TOML `[mission]`). Contains `id`, `allowed_intents`, and `expires_at`. Only narrows static policy, never widens. |
| `missions` | `[]` | Per-agent missions (TOML `[[missions]]`). Each entry has `id`, `allowed_intents`, `expires_at`, and at least one selector: `agents` (token `instance_uid` values), `charters`, or `subjects` (human `sub` values). An entry applies to a caller when every selector it sets matches. A call must satisfy the global `[mission]` and every per-agent mission that applies, so missions only ever narrow. Mission ids must be unique. |
| `mission.task` / `missions[].task` | none | Optional operator-written statement of the task the mission is for (1 to 4096 characters). The semantic judge reads it, never the agent's prompt, when it decides whether a tool call's arguments fit the task. It has no effect on the allow/deny rules above. |
| `intent_token_ttl_s` | `60` | TTL in seconds for per-call intent tokens issued by the local PDP. |
| `authzen` | none | External AuthZEN policy decision point (TOML `[authzen]`), described below. |

The policy decision point runs before the tool budget is charged, in every
mode, including verdict-only mode (no `tool_upstream_url` and no
`[[backends]]`). A denied call consumes no budget, and its audit event
records `allowed: false` with the denial code and a `policy` name of
`pdp.intent_map`, `pdp.mission`, or `pdp.authzen`. The JSON-RPC error
echoes the request `id` and carries the machine-readable code in
`error.data.code` (for example `UNMAPPED_TOOL`, `MISSION_EXPIRED`,
`MISSION_DENIED`, `PDP_DENIED`).

### External AuthZEN policy decision point

| `[authzen]` key | Default | Notes |
| --- | --- | --- |
| `evaluation_endpoint` | required | Access Evaluation endpoint of an [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) PDP, for example `https://pdp.example.com/access/v1/evaluation`. |
| `evaluations_endpoint` | none | Access Evaluations (batch) endpoint, used to filter `tools/list` in one request. Without it, `tools/list` sends one evaluation per tool. |
| `auth_file` | none | File holding a bearer token for the PDP (owner-only permissions enforced). |
| `timeout_ms` | `1000` | Per-request timeout, 1 to 10 000 ms. |
| `resources` | none | How tools are described to the PDP as resources, keyed by tool name or pattern: `[authzen.resources."create_todo"]` with `type = "todo"`, optional `id` (the tool name when absent) and optional `properties` (a table merged into the request). An exact name wins over a pattern (`"payments.*"`); patterns apply in key order. A tool without an entry is sent as `{"type": "tool", "id": "<tool>"}`. The backend serving the tool is always added to `properties`, and the tool name too for mapped resources. |

When `[authzen]` is set, every tool call that the intent map and missions
permit is also evaluated by the PDP, before any budget is charged. The
request's `subject` is the human principal (`type: "user"`, `id`: the
token's `sub`) with the acting agent, `azp`, `act`, issuer, and scopes in
`subject.properties`; the `action` is the resolved intent (`name`) with the
tool in `properties`; the `resource` is `{type: "tool", id: <tool>,
properties: {backend}}`; the `context` carries `session_id`, the applicable
`missions`, and `time`. Requests carry `X-Request-ID`. `{"decision":
false}` is an audited denial with the code `PDP_DENIED`; a reason from the
response context (`reason_admin`, `reason_user`, or `reason`) is included
in the error. A timeout, a non-200 status, or a body without a boolean
`decision` fails closed with `503`. Outcomes are counted in
`pv_authzen_decisions_total{decision}`.

When `token_exchange_seed_file` is set, every forwarded tool call carries a
signed intent token in the `x-pv-intent-token` header. It is an EdDSA JWT
with the header `typ: av-intent+jwt`, so a backend can tell it apart from
an access token signed by the same key. Its claims are `iss` (the harness
`audience`), `aud` (the receiving backend's `name`, or `default` for
`tool_upstream_url`), `sub` (the human principal: the caller token's `sub`,
or the caller's `instance_uid` when no identity was validated), `act`
(`{"sub": <calling agent instance_uid>}`, present when an identity was
validated), `tool`, `intent`, `missions` (the ids of the missions that
applied, when any), `iat`, `exp`, and a unique `jti`. The token never
outlives an applicable mission. Backends should check `typ`, `aud`, and
`exp`, and may reject a repeated `jti`.

## Semantic judge (`[judge]`)

The semantic judge answers questions that schemas and rules cannot,
such as "do these tool arguments fit the task this agent was given?".
Each question is a named, versioned **predicate** with a fixed set of
labels. The judge returns a probability for every label; it never
decides. Policy turns the probabilities into allow, ask (hold for human
approval), or deny. The `judge` key is absent by default, and then no
tool call reaches the judge.

Where it runs: on `/v1/mcp` tool calls whose tool is listed under
`[[judge.tools]]`, after the parse and schema gates and before the
policy and budget gates. Untagged tools take the same path as before.
The judge sees the schema-validated arguments and context the operator
controls: the tool's intent, the applicable missions (ids, allowed
intents, and `task` statements), the caller's charter and delegation
depth, and refusals the harness recorded earlier in the session and
for the agents above the caller in its delegation chain (the agents of
its `parent_token` chain and the agents named in its nested `act`
claims). Only policy refusals (thresholds, WASM policies, allow lists,
the judge) of tools the operator defined (a tool with a schema, or a
judged tool) are recorded: a caller cannot plant text through a made-up
tool name, and cannot push a real refusal out of view with schema or
budget refusals, which are free to provoke. Each log keeps one entry per
kind of refusal (tool, code, predicate), and the judge sees the
refusals of the tool it is judging first. A session's refusals are
kept per agent instance, because the session id is chosen by the
caller. It never sees the prompt. A judged tool must have a schema in
`tool_schema_dir`, or the daemon refuses to start; `pvctl
config-validate` checks the `[judge]` section's structure, while the
schema and policy checks run when the daemon starts. The judge is
consulted before the session's admission lock is taken, so a slow
judge never delays a session close.

Three optional uses run in the background, off the request path:
`[judge.trace]` judges recorded tool outputs and model answers after
they are written to the audit trail, `[judge.breaker]` gives the loop
breaker a second opinion, and `[[judge.standing_rules]]` puts rules
back after compression (by exact text, without calling the judge).
These are described in the table below. Trace judging and the breaker
send output text to the judge (a tool's response or the model's
answer), never the request's prompt text.

Built-in predicates:

| Predicate | Labels | Question |
| --- | --- | --- |
| `arg_matches_task@1` | `match`, `mismatch` | Do the arguments fit the task, intent and mission? |
| `child_uses_parent_entitlement@1` | `independent`, `laundering` | Is a delegated agent using its inherited entitlement to do what an agent above it was refused? |
| `memory_write_safe@1` | `safe`, `unsafe` | Is this write to a memory or knowledge store safe to persist (governed memory writeback)? |
| `output_safe@1` | `safe`, `unsafe` | Is this recorded tool output or model answer safe, or does it carry an injected instruction or a policy violation? Used by `[judge.trace]`. |
| `loop_progress@1` | `progressing`, `looping` | Is the model's current answer progress over its previous one, or a repeat? Used by `[judge.breaker]`. |

| `[judge]` key | Default | Notes |
| --- | --- | --- |
| `mode` | required | `shadow` scores and records, and never blocks; every record says whether judge-aware policy *would* have blocked. `enforce` lets policy act on the verdicts. |
| `max_concurrency` | `16` | Judge calls in flight at once (1 to 4096, and at least the number of predicates bound to any one tool). Beyond it a judged call is not attempted and counts as *saturated*. A call that passed its deadline keeps its slot until the model actually finishes. |
| `max_concurrency_per_caller` | a quarter of `max_concurrency`, and at least the most predicates bound to one tool | Judge calls one agent instance may have in flight, counting one per predicate (a tool with three predicates takes three). It must be at least the most predicates bound to one tool. Beyond it the call fails as `saturated` (by default, refused), so one caller cannot fill the judge and make every other agent's judged calls fail. It applies to callers with a validated identity; without one (`require_identity = false`) callers cannot be told apart, and only `max_concurrency` applies. |
| `adapters` | `[]` | Judge backends (`[[judge.adapters]]`, below). |
| `tools` | required | Tools tagged for review (`[[judge.tools]]`): `tool`, `predicates` (a list of `{ id = "<predicate>", adapter = "<adapter name>" }`), and `allow_cloud` (default `false`; must be `true` to bind a cloud adapter, because the tool's arguments then leave the harness). |
| `thresholds` | `[]` | Policy thresholds (`[[judge.thresholds]]`): `predicate`, `label`, and at least one of `deny_above`, `ask_above`, `min_confidence`, written as probabilities. Comparisons are strict: `deny_above = 0.7` denies at 0.700001 and above. `ask_above` must not exceed `deny_above`. `min_confidence` asks when the most probable label is below it (default `0.6`, so a near-even verdict asks instead of being allowed; `0` turns the check off). In `enforce` mode every bound predicate needs a threshold or a policy using interface version 2, or the daemon refuses to start. |
| `on_failure` | see notes | What a failure does (`[judge.on_failure]`): `timeout`, `unavailable` (crash or unreachable), `saturated` default to `deny`; `malformed` (output that does not fit the predicate's labels or is not a probability distribution) defaults to `ask`. Each accepts `deny` or `ask`; `allow` is not accepted. A model that answers with an unpinned identity always denies. |
| `predicates` | `[]` | Operator-defined predicates (`[[judge.predicates]]`): `id` (`name@version`), `labels` (2 to 16, `[a-z0-9_]`), `positive_label` (the risky label, used by calibration), `description`. |
| `pilot` | none | `[judge.pilot]` `daily_block_cap`: in `enforce` mode, the most score-based judge blocks per tool and agent instance per UTC day (per agent, so one agent cannot use up the cap and let other agents' blocked calls through). Callers without a validated identity cannot be told apart, so they share one count: when `require_identity = false`, one of them can use up the cap for all of them. Later ones are recorded with `pilot_cap_reached` and let through. A judge failure always keeps its block, and so does any call where a judged predicate is in ask-by-default mode after the calibration drift check. The counters live in the state store, so all instances sharing it share the cap. |
| `drift` | none | `[judge.drift]`: the runtime calibration check. `state_file` (required): where the band statistics and the ask-by-default switches are saved, atomically, after every review and reset, and loaded at startup, so a switch survives restarts until an operator resets it; a file that cannot be read or parsed stops the boot. `sample_every` (default `20`): one scored verdict in this many gets a `review_id` in its record. `min_reviews_per_band` (default `30`), `tolerance` (default `0.02`), `max_pending` (default `10000`). See [Operations](OPERATIONS.md#semantic-judge). |
| `background_max_concurrency` | `8` | Judge calls in flight for trace judging, 1 to 4096; the loop breaker's second opinions have a pool of the same size of their own, so long outputs cannot crowd them out. Kept apart from `max_concurrency`, so background work never starves tool-call admission. A trace window waits for a free call within its adapter's deadline; a second opinion does not wait. A call refused for this limit is recorded with status `saturated`. |
| `trace` | none | `[judge.trace]`: judge recorded outputs after the fact, off the request path. `adapter` (required), `predicate` (default `output_safe@1`), `sources` (`["tool", "model"]` by default: tool response bodies and the model's answers; request text is never sent), `finding_above` (default `0.7`: a verdict whose risky label is above it is a finding), `allow_cloud` (required `true` with a cloud adapter), `max_output_chars` (default `16384`, at most `65536`). A tool's response is judged as the text the model reads: the keys and strings of its JSON-RPC result or error, decoded from one JSON body or from a server-sent event stream (the `data` lines of an event joined, as the standard says; a body with any line that is not an event field or comment is not taken for one), so escapes cannot hide an instruction. Any other body, including JSON a strict parser refuses (an unpaired surrogate escape, very deep nesting, a huge number), is judged whole, with its JSON strings decoded in place. The `type` and `mimeType` labels of content parts, the base64 `data` of image and audio parts and the `blob` of embedded resources are not judged when they hold no whitespace, as labels and base64 never do; text with spaces put there is judged. Line-breaking characters become spaces, and with a redacting adapter the judged text, and 256 characters past it, is redacted before it is cut; text redaction lengthens is kept, up to twice `max_output_chars` (`complete` is false if that cuts it). Decoding and redaction run off the request threads. It is judged in windows of 3,900 characters, each starting 200 characters before the previous one ends, so a boundary cannot cut a shorter instruction in two; it is a finding when any window is. A window the judge refuses as longer than it reads (a local model counts tokens) is split into two overlapping halves and judged again, down to pieces of 500 characters, so padding cannot keep an instruction from being judged. One output has at most 4 windows judged at a time and is judged within 3 of its adapter's deadlines and at most 2.5 seconds (a session's close waits for it, and has 3 seconds at shutdown); a window not judged by then counts as failed. A local adapter used here needs `max_input_tokens` of at least 2048. The event records `output_chars`, `judged_chars`, `complete` (false when the output was longer than `max_output_chars` or any window failed), `windows`, `failed_windows` and `skipped_windows` (windows not judged within the time). |
| `breaker` | none | `[judge.breaker]`: the loop breaker's second opinion. `adapter` (required), `predicate` (default `loop_progress@1`), `ambiguous_low` and `ambiguous_high` (required; the range of semantic delta where the judge decides, which must contain the breaker's `delta_epsilon`), `looping_above` (default `0.5`), `allow_cloud`. Only the model's answers (the previous and the current one) are sent, never request text. If the judge fails, the breaker keeps its own decision. The judge is not asked about a session's first answer, about a change above 1, or about an embedding that is not usable (that step always counts as no progress). The second opinion runs inside the audit worker that records the step, before the breaker decides, so a slow judge call delays that session's later audit records by up to the adapter's deadline. Other sessions keep being recorded: the worker records up to eight sessions at once in each of its shards, so only a shard whose eight session slots all wait on the judge would hold up a ninth session. The breaker's adapter must have a `deadline_ms` of at most 500, or the daemon refuses to start; define a separate adapter entry for the breaker if the tool calls use a slower one. After 3 failed second opinions in a row, the breaker stops asking for 30 seconds and decides alone, so a judge outage does not cost every ambiguous step a full deadline. Each of the two answers is cut to 1,900 characters, after redaction with a redacting adapter; a local adapter used here needs `max_input_tokens` of at least 2048. |
| `standing_rules` | `[]` | `[[judge.standing_rules]]` with `id` and `text`: rules an agent must keep in view. When compression changes a request and the request carried a rule's exact text before compression but not after, the rule is added back as a system message, right after the leading system messages, and the token count is recomputed before any budget is charged. The compression record lists the re-pinned ids in `repinned_rules`. This check is by exact text and does not call the judge, so the chat path is not slowed. It replaces the build specification's "one predicate per standing rule" because compression never rewrites text: it keeps a message as it is, replaces a whole message with a stub, or removes spaces from JSON in tool and assistant messages. A rule whose exact text is gone was therefore cut, and a judge would add delay and possible error without catching more. The check relies on the application sending each rule with exactly the configured text. |
| `record_inputs` | `false` | Keep in each judged call's record (`payload.judge.inputs`) what the judge was asked: the tool, the validated arguments as JSON text, and the context. `pvctl judge-export` turns such records into a labelled set. The arguments and mission tasks then reach the audit stream, so turn it on only where that is acceptable. |

| `[[judge.adapters]]` key | Default | Notes |
| --- | --- | --- |
| `name` | required | Referenced by `[[judge.tools]]` bindings. |
| `kind` | required | `local` (an ONNX sequence classifier run in-process; needs the `onnx` cargo feature), `cloud` (an HTTP endpoint speaking the `proofvisor.judge.v1` contract), or `typesafe` (TypeSafe's Jev model through its System One API; see below). |
| `deadline_ms` | `200` local, `1000` cloud | Hard per-call deadline, 1 to 30 000 ms. Past it the call is a *timeout*. Judge time is recorded as `judge_us`, separate from the sandbox's `decision_us`. |
| `model_name`, `model_version`, `weights_sha256` | required | The model pin. For `local`, `weights_sha256` must be the SHA-256 of the `.onnx` file: the daemon hashes the bytes it loads and refuses to start on a mismatch. For `cloud`, the endpoint must report exactly this pin in every answer. For `typesafe`, `model_version` must be a fixed release such as `jev-1.14.0` (the aliases `jev-latest` and `jev-preview` are refused), and `weights_sha256` may be left out: it is derived from the version name, because TypeSafe publishes no weight hash. |
| `model_path`, `tokenizer_path`, `tokenizer_sha256` | local only | The model, its Hugging Face `tokenizer.json`, and the tokenizer's SHA-256 (checked the same way). |
| `output_labels` | local only | The label of each output logit, in output order; must be exactly the labels of every predicate bound to the adapter. |
| `max_input_tokens` | `512` (local) | A longer input is not scored: it fails as `malformed`. |
| `endpoint` | cloud: required; typesafe: `https://api.typesafe.ai/v1/systemone` | `https://…`, or `http://` to a loopback address only. Redirects are not followed. |
| `bearer_file` | none (cloud); required (typesafe) | Owner-only file holding a bearer token for the endpoint (for `typesafe`, the API key). |
| `redact` | `true` (cloud) | Run the harness redaction engine (`redaction_patterns`, `redaction_paths`, and the built-in patterns) over the arguments and context before they are sent. Arguments and recorded outputs are redacted like tool arguments in the audit trail, whole numbers and object keys included. When the harness has no redaction configured, the built-in patterns alone are applied. |

A local model reads the request rendered as text in a fixed, versioned
layout (template version 2, `pv_judge::render::render_request`), so it
must be trained on that layout. The operator's context (intent, task,
missions, refusals) comes first and the arguments last. A request the
model cannot read in full is not judged: when the rendered arguments
exceed 8192 characters, the tasks of the applicable missions together
exceed 8192 characters (the daemon warns at startup when the tasks of
all missions together are longer), or the whole text exceeds
`max_input_tokens`,
the call fails as `malformed` (by default, held for approval). Scoring
only the beginning would let a caller hide the risky part of a call
behind padding, because the argument keys are sorted. Give judged tools
a schema with `maxLength` limits so legitimate calls fit. A cloud judge
receives the full arguments.

A cloud judge is a second path by which data leaves the harness: without
the judge, the harness sends data out only to the upstream model
provider and the configured tool backend. Tool arguments go to a cloud
judge only for tools whose `[[judge.tools]]` entry sets `allow_cloud =
true`; outputs and model answers go to it only when `[judge.trace]` or
`[judge.breaker]` sets `allow_cloud = true`. Redaction (`redact`, on by
default) runs before each request is sent. List these settings for
enterprise buyers when describing where their data goes. The cloud contract is documented in
`crates/pv-judge/src/cloud.rs`; a vendor is integrated by a small
translator in front of its API, or by speaking the contract directly.

**TypeSafe (Jev).** `kind = "typesafe"` calls TypeSafe's System One API
directly, one request per predicate. As of October 2026 TypeSafe offers
no service-level agreement and no known on-premises option, and its
latency and pricing are not confirmed: do not promise it to customers. It was built from TypeSafe's
published reference and tested against a local stand-in that speaks
that format, not against the live service; a test runs against the live
API when `PV_TYPESAFE_API_KEY_FILE` names a file holding a key.

- What is sent: the request rendered with the local classifier's
  template (version 2) after redaction, so the operator's context comes
  first and the arguments last. A call whose rendered arguments, or the
  tasks of whose missions together, exceed 8192 characters is not sent;
  it fails as `malformed`. One `choice`
  question asks the predicate's question, with its labels as the
  options. The prompt is never sent, and no header that widens what
  TypeSafe accepts (images, long context) is set.
- What is accepted: the answer's probabilities over exactly the
  predicate's labels, from exactly the pinned release. Any other release
  is a model mismatch, and missing or extra labels are a malformed
  answer.
- The pin covers the version name only. TypeSafe reports in each answer
  the release that produced it, but publishes no weight hash; a change
  of weights under the same version name cannot be detected.
- Errors (401 key, 429 rate limit, 529 overload, any other non-200) make
  the judge unavailable for that call, and policy fails closed. Nothing
  is retried; the adapter's deadline bounds each call.
- TypeSafe offers no service-level agreement. Measure its latency and
  accuracy on your own labelled set with `pvctl judge-calibrate` before
  enforcing, and set `deadline_ms` from that.
- Data: TypeSafe's legal page refers to a data processing agreement and
  a stated commitment not to train on customer data, and offers zero
  data retention to enterprise customers only. The same per-tool
  `allow_cloud` opt-in applies, and verdicts record the adapter as
  `cloud`.

```toml
[[judge.adapters]]
name = "jev"
kind = "typesafe"
model_name = "jev"
model_version = "jev-1.14.0"
bearer_file = "/etc/proofvisor/typesafe.key"
deadline_ms = 1000
```

Refusals use the JSON-RPC error shape of every other policy refusal
(HTTP 403, `error.code` -32001), with `error.data.code`:

| Code | Meaning |
| --- | --- |
| `JUDGE_DENIED` | A verdict crossed a deny threshold. |
| `APPROVAL_REQUIRED` | Policy holds the call for human approval: a verdict fell in an ask band, the model was not confident enough, its output was malformed, the drift gate is tripped, or a version 2 policy returned `2`. Nothing ran. There is no approval queue in the harness; the agent or its host decides how to ask a person. |
| `JUDGE_UNAVAILABLE` | The judge produced no usable verdict (timeout, crash, saturation, unpinned model) and policy failed closed. |

Adapters used by `[judge.trace]` or `[judge.breaker]` must have a
deadline of at most 2500 ms: a pending background verdict holds the
session's close (so it is signed with the session), and at shutdown each
close has 3 seconds.

**Findings (`agent.judge` events).** Trace verdicts (`kind: "trace"`,
with `source`, `tool`, `finding`, `risk_ppm` and the verdict), the
breaker's second opinions (`kind: "breaker"`, with `delta_ppm`, the
range, and `looping`), and shadow-mode would-be blocks (`kind: "shadow"`,
with the admission record) are published on the `agent.judge` topic. Each
is also an ATIF step, so a session's receipt covers it whether the
session is signed (event chain) or unsigned (trajectory digest). A trace
finding has OCSF severity 4 (high), a shadow would-be block 3 (medium),
and the others 1 (informational). When the audit queue is full, an
event waits up to 2 seconds for room (a session's close waits with it);
one that still finds none marks its session's record as incomplete, as
a lost response capture does. When
`[judge]` is set, an embedded Bridge created before this topic existed
gains it at startup; with your own `bridge_manifest_path`, add an
`agent.judge` topic to that file, or the daemon refuses to start and
names the file.

Judge refusals name the predicate in `error.data.predicate_id` and the
policy `judge.thresholds` in the audit record. A refusal by a policy
using interface version 2, which reads the verdicts, lists the judged
predicates in `error.data.predicate_ids` (and names the predicate in
`error.data.predicate_id` when there is only one).

The record: every judged call's `agent.tool_call` event payload carries
a `judge` object, and the ATIF tool call carries the same object in
`extra.judge`. It holds `mode`, `judge_us`, one entry per predicate in
`verdicts` (adapter, adapter kind, pinned model, `status` — `scored` or
the failure class — the full distribution as integer parts per million,
latency, and `review_id` when sampled), the threshold `decision`,
`decision_predicate`, `cause` (for example `{"kind": "threshold",
"label": "mismatch", "ppm": 820000, "threshold_ppm": 700000}`),
`enforced`, `would_block`, `policy_decision` and `policy` (what the
whole policy stage decided with the verdicts, including a policy using
interface version 2, and which policy decided it), and, when they apply,
`pilot_cap_reached`, `drift_tripped` and, with `record_inputs`, `inputs`. Probabilities are integers because the event chain is
hashed in canonical JSON, where floats are a known source of
disagreement between implementations. A signed workflow's receipt signs
the event chain's head, and a retroactive receipt signs the ATIF file's
digest, so the verdicts are covered by whichever signature the session
gets; the receipt format itself is unchanged.

```toml
[judge]
mode = "shadow"

[[judge.adapters]]
name = "local-args"
kind = "local"
model_path = "/models/judge-args.onnx"
tokenizer_path = "/models/tokenizer.json"
tokenizer_sha256 = "<sha256 of tokenizer.json>"
output_labels = ["match", "mismatch"]
model_name = "judge-args"
model_version = "2026-11-01"
weights_sha256 = "<sha256 of judge-args.onnx>"

[[judge.tools]]
tool = "refund_order"
predicates = [{ id = "arg_matches_task@1", adapter = "local-args" }]

[[judge.thresholds]]
predicate = "arg_matches_task@1"
label = "mismatch"
deny_above = 0.7
ask_above = 0.3
```

## Backend routing

| Key | Default | Notes |
| --- | --- | --- |
| `backends` | `[]` | Per-backend MCP server routing (TOML `[[backends]]`). Each entry has `name`, `url`, `auth`, `tools`, and `transport`. An entry with an empty `tools` list is the default for unmapped tools (at most one). When `backends` is empty, `tool_upstream_url` becomes an implicit backend named `default`, and it carries the `tool_upstream_bearer_env` / `tool_upstream_bearer_file` credential. |

| Key | Default | Notes |
| --- | --- | --- |
| `require_private_backends` | `false` | Refuse to connect to a tool backend (every `[[backends]]` URL and `tool_upstream_url`) whose address is not private: loopback, RFC 1918, shared address space (RFC 6598), link-local, or IPv6 unique-local and link-local. Tool traffic uses its own HTTP client, whose resolver checks every address a backend host name resolves to on every new connection, and refuses the host if any address is public, so a DNS change after boot cannot send tool calls to the internet. IP literals are checked at boot. The LLM upstream and the AuthZEN PDP are not affected. Pair it with the network policies in `deploy/kubernetes/network-policies.yaml` or the internal routes and network policies in `deploy/cloudfoundry/`, which stop anything but the gateway from reaching a backend. |

A backend may not be named like `audience`: tokens the gateway signs for a
backend carry the backend's name as their audience, so that name must never
be the gateway's own.

Each backend's `transport` is `mcp` (the default) or `json_rpc`. On `mcp`,
the gateway is a conforming Streamable HTTP client: it opens one backend
session per audited session with `initialize` and
`notifications/initialized`, sends `Accept: application/json,
text/event-stream`, `MCP-Session-Id`, and `MCP-Protocol-Version` on every
request, accepts either a JSON reply or an SSE stream (it stops reading at
the matching response and resumes an early-ended stream with `GET` and
`Last-Event-ID`), answers a backend's `ping` requests and refuses its other
requests with "method not found" (the gateway declares no client
capabilities), and after a session-expiry `404` starts a new backend
session and retries once. A handshake failure is treated like a connect
failure: the call was not delivered, its budget is refunded, and it can be
retried. On `json_rpc`, each call is one plain POST.

A tool that maps to no backend, when there is no default backend, is sent
to `tool_upstream_url` with its bearer if that is set. Otherwise the call
is decided (allowed or denied, and audited) but not forwarded. The
caller's own `Authorization` header is never forwarded to a backend unless
that backend uses `auth = "forward_token"`.

### Backend `auth` modes

Each `[[backends]]` entry accepts an `auth` field selecting how the harness authenticates
to that MCP server:

| `auth` value | Description |
| --- | --- |
| `"none"` (default) | No credential is sent. |
| `{ static_env = "VAR" }` | Bearer token read from the named environment variable at boot. Surrounding whitespace is trimmed; an unset or empty variable refuses boot. |
| `{ static_file = "path" }` | Bearer token read from a file at boot (owner-only permissions and no symlinks, enforced on Unix). Surrounding whitespace is trimmed; an empty file refuses boot. |
| `"exchange"` | On-the-fly RFC 8693 token exchange for every call: the caller's NHI bearer is exchanged for a short-lived token whose `aud` is this backend's `name` and whose only scope is `tool:<called tool>`. The caller's token must hold that scope (directly or through a wildcard such as `tool:*`); otherwise the call is refused with `403` before anything reaches the backend or charges the budget. `sub` stays the human principal, and `azp` and `act.sub` carry the caller's `instance_uid`. Requires `require_identity = true` and `token_exchange_seed_file`; boot refuses the combination otherwise. |
| `"forward_token"` | The caller's own validated bearer token is forwarded to this backend, and to no other. Requires `require_identity = true`. The backend receives a token whose audience is the gateway, so it could replay that token against the gateway: use this mode only for a backend that must see the original identity-provider token and that you trust as much as the gateway. Prefer `"exchange"` otherwise. |

Static credentials are marked as sensitive header values, so they are kept
out of debug output and HTTP/2 header compression tables.

## Tenant observability and redaction

| Key | Default | Notes |
| --- | --- | --- |
| `otel_tenant_endpoint` | none | Tenant OTLP/HTTP trace endpoint (including `/v1/traces`), exported alongside any operational collector. Requires the `otel` build feature. Operational authentication headers are not forwarded to this endpoint. |
| `otel_tenant_auth_file` | none | Bearer token file for the tenant OTEL endpoint (owner-only permissions enforced). |
| `otel_tenant_content` | `redacted` | What the tenant endpoint receives beyond request metadata spans. `redacted` also exports every audited step as an OpenTelemetry GenAI span with its content, after redaction (see below). `off` exports metadata spans only. |
| `redaction_patterns` | `[]` (compiled-in default: no redaction); every shipped config, and the config `pvctl init` / `pvctl setup` write, set the recommended list | A list of raw regular expressions (not pattern names) for sensitive-data stripping, applied to event payloads and ATIF step fields before the journal write. Whenever this list or `redaction_paths` is non-empty, the built-in set is always included as well: `Bearer` tokens, `sk-`/`key-` style API keys, email addresses, Luhn-valid card numbers, US SSNs, and public IPv4 addresses. The shipped list adds AWS access key IDs, GitHub tokens, Google API keys, Slack tokens, and bare JWTs; it is the constant `pv_harness::config::RECOMMENDED_REDACTION_PATTERNS`. |
| `redaction_paths` | `[]` | JSON pointer paths to always redact in event payloads and their ATIF observation copies. Configuring paths also enables the built-in patterns. With `[judge.trace]` on a redacting remote adapter, `/source` and `/output` (and paths under them) are refused, with `[judge.breaker]` on one, `/previous` and `/current`, and with either, the empty path (the whole value): they would hide from the judge every text it reads there. |

Redaction changes only the copies ProofVisor persists for audit — the
journal, the ATIF trajectory, the OCSF events, the exports, and what
`pvctl console-sync` uploads. The request forwarded to the model and the
response returned to the client are never altered by redaction.

The compiled-in default is no redaction: a config file that simply omits
`redaction_patterns` has no redaction at all. Every shipped configuration
file (`config/harness.example.toml`, `harness.docker.toml`,
`harness.container.toml`), the config written by `pvctl init` and `pvctl
setup`, and the Cloud Foundry and Kubernetes manifests under `deploy/`
carry the same `redaction_patterns` block, so a deployment that starts
from any of them redacts out of the box with the built-in set plus the
recommended additions. To disable redaction deliberately, set
`redaction_patterns = []` and leave `redaction_paths` unset; either one
being non-empty turns the engine (and the built-in set) back on.

### Full-content tenant telemetry

With `otel_tenant_endpoint` set and `otel_tenant_content = "redacted"` (the
default), every audited step is exported to the tenant collector as a span
that follows the OpenTelemetry
[GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai):

- A chat call becomes one `chat {model}` span of kind `CLIENT`, from the
  request to the response, with `gen_ai.operation.name = "chat"`,
  `gen_ai.provider.name` (the `provider` setting), `gen_ai.request.model`,
  `gen_ai.response.model`, `gen_ai.usage.input_tokens`,
  `gen_ai.usage.output_tokens`, `gen_ai.response.finish_reasons`,
  `gen_ai.input.messages` (the new input message of this turn), and
  `gen_ai.output.messages` (the output text, reasoning, and requested tool
  calls).
- A tool authorization becomes an `execute_tool {tool}` span with
  `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.call.arguments`,
  and the gateway's verdict (`proofvisor.tool.allowed`, `denial_code`,
  `policy`, `stage`, `reason`). A tool completion becomes an
  `execute_tool.result` span with `gen_ai.tool.call.result`.
- Every other audit event becomes an `proofvisor.{class}` span that carries
  the event as JSON.

Every span carries `gen_ai.conversation.id` (the session id, so a whole
conversation can be reassembled), `gen_ai.agent.id` (the agent's
`instance_uid`), `gen_ai.agent.name` (its charter), and the audit event
uid. Content is redacted before export with the built-in patterns plus
`redaction_patterns` and `redaction_paths`, even when journal redaction is
not configured. Each content attribute is capped at 256 KiB; a longer value
is cut and ends with a marker that states how many bytes were removed.

Content spans use a tracer provider whose only exporter is the tenant
endpoint, so the operational collector (`OTEL_EXPORTER_OTLP_*`) receives
metadata spans only and never content. Both are flushed at shutdown.
Tenant export requires the `otel` build feature.

## Performance

| Key | Default | Notes |
| --- | --- | --- |
| `compression_enabled` | `true` | Context-compression pipeline on the chat path. |
| `worker_channel_capacity` | `32768` | Bounded audit-worker channel; overflow is counted (`pv_events_dropped_total`), never blocking. |
| `mcp_concurrency` | `128` | Max concurrent `mcp_call_inner` executions. Each admitted call can buffer up to `MAX_TOOL_RESPONSE_BYTES = 16 MiB` in `read_limited_tool_response`, so this cap bounds worst-case MCP resident memory (default: ~2 GiB). Refused admissions increment `pv_mcp_admission_refusals_total` and respond `503` with `Retry-After: 1` — a server-side capacity signal (mirrors the breaker-open discipline). |
| `strict_stage_budget` | `false` | Strict per-stage latency assertions (`PV_STRICT_BUDGET=1` also enables). Development diagnostics, not a production knob. |

## Development-only knobs

The following flags are safe **only** for local development and are
refused by `validate()` in combination with production settings.

| Combination | Refused with |
| --- | --- |
| `listen = "0.0.0.0:*"` + `require_identity = false` + `allow_wildcard_bind = false` | Explicit boot refusal. |
| `principal_budget = {…}` + `require_identity = false` + `allow_anonymous_principal_budget = false` | Explicit boot refusal. |
| Wildcard `listen` + `dashboard_enabled = true` + `allow_wildcard_bind = false` (also with `require_identity = true`) | Explicit boot refusal (the dashboard has no identity check of its own). |
| `upstream_authorization_passthrough = true` + `require_identity = true` | Explicit boot refusal (the client's header carries the identity token, not an upstream key). |
| `upstream_authorization_passthrough = true` + `upstream_api_key_env` or `upstream_api_key_file` | Explicit boot refusal (choose one upstream auth mode). |
| `ignore_client_authorization = true` + `require_identity = true` | Explicit boot refusal (the validator must see the header). |
| `ignore_client_authorization = true` + `upstream_authorization_passthrough = true` | Explicit boot refusal (cannot both discard and forward). |

If `validate()` rejects your config, the error message names the exact
key combination — do NOT try to bypass it; the guard exists to stop the
"I forgot to turn on identity and pushed a wildcard bind" incident.
