# ProofVisor — what exists today

Dated 2026-10-31. Every item below was exercised on this date on a
laptop against the local `integration/all` branch (the rename branch
plus the native-provider, policy-push, SCIM and billing, and interop
work): the Rust test suites, the API and console test suites, the
browser drills, the real-binary drills and the interop tests all
passed. The numbers are in the
last section. Items that are planned, partial or demo-only are listed
separately so that nothing here overstates what a customer gets.

## 1. The proxy (`proofvisord`)

ProofVisor sits between an AI agent and its model provider. The agent
changes one line, the API base URL, and keeps using the OpenAI
chat-completions format.

- **Drop-in for OpenAI, Anthropic and Gemini.** The daemon serves
  `POST /v1/chat/completions`. OpenAI-compatible upstreams receive the
  request unchanged. With `provider = "anthropic"` or `"gemini"` the
  daemon translates the request into the vendor's native API (Anthropic
  Messages, Gemini `generateContent`) and translates the answer back,
  including streaming, tool calls, stop reasons, usage and errors.
  `n > 1` works with every provider (Anthropic gets one request per
  choice). Sixteen presets exist in `pvctl init` (OpenAI, Azure,
  Anthropic and Gemini natively, Groq, Mistral, OpenRouter, Together,
  DeepSeek, xAI, Ollama, LM Studio, vLLM, llama.cpp, LiteLLM, custom).
- **Streaming passes through.** Server-sent events are relayed frame by
  frame; `include_usage` is honoured; a failing first frame yields a
  clean error.
- **The proxy holds the provider key.** Clients never see it. Keys come
  from an environment variable or a permission-restricted file.
  Provider key headers are stripped from responses.
- **Hard caps enforced before the call leaves.** Total tool calls,
  per-tool calls, payout amount in micro-dollars (`max_payout_usd_micros`
  on a configurable payout field) and prompt tokens. A refused call
  returns HTTP 403 and the provider is never contacted. Budgets can be
  pinned to the caller's identity so rotating session ids does not reset
  them.
- **Loop breaker.** Consecutive steps are compared semantically (hashed
  n-grams by default, optional ONNX MiniLM embeddings, optional Qdrant
  storage); a near-repeat run trips a circuit breaker.
- **Tool-call sandbox.** Every MCP tool call is parsed strictly, checked
  against a JSON Schema for that tool, and run through WebAssembly policy
  modules with fuel and memory limits. Unknown tools can be refused.
  Consequential tools (database writes, payouts, merges, deploys) can be
  required to run inside a signed session.
- **Context compression.** Long histories are pruned with auditable,
  tamper-evident stubs; off with one setting.
- **Redaction of persisted evidence.** API keys, bearer tokens, emails,
  card numbers, US social security numbers, public IP addresses, plus
  AWS, GitHub, Google and Slack credentials and bare JWTs are redacted
  from the stored audit copies (events, trajectories, receipts). This is
  on in every shipped configuration and in configurations written by
  `pvctl init` and `pvctl setup`. It does not alter the traffic sent to
  the model.
- **Crash safety.** Durable intent files, quarantine of incomplete
  sessions (never silently promoted to a full receipt), no re-execution
  after a crash, and a lock that stops a second daemon on the same spool.
- **Health and metrics.** `/health`, `/livez`, `/readyz` and Prometheus
  `/metrics`. An optional read-only operator dashboard can be enabled.
- **Nothing phones home.** Every artifact is a plain file. Sending
  evidence to the hosted console is a separate, opt-in command.

## 2. Evidence: signed receipts and trajectories

- **Ed25519 session receipt.** When a session closes, the daemon signs a
  receipt that commits to the whole event chain, cost, tool-call counts
  and stop reason. Receipts verify offline with the public key. All
  shipped configurations sign by default.
- **Retroactive receipt** for an unsigned trajectory via
  `POST /v1/sessions/{id}/promote` or `pvctl session-promote`.
- **OCSF event stream.** Every event is an OCSF `ai_operation` record for
  SIEM ingestion.
- **ATIF trajectory files** (Harbor ATIF v1.7) that pass the Harbor
  validator.
- **Event bus choices:** embedded file-backed broker (default),
  Kafka/Redpanda with TLS and SASL, NATS JetStream with TLS. S3-compatible
  cold storage behind a build feature.
- **Three verifiers agree:** `pvctl receipt-verify` (Rust), a Node
  script, and the browser page at proofvisor.com/verify (Web Crypto, no
  network). The browser page shows "trusted" only for keys it knows; for
  a customer's own deployment it shows "internally consistent" and tells
  the auditor to compare the key fingerprint with the deployment page in
  the console.

## 3. Identity, tokens and authorization

- **Agent identity tokens** (JWT, EdDSA or HS256) with a 15-minute
  maximum lifetime, bounded delegation chains and scope narrowing.
- **RFC 8693 token exchange**, **RFC 7009 revocation**, **RFC 7662
  introspection**, and operator revocation by token, by agent instance or
  by issuer, shared across replicas through Redis.
- **Per-backend tool credentials** so the caller's token never reaches a
  backend; modes `none`, `static_env`, `static_file`, `exchange`,
  `forward_token`.
- **MCP gateway** (Streamable HTTP, `tools/list` aggregation, per-backend
  routes) with a private-network check for backends.
- **Intent tokens, missions and an optional external AuthZEN policy
  decision point.**
- **Cloud Foundry workload identity** (RFC 7523), `pvctl sidecar` and a
  buildpack.

## 4. The CLI (`pvctl`)

Twenty-one subcommands, none of them stubs: guided `setup`, `init` with
presets, `doctor`, `health`, `start`, `sidecar`, `keygen`, `pubkey`,
`receipt-locate`, `spool-prune`, `receipt-verify`, `atif-validate`,
`manifest-validate`, `bridge-provision`, `event-tail`,
`session-promote`, `token-revoke`, `instance-revoke`, `config-validate`,
`console-sync` (uploads evidence to the hosted console, with a watch
mode) and `loadgen`.

## 5. The hosted console (proofvisor.com/app and api.proofvisor.com)

A real multi-tenant web application (Node, Fastify, Prisma, Postgres)
with a static single-page console. The console also runs in a mock mode
with demonstration data, which is what the public site shows by default.

- **Accounts:** signup, login, logout, sign out everywhere, organisation
  switching, password and email change with confirmation, profile,
  data export (NDJSON), account deletion with a typed confirmation,
  password reset.
- **Second factor with passkeys (WebAuthn)** and administrator reset.
- **Single sign-on:** Google, Microsoft and generic OIDC; a SAML 2.0
  service provider with discovery by email domain. Tested against
  scripted identity-provider fixtures, not yet against a customer's IdP.
- **Organisation administration:** rename, retention windows with a
  manual sweep, IP allow-list (refuses to lock out the current user),
  members with roles, invitations.
- **Deployments and ingest tokens.** Tokens are shown once and can be
  rotated; new tokens carry the `pv_live_` prefix so secret scanners
  recognise them. Each deployment shows sessions and spend over the
  last 24 hours and the exact environment block the daemon needs
  (`PV_CONSOLE_URL`, `PV_CONSOLE_DEPLOYMENT`, `PV_CONSOLE_TOKEN`) for
  `pvctl console-sync --watch`.
- **API keys** with a role (owner, admin, member), shown once.
- **Policies** as an inventory with hit and block counts per policy and
  the sessions that fired each one. Daemons enforce their local policy
  files; the console does not push policies to daemons yet.
- **Webhooks** with HMAC signatures, SSRF guards, retries and a delivery
  log; Slack, Teams and Discord payloads are formatted automatically.
  Emitted events: `policy.block`, `session.blocked`, `member.invited`,
  `apikey.created` and a test event.
- **Ingest** of public keys (pinned on first contact), sessions, events
  and receipts. Receipt signatures are verified server-side before they
  are accepted.
- **Reading:** overview with time series, cursor-paginated sessions,
  session detail with event stream and waterfall, receipts, audit log
  with CSV export, and live updates over server-sent events.
- **Security posture:** Argon2id passwords, HttpOnly cookies, uniform
  login timing, rate limits, CSRF checks, a strict content security
  policy, problem+json errors.
- **Operations:** health and readiness endpoints, IP-gated Prometheus
  metrics, encrypted nightly database dumps with a restore drill. The
  API runs on Render; the site and console are served by GitHub Pages.
- **Console quality:** command palette, keyboard shortcuts, dark and
  light themes, zero serious accessibility findings, works on phone,
  tablet and the three browser engines.

## 6. Added on 2026-10-31

- **Policy push from the console to daemons.** Budget, allowlist,
  argument-schema and token-rate policies written in the console reach
  daemons through `pvctl console-sync --watch --pull-policies`. Each
  daemon applies the bundle on top of its local config (a pushed
  policy can only tighten it), survives restarts with it, reports what
  it actually enforces, and the console shows "Enforced by N of M
  daemons". Refusals name the console policy.
- **SCIM 2.0 provisioning** for Okta, Entra ID and other identity
  providers: users and groups, deactivation, role mapping by group, the
  last owner protected.
- **Billing with Stripe**: checkout, customer portal, webhooks, and plan
  limits. Limits are off unless the operator turns them on.
- **Receipt trust anchor**: `/.well-known/receipt-keys.json`, and a
  public per-deployment key endpoint, so a shared verify link says
  "signed by the key the console pinned for this deployment".
- **Live-mode guided tour, onboarding checklist and "Simulate an
  attack"**, with demo rows labelled and removable.
- **Interoperability verified** against a third-party MCP server and the
  official MCP SDK client, Keycloak 26.8.1 (OIDC and SAML login in a
  real browser), and two public AuthZEN interop decision servers.
- **Windows**: the daemon and CLI compile for Windows x64, and CI and
  the release workflow build them there.

## 7. Not yet, partial, or needs a decision

- **Billing is built but not switched on.** No Stripe account is
  connected to the hosted API, and plan limits are off by default. The
  prices and the free-plan limits (2 deployments, 3 members, no SAML or
  SCIM) were proposed during development and need a business decision
  before anyone turns them on; they contradict today's "every
  governance feature on Free" wording.
- **Guardrail and transform policies** document intent in the console;
  daemons do not enforce them.
- **Windows** has not been run on Windows hardware yet, and its CI job
  runs only after a push, so it is a Tier-2 platform.
- **Release state.** The latest release is the pre-release
  `v0.1.0-rc.5`; nothing is on crates.io yet. Publishing needs explicit
  approval.
- **Still tested with stand-ins only:** a real Cloud Foundry
  foundation, cloud object storage, and identity providers other than
  Keycloak (for example Okta and Entra ID).
- **None of this is deployed.** All work above is on local branches; the
  hosted console and API still run the previous version.

## 8. Verification record for 2026-10-31

All on the merged `integration/all` branch.

| Suite | Result |
|---|---|
| Rust workspace, all features | 1,827 tests passed, 0 failed |
| `cargo fmt`, `cargo clippy -D warnings`, `cargo deny` advisories, schema check | clean |
| Windows x64 compile check (daemon and CLI, all targets) | no errors |
| Provider contracts with the real daemon (OpenAI, Anthropic, Gemini, `n = 2`) | 14 of 14 |
| Policy push end to end with the real API, daemon and pvctl | 32 checks passed |
| Live pillars (identity, exchange, revocation, receipts, end to end) | 84 checks passed |
| API unit and recovery tests, including SCIM and billing (`npm test`) | 82 passed |
| API smoke suite | passed |
| API contract suite (`ci/e2e.mjs`) | 141 of 141 |
| Browser end-to-end against the real API (live tour, checklist, simulated attack) | all passed |
| Database drill battery (17 drills, including policy push and the public receipt key) | 17 of 17 |
| `/verify` page drill (including the deployment pin) | 16 of 16 |
| Receipt download and offline verification | 8 of 8 |
| Interactive console drill | 35 of 35 |
| Console injection drill | 207 checks passed |
| Mobile, accessibility, full investor flow | all passed |
| Third-party MCP server / official MCP SDK client | 14 / 12 checks passed |
| Keycloak 26.8.1 OIDC and SAML login | 22 checks passed |
| AuthZEN public interop PDPs (Cerbos, Aserto Topaz) | allow and deny as expected |
