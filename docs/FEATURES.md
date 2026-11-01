# ProofVisor — what exists today

Dated 2026-10-31, rechecked on 2026-11-01. Every item below was
exercised on a laptop against the local `integration/all` branch (the rename branch
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
  the sessions that fired each one. Budget, allow/deny-list, argument
  schema and token-rate policies are pushed to daemons (`pvctl
  console-sync --pull-policies`), which can only tighten their local
  configuration and report back whether each policy was applied;
  guardrail and transform policies stay documentation only (see
  section 7).
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
  daemons through `pvctl console-sync --watch --pull-policies` together
  with `policy_bundle_file` in the daemon config (the deployment page
  shows both). Each
  daemon applies the bundle on top of its local config (a pushed
  policy can only tighten it), survives restarts with it, reports what
  it actually enforces, and the console shows "Enforced by N of M
  daemons" (N counts the daemons that applied that policy, not every
  daemon on the current bundle). Refusals name the console policy,
  for tool calls and for chat requests a pushed token-rate or budget
  rule refuses, and the console attributes each refusal to the policy
  in its hit and block counts.
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
  real browser), the daemon's AuthZEN request format against two public
  interop decision servers, and the daemon's own AuthZEN client against
  the public Topaz server.
- **Windows**: the daemon and CLI compile for Windows x64, and CI and
  the release workflow build them there.
- **The rename keeps existing deployments working.** Signed and hashed
  labels (receipt tag, chain genesis, journal and outbox labels, token
  types and claims, the default audience) keep their pre-rename bytes,
  so receipts and state written by `agentvisord` verify and load. The
  API accepts `av_srv_` keys and the old `X-AV-*` headers, webhooks and
  Kafka records carry both header names, `pvctl console-sync` sends
  both deployment header names (so a new `pvctl` uploads to a console
  that still runs the pre-rename API), and the daemon and `pvctl`
  adopt `AV_*` variables and find `agentvisor.toml` and `~/.agentvisor/`.
  A database written by the pre-rename API upgrades in place: the four
  new migrations ran on a copy holding its accounts, deployment,
  pinned key, sessions, receipt, `av_srv_` key, policy, webhook and
  invitation, and every one of them still worked through the new API.
  `CHANGELOG.md` lists what still changes (one sign-out on deploy,
  metric, tracing, OCSF and `/health` names).
- **Second security pass** on the code added here: SCIM can re-address
  or re-attach only accounts its own workspace created and clears the
  verified mark when it changes an email; daemon authentication bounds
  argon2 work per address and in total; demo deployments refuse daemon
  traffic; the Kafka client no longer decodes zstd (four RustSec
  advisories); a pushed schema policy can no longer make the daemon
  fetch a URL or read a local file through an external `$ref` (the
  console refuses such schemas when they are saved, and the daemon
  refuses them again when it compiles them).

## 7. Not yet, partial, or needs a decision

- **Billing is built but not switched on.** No Stripe account is
  connected to the hosted API, and plan limits are off by default. The
  prices and the free-plan limits (2 deployments, 3 members, no SAML or
  SCIM) were proposed during development and need a business decision
  before anyone turns them on; they contradict today's "every
  governance feature on Free" wording.
- **Guardrail and transform policies** document intent in the console;
  daemons do not enforce them.
- **A pushed token budget that a streaming completion overflows
  mid-stream** is refused with the limit name but without the console
  policy's name; only the request-time check (prompt tokens, where a
  pushed cap normally binds) names the policy.
- **Budget policies written before this release have no spec.** The
  pre-rename console stored budget policies as text only, so a daemon
  reports such a policy as unsupported ("budget policy has no JSON
  spec") until an administrator re-saves it from a template.
- **Windows** has not been run on Windows hardware yet, and its CI job
  runs only after a push, so it is a Tier-2 platform.
- **Release state.** The latest release is the pre-release
  `v0.1.0-rc.5`; nothing is on crates.io yet. Publishing needs explicit
  approval.
- **Native Anthropic and Gemini have not reached the real APIs yet.**
  They were tested against local servers that speak each vendor's wire
  format as documented. A run against api.anthropic.com and the Gemini
  API needs real keys and makes a few paid requests
  (`scripts/provider-smoke.py --allow-live-request --provider anthropic`
  or `gemini`).
- **AuthZEN resource modelling.** The daemon's own AuthZEN client was
  run against the public Topaz interop server and decided correctly
  (allow and deny). The daemon always describes the resource as
  `{"type": "tool", "id": <tool name>}`, so a decision server's policies
  must model resources of type `tool`; the Cerbos demo policy, which
  only models `todo` resources, denies every such request. A per-tool
  resource mapping does not exist yet.
- **Still tested with stand-ins only:** a real Cloud Foundry
  foundation, cloud object storage, and identity providers other than
  Keycloak (for example Okta and Entra ID).
- **Deployed on 2026-11-01.** Pull request ProofVisorAI/proofvisor#396
  is merged. The site is served from GitHub Pages at
  `https://proofvisor.com` (own certificate, HTTP and `www` redirect to
  it) and the API runs on Render at `https://api.proofvisor.com` (the
  old `api.agentvisorai.me` still answers, same service). The old
  domain `agentvisorai.me` forwards (301, front page only) to the new
  one. Render's Auto-Deploy for this service is **off**: a merge to
  `main` does not deploy by itself; use Manual Deploy in the Render
  dashboard (the `render.yaml` blueprint says `autoDeploy: true`, the
  existing service predates it).
- **Mail still goes out from Resend's sandbox sender**
  (`ProofVisor <onboarding@resend.dev>`), which delivers only to the
  Resend account owner. Verification, password-reset and invitation
  emails to anyone else need `proofvisor.com` verified as a sending
  domain in Resend (DNS records at the registrar) and `EMAIL_FROM`
  changed to match.
- **No identity-provider sign-in is configured on the live API.** No
  Google or Microsoft client is set, so only email and password (and
  passkeys, which are bound to `proofvisor.com`) work until a client
  id and secret are added; SAML and SCIM are built in and off by
  default.
- **Security review depth.** The code added on 2026-10-31 and the
  rename's compatibility were reviewed line by line; older console API
  code and the Rust daemon got spot checks only.

## 8. Verification record for 2026-10-31 and 2026-11-01

All on the merged `integration/all` branch. Every row was rerun on
2026-11-01, after the rename compatibility work, the pushed-schema fix
and the three CI fixes, except two that were run on 2026-10-31: the
Windows compile check, and Keycloak (which CI's keycloak-interop job
passed on 2026-11-01).

| Suite | Result |
|---|---|
| Rust workspace, default features | 1,733 tests passed, 0 failed (9 restart tests timed out during a disk stall and passed when rerun alone; the all-features run is left to CI) |
| Rust 1.95 build check (the new minimum version) | builds |
| `cargo fmt`, `cargo clippy -D warnings`, `cargo deny` advisories, schema check | clean |
| Windows x64 compile check (daemon and CLI, all targets) | no errors on 2026-10-31; the folder-flush fix for the Windows unit tests is checked only by CI |
| Provider contracts with the real daemon against local stand-ins of the OpenAI, Anthropic and Gemini wire formats (`n = 2` included) | 14 of 14 |
| Introspection expiry with Redis / MCP uncertainty | 11 of 11 / passed |
| Crash recovery reaching the console (`daemon-console-drill`) | 15 of 15 |
| Policy push end to end with the real API, daemon and pvctl (now also checks that a refused chat request is attributed to its policy on the console) | 35 checks passed |
| Live pillars (identity, exchange, revocation, receipts, end to end) | 84 checks passed in memory, 115 with Redis |
| API unit and recovery tests, including SCIM, billing, rename compatibility and schema references (`npm test`) | 100 passed |
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
| The daemon's AuthZEN request format, sent by a test script to public interop PDPs (Cerbos, Aserto Topaz) | allow and deny as expected |
| The daemon's own AuthZEN client against the public Topaz PDP | allow and deny as expected |

Added later on 2026-11-01, after a second pass over the whole chain:

| Check | Result |
|---|---|
| Upgrade in place: a database at the pre-rename schema, filled through the pre-rename API (owner, deployment, pinned key, sessions, a real daemon receipt, `av_srv_` key, policy, webhook, invitation), then the four new migrations and the new API | migrations applied; 21 of 21 checks (login, old key, old ingest token with either header name, policy pull, receipt, public key endpoint, invitation, free plan, SCIM off); smoke suite and 141 of 141 contract checks against the upgraded database |
| New `pvctl console-sync` against the pre-rename API | failed with 401 before the fix (one header name); uploads session, events and receipt after it |
| README quickstart with the real binaries (`pvctl init --preset openai`, `doctor`, `proofvisord`, chat with and without streaming, session close, `pubkey`, `receipt-verify` in hex and base64, `event-tail`, `/health`, `/livez`, `/readyz`, `/metrics`, `/dashboard`, JWKS, MCP refusal without schemas) and the no-config start (`PV_UPSTREAM_URL` only, `close` then `promote`) | all as documented; the client's own bearer token never reached the upstream |
| Daemon → `pvctl console-sync` → API → console in a real browser → shared verify link → verify page | the session, its event stream, "Signature verified" and the shared link's "Trusted: key pinned by the console for deployment quickstart" all shown |
| Policy push from the console UI to that daemon (token-rate and budget templates) | chat requests refused naming the policy; the policy page counts the hit and the block; the deployment page flips from "not pulling" to "current" |
| `cargo fmt`, `cargo clippy --all-features --all-targets -D warnings`, the pv-cli console-sync and pv-harness policy-push unit tests, API `npm test` after these changes | clean; 20 and 3 tests passed; 100 API tests, 99 passed in the full run and the one auth-drill timeout passed alone (it waits 5 s for a container while clippy and the end-to-end script loaded the laptop) |
| Live production checks on 2026-11-01 (after the merge, Render deploy and DNS): a throwaway account on `https://api.proofvisor.com`, a deployment, the real daemon (offline demo) uploading its session and Ed25519 receipt with `pvctl console-sync`, read back through the API | account, session cookie, `pv_live_` token, 14 events, 2 allowed and 1 blocked tool call, receipt stored and verified server-side, public key endpoint (CORS open), policies, SCIM settings (off) and billing answered; the account and its deployment were then deleted through the API. One check of my own (a `status` field the API does not return) was wrong, not the product |
| Full verification of merged `main`, 2026-11-01 (second half of the day), one heavy job at a time | Rust workspace 1,734 passed, 0 failed (3 ignored); API tests 100 of 100; database drill battery 17 of 17; smoke suite; contract suite 141 of 141; policy push with the real daemon and `pvctl` 34 of 34 locally and 36 of 36 on production; interactive drill 35 of 35; browser end-to-end (sign-up through the real form, demo data, tour, checklist); quarantine drill 25 of 25; real daemon crash and restart reaching the console; console injection drill 207 checks, 0 failed; accessibility audit (0 serious or critical violations across 11 routes, 9 modal states, 3 static pages, both themes, forced colours); mobile drill (down to 280 px); strict security-policy drill (including verify and login under it). Several stages first failed because my runner passed them wrong settings (a base path, a relative binary path, a missing `SITE`); each was rerun correctly and passed |
| Live production, feature by feature, with one throwaway account (24 later checks, 2 earlier runs) | API keys (create, use, revoke, then 401), invitations, retention and IP allow-list settings, a webhook (and a metadata-address target refused), SCIM end to end (token, provision, filter, deactivate, group, wrong token refused, delete), audit log and CSV, personal data export, sign out everywhere (needs the password again), the real daemon's receipt verified by the offline Node verifier and rejected when one byte changed, and on the live verify page in a real browser (genuine accepted, tampered rejected, pinned-key "Trusted" for the right deployment only). A wrong password gets the same `mfaRequired` reply as an account with a second factor and no session cookie. One workspace from this run could not be deleted (see STATUS notes) |
| Release pipeline, tag `v0.1.0-rc.6` | exposed a real defect: the Windows build step ran under PowerShell and failed on a bash line continuation; fixed on `main` (`shell: bash`). No release was published; the installer on the live site still pins `0.1.0-rc.5`, whose files carry the old names, so prebuilt installs 404 until a new tag is built |
| Production build and boot reproduced locally: the merged `server/Dockerfile` image with Render's real settings over a database at the old schema | four migrations applied, `/healthz` and `/readyz` 200, new endpoints present |
| HTTPS and redirects on the public site | `https://proofvisor.com` presents its own Let's Encrypt certificate; `http` and `www` redirect to it; `/lander` redirects to the home page; `agentvisorai.me` and its `www` forward (301, front page only) |
| The public console in a browser over HTTPS (`live-site-smoke.mjs`) | 11 checks passed: routes, populated tabs, link and media integrity, link previews, videos, installer |
