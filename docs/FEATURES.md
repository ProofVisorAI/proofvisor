# ProofVisor — what exists today

Dated 2026-10-31, rechecked on 2026-11-01 (last pass in the evening,
on `main`). Sections 1 to 6 list only features that an automated
end-to-end test drives through the real server or binary and that
passed on every run recorded in sections 8 to 10: the Rust test suites,
the API and console test suites, the browser drills, the real-binary
drills and the interop tests. Where the far end of a test is a stand-in
rather than the real service (a local server speaking a vendor's wire
format, fixture certificates for Cloud Foundry, a scripted identity
provider), the item says so. Anything that is built but not proven
that way, planned, partial or demo-only is in section 7, so that
nothing here overstates what a customer gets.

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
  choice). The Anthropic and Gemini adapters are driven end to end
  against local servers that speak each vendor's wire format; a run
  against the vendors' live APIs is still owed (section 7). Sixteen presets exist in `pvctl init` (OpenAI, Azure,
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
  buildpack. These were tested with fixture certificates and fixture
  distributions, not on a real Cloud Foundry foundation (section 7).

## 4. The CLI (`pvctl`)

Twenty-two subcommands, none of them stubs: guided `setup`, `init` with
presets, `doctor`, `health`, `start`, `sidecar`, `keygen`, `pubkey`,
`receipt-locate`, `spool-prune`, `receipt-verify`, `atif-validate`,
`manifest-validate`, `bridge-provision`, `event-tail`,
`session-promote`, `token-revoke`, `instance-revoke`, `config-validate`,
`console-sync` (uploads evidence to the hosted console, with a watch
mode), `loadgen` and `judge-calibrate` (measures a semantic-judge model
on a labelled set and fails below set floors; see section 11).

## 5. The hosted console (proofvisor.com/app and api.proofvisor.com)

A real multi-tenant web application (Node, Fastify, Prisma, Postgres)
with a static single-page console. The console also runs in a mock mode
with demonstration data, which is what the public site shows by default.

- **Accounts:** signup, login, logout, sign out everywhere, organisation
  switching, password and email change with confirmation, profile,
  data export (NDJSON), account deletion with a typed confirmation,
  password reset.
- **Second factor with passkeys (WebAuthn)** and administrator reset.
- **Single sign-on:** Google (live on the hosted API); Microsoft (built,
  but it needs an Entra app registration before its button appears;
  section 7); generic OIDC and a SAML 2.0 service provider (built in,
  off by default) with discovery by email domain. Discovery trusts
  only domains the workspace has verified with a DNS TXT record
  (Settings → SSO → Verified email domains), and the login page shows
  which provider it found and asks before leaving. Tested against
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
  schema, token-rate, guardrail and transform policies are pushed to
  daemons (`pvctl console-sync --pull-policies`), which can only tighten
  their local configuration and report back whether each policy was
  applied. A guardrail or transform whose body is free text rather than
  the JSON spec stays documentation only (see section 6).
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
  the public Topaz server, and against the public Cerbos demo server
  with the mapping (its policy models `todo` resources).
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
- **Guardrail policies are enforced** when their body is the JSON spec
  described in `docs/reference/OPERATIONS.md` ("Guardrail policies"):
  `applies_to` (`tool.args` or `llm.ingress`), `deny_patterns` (1 to 64
  bounded regular expressions) and `effect: block`. The daemon refuses
  a tool call whose arguments match at the policy stage, and a chat
  request whose messages match at the sanitize stage, each refusal
  naming the console policy and the pattern position, never the matched
  text; `pvctl console-sync` uploads the block attributed to the policy.
  Patterns are compiled under the same bounds as `redaction_patterns`
  (`pv_redact::compile_pattern`). A guardrail saved before this spec
  existed keeps its free-text body: the console still accepts it, it
  stays documentation only, and daemons now list it as unsupported with
  the reason "guardrail policy has no JSON spec".
- **Guardrails over model responses** (`applies_to: "llm.egress"`,
  scope `llm.egress`, added later on 2026-11-01). The daemon scans the
  response text as it captures it. A buffered response that matches is
  refused with HTTP 403 naming the policy and no byte of it reaches the
  client. A streamed response that matches in its first frame is
  refused the same way; one that matches later ends with an error frame
  naming the policy, and the frame that completed the match is never
  relayed (the scan overlaps frames by 1 KiB and rescans the whole body
  at the end). The turn is attested "Policy Blocked" with the policy
  name, so the console counts it as a block.
- **Transform policies are enforced** when their body is the JSON spec
  described in `docs/reference/OPERATIONS.md` ("Transform policies"):
  `applies_to` (`tool.args` or `llm.ingress`), `redact_patterns` and an
  optional `replacement` (default `[REDACTED]`). Tool arguments are
  rewritten before the sandbox verdict, so the journal and the backend
  both see the rewritten call; chat messages are rewritten after the
  guardrails and before compression, and the compression record lists
  the transforms that fired with their replacement counts. A free-text
  transform stays documentation and is reported unsupported.
- **A pushed token budget that a completion overflows** is refused
  naming the console policy, as the admission-time check already did,
  and the stop-reason event carries the policy name.
- **Transforms over model responses** (`applies_to: "llm.egress"`,
  scope `llm.egress`, added late on 2026-11-01). A buffered response is
  rewritten before it is journaled and before it is relayed, in its
  content, reasoning and tool-call arguments; the capture lists the
  transforms that fired with their replacement counts. A streamed
  response is held until it is complete and then relayed rewritten,
  with the provider's frame count, finish reason and usage intact (the
  first content frame carries the whole rewritten text). The console
  validates the spec and offers a "Redact in answers" template.
- **Egress guardrails scan every part of a response**: the text, the
  reasoning content and tool-call arguments, each named in the
  refusal ("model reasoning matches deny pattern 1 of 1").
- **Per-tool resource mapping for AuthZEN** (`[authzen.resources]` in
  the daemon config): a tool name or pattern maps to the resource type,
  id and properties a decision server's policies model; unmapped tools
  keep the default `{"type": "tool", "id": <tool>}`.

## 7. Not yet, partial, or needs a decision

- **Billing is built but not switched on.** No Stripe account is
  connected to the hosted API, and plan limits are off by default. The
  prices and the free-plan limits (2 deployments, 3 members, no SAML or
  SCIM) were proposed during development and need a business decision
  before anyone turns them on; they contradict today's "every
  governance feature on Free" wording.
- **Budget policies written before this release have no spec.** The
  pre-rename console stored budget policies as text only, so a daemon
  reports such a policy as unsupported ("budget policy has no JSON
  spec") until an administrator re-saves it from a template.
- **Windows.** Windows x64 is a Tier 2 platform (see
  `docs/PLATFORMS.md`). Each release includes a prebuilt `.zip` with
  the daemon and CLI; `install.sh` does not install it. CI compiles both
  for Windows, runs the workspace unit tests, and since 2026-11-01 also
  runs the built binaries on a hosted Windows runner
  (`scripts/boot-smoke.py`: boot, readiness, a proxied chat completion,
  a signed session with a verified receipt and a refused tampered copy,
  restart on the same spool). Other features, such as MCP routes,
  budgets, console sync, the sidecar and Ctrl-C shutdown, are compiled
  and unit-tested on Windows but not run there. Nothing has run on
  customer Windows hardware, and the installer, service unit and
  containers stay Unix-only, so Windows is listed here rather than among
  the Tier 1 platforms.
- **Release state.** The latest release is the pre-release
  `v0.1.0-rc.8` (2026-11-01; the installer pins it); nothing is on
  crates.io yet. Publishing needs explicit approval.
- **Native Anthropic and Gemini have not reached the real APIs yet.**
  They were tested against local servers that speak each vendor's wire
  format as documented. A run against api.anthropic.com and the Gemini
  API needs real keys and makes a few paid requests
  (`scripts/provider-smoke.py --allow-live-request --provider anthropic
  --base-url https://api.anthropic.com --model <model> --output-dir <dir>`,
  or `--provider gemini --base-url https://generativelanguage.googleapis.com`
  with the same other options; the script requires `--model` and
  `--output-dir`, and without `--base-url` it sends to api.openai.com).
- **Still tested with stand-ins only:** a real Cloud Foundry
  foundation, cloud object storage, and identity providers other than
  Keycloak (for example Okta and Entra ID).
- **Deployed on 2026-11-01.** Pull request ProofVisorAI/proofvisor#396
  is merged. The site is served from GitHub Pages at
  `https://proofvisor.com` (own certificate, HTTP and `www` redirect to
  it) and the API runs on Render at `https://api.proofvisor.com` (the
  old `api.agentvisorai.me` still answers, same service). The old
  domain `agentvisorai.me` forwards (301, front page only) to the new
  one. Render's Auto-Deploy for this service is on and set to deploy
  **after CI checks pass**: a merge to `main` deploys once that
  commit's GitHub checks are green (a commit whose CI run was cancelled
  because a newer commit superseded it is skipped; the newer commit
  deploys). The container applies database migrations at start.
- **Mail goes out from `ProofVisor <no-reply@proofvisor.com>`.** The
  domain is verified at Resend (a test message from it was accepted on
  2026-11-01) and the live service's `EMAIL_FROM` already uses it.
- **Sign-in with Google is live** (the live API advertises it);
  Microsoft needs an Entra app registration (`MICROSOFT_CLIENT_ID` and
  `MICROSOFT_CLIENT_SECRET`) before its button appears. SAML and SCIM
  are built in and off by default.
- **Security review depth.** The code added on 2026-10-31 and the
  rename's compatibility were reviewed line by line on those days. On
  2026-11-01 the older console API code (every route, the auth,
  session, SAML, OIDC, passkey, SCIM, webhook and export code) and the
  daemon's older paths (authentication, token exchange, MCP gateway,
  policy and budget enforcement, relay, receipts) were reviewed line by
  line as well; the findings are fixed (section 10).

- **Semantic judge: what is not proven or not built.** These items
  belong to section 11.
  - No trained judge model and no labelled data set exist yet. The
    tests use a small toy ONNX classifier, and the scenario script uses
    a stand-in judge service that speaks the cloud contract.
  - No real-binary test covers three situations:
    - after a restart, outputs that were already judged are not judged
      again;
    - an embedded Bridge created by an older build gains the
      `agent.judge` topic, and a daemon with an operator's own manifest
      that lacks it refuses to start;
    - shutdown waits for a background verdict still on its way.

    Tests inside the process cover the code involved, but not these
    situations end to end.
  - The hosted console does not receive `agent.judge` events;
    `console-sync` skips them.
  - Standing rules are put back by exact text, not by a judge
    predicate per rule as the build specification proposed, and not
    through the loop breaker's inject path (which adds its message at
    the end, where the audit record would take it for the caller's
    turn). Compression never rewrites text, so a missing rule text
    means compression cut it; the check relies on the application
    sending each rule with exactly the configured text.
  - The breaker's second opinion runs inside the audit worker, so a
    slow judge call also delays the audit records of other sessions
    that share that worker.
  - Tools are tagged for review in `[[judge.tools]]`, not inside their
    schema files.
  - The prior-denial log, the review queue and the drift state are kept
    per instance.

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
| The daemon's own AuthZEN client against the public Cerbos demo PDP, with `[authzen.resources]` mapping the tool to a `todo` resource (2026-11-01) | allow and deny as expected |

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
| Release pipeline, tag `v0.1.0-rc.6` | exposed a real defect: the Windows build step ran under PowerShell and failed on a bash line continuation; fixed on `main` (`shell: bash`). No release was published; at that time the installer on the live site still pinned `0.1.0-rc.5`, whose files carry the old names, so prebuilt installs returned 404. Superseded: `v0.1.0-rc.8` was published on 2026-11-01 and the installer pins it (section 7) |
| Production build and boot reproduced locally: the merged `server/Dockerfile` image with Render's real settings over a database at the old schema | four migrations applied, `/healthz` and `/readyz` 200, new endpoints present |
| HTTPS and redirects on the public site | `https://proofvisor.com` presents its own Let's Encrypt certificate; `http` and `www` redirect to it; `/lander` redirects to the home page; `agentvisorai.me` and its `www` forward (301, front page only) |
| The public console in a browser over HTTPS (`live-site-smoke.mjs`) | 11 checks passed: routes, populated tabs, link and media integrity, link previews, videos, installer |

## 9. Blind spots closed on 2026-11-01 (evening)

A review of the verification record against the code found features
that were implemented and unit-tested but never driven end to end, and
one end-to-end script that no workflow ran. Each is now covered on
every push to `main`.

| Blind spot | Now covered by | Result |
|---|---|---|
| Context compression on the chat path (every real-binary drill ran with it off) | `crates/pv-harness/tests/e2e_proxy_contracts.rs`: a forty-turn repetitive history reaches the upstream with its repeated turns replaced by `[pruned: …]` stubs, at less than half the bytes, the system prompt and protected tail intact, and an `agent.compression` record with `changed: true` on the bus; with `compression_enabled = false` the history is forwarded verbatim | 2 of 2 |
| `consequential_tools` require a signed session | same file: `payout` on an unsigned session is refused with "requires a signed workflow" before the backend is contacted; a non-consequential tool runs unsigned; the same `payout` runs on a signed session | 1 of 1 |
| Provider key headers stripped from upstream responses | same file: `Authorization`, the configured key header, `Set-Cookie`, `Server` and `X-Powered-By` echoed by the upstream never reach the client; `ETag`, `Cache-Control` and vendor request ids pass; `nosniff` is pinned | 1 of 1 |
| Operator dashboard | same file: page, stylesheet, script and the three JSON endpoints answer when `dashboard_enabled = true`, reflect a live session, and all return 404 when it is off | 1 of 1 |
| `pvctl console-sync --watch` (no test at all) | `crates/pv-cli/tests/e2e_console_sync_watch.rs` runs the real binary in watch mode against a loopback console: a trajectory written while watching is uploaded on the next pass, event batches go out once, the policy bundle is written owner-only and re-checked with `If-None-Match` (304), the daemon's status file is reported once without its private `error` field, Ctrl-C exits 0 without warnings; `--interval 0` and `--pull-policies` without a bundle file are refused | 2 of 2 |
| `pvctl sidecar` (unit-tested in-process only) | `crates/pv-cli/tests/e2e_sidecar.rs` runs the real binary from a settings file: buffered and streamed chat and an MCP call pass through, every forwarded request carries the token from the credential file and never the application's own bearer, a non-loopback listen address and a missing gateway are refused, SIGTERM exits 0 | 3 of 3 |
| The CLI help contract listed ten of the twenty-one subcommands | `e2e_cli_contract.rs` now checks all twenty-one in `--help` and each one's own help | 22 of 22 |
| `scripts/policy-push-e2e.mjs` ran only by hand | a step in the Console + API workflow (`console-api.yml`), after the daemon crash drill, with the same API and built binaries; the script now honours a signup `Retry-After` once | 36 of 36 locally |
| Guardrails over model responses (`llm.egress`, previously refused by the console) | `crates/pv-harness/tests/e2e_policy_egress_and_transforms.rs`: a buffered response that matches is refused with 403 naming the policy and the matched text never reaches the client; a streamed match in the first frame is refused the same way; a later match ends the stream with an error frame, the completing frame withheld; each refusal is attested with the policy name. `scripts/policy-push-e2e.mjs`: a real daemon refuses a model response naming `privacy.no_codenames`, a clean response on the same session passes, and the console counts the block | 3 of 3; script 51 of 51 |
| Transform policies (documentation only before) | same Rust file: an `llm.ingress` transform rewrites the chat request before the model sees it and the compression record names it with the replacement count; a `tool.args` transform rewrites the arguments before the backend sees them, leaves tools outside its scope alone, and leaves a body the strict parser refuses alone. Script: a real daemon forwards a rewritten tool call and the console shows the transform enforced. `server/ci/policy-spec.test.mjs`: the spec and its refusals | 2 of 2; script 51 of 51; 10 of 10 |
| Transforms did not rewrite model responses | `crates/pv-harness/tests/e2e_policy_egress_transforms.rs`: a buffered response reaches the client with its ticket numbers replaced and the capture names the transform with two replacements; a streamed response is held and relayed rewritten with five frames, the finish reason and usage intact and no original text anywhere. `scripts/policy-push-e2e.mjs`: a real daemon relays a rewritten answer and the console shows the transform enforced | 2 of 2; script 55 of 55 |
| Egress guardrails ignored reasoning and tool calls | same Rust file: a response whose reasoning names the codename is refused naming "model reasoning"; one whose tool-call arguments name it is refused naming "model tool call"; a clean response still passes | 1 of 1 |
| No per-tool AuthZEN resource mapping | `crates/pv-harness/tests/e2e_identity_and_policy.rs`: an exact mapping sets type, id and properties, a pattern mapping sets the type and keeps the tool name as id, an unmapped tool keeps the documented default; the config validator refuses empty types and non-table properties | 1 of 1 |
| Mid-stream budget refusal without the policy name | same Rust file: a completion that overflows a pushed `max_tokens` is refused with `policy "llm.token_cap": max_tokens exceeded (cap 120)` and the stop-reason event carries the policy | 1 of 1 |
| Audit-log CSV export (tested only by the scheduled console-smoke drill) | `server/ci/e2e.mjs`: status and download headers, the `id,at,event,…` header row, the org's own `deployment.create` entry and actor email, no formula-leading cells, and the `audit.exported_csv` breadcrumb in the JSON audit log | 146 of 146 (was 141) |

Not closed, and why:

- **Guardrail enforcement** was closed later the same evening (section
  6; pull request ProofVisorAI/proofvisor#397), and **guardrails over
  model responses, transform policies and the named mid-stream budget
  refusal** after that (section 6, and the table above).
- **Live Anthropic and Gemini runs** need real keys; none are available
  on the verification laptop.
- **Windows hardware, a real Cloud Foundry foundation, Okta and Entra
  ID, cloud object storage, a live Stripe account and a crates.io
  release** need resources or approvals this checkout does not have.

After these additions, on the same laptop: Rust workspace 1,744 tests
passed, 0 failed, 3 ignored (ten new); `cargo fmt --check` and `cargo
clippy --workspace --all-targets --all-features -D warnings` clean; API
unit tests 100 of 100; contract suite 146 of 146 and the policy-push
script 36 of 36 against a locally booted API with the real daemon and
`pvctl`.

After the response guardrails, transforms and the named mid-stream
budget refusal landed, on the same laptop: Rust workspace 1,757 tests
passed, 0 failed, 3 ignored; `cargo fmt --check` and `cargo clippy
--workspace --all-targets --all-features -D warnings` clean; API tests
108 of 108; API type check clean; contract suite 146 of 146; policy-push
script 51 of 51 against a locally booted API with the real daemon and
`pvctl`; the 17-drill console battery 17 of 17 (the IP allow-list drill
first hit the per-IP invitation rate limit left by the two invite drills
before it, and passed on its own).

After response transforms, part-aware egress guardrails and the AuthZEN
resource mapping landed, on the same laptop: Rust workspace 1,762 tests
passed, 0 failed, 3 ignored; `cargo fmt --check` and `cargo clippy
--workspace --all-targets --all-features -D warnings` clean; API tests
108 of 108 and the type check clean; contract suite 146 of 146;
policy-push script 55 of 55 against a locally booted API with the real
daemon and `pvctl`.

## 10. Security review findings closed on 2026-11-01 (night)

Both reviews read the older code line by line. Every finding is fixed
and pinned by a test that runs in the normal suites.

| Finding | Fix | Proof |
|---|---|---|
| A web page could drive a loopback daemon cross-site: the chat, session and token routes did not look at `Origin`, and a `no-cors` `POST` with a `Blob` body needs no preflight. | Every state-changing route refuses an `Origin` that is not in `mcp_allowed_origins`, the allowlist the MCP routes already used. | `e2e_origin_guard` (3 tests) |
| The "requires a signed workflow" refusal for consequential tools was only an audit-mode choice: any caller could send `X-PV-Workflow: signed`. | New `signed_workflow_scope` setting; when set, a token without that scope cannot open a signed session, so consequential tools stay out of reach. Unset by default, documented. | `signed_workflow_scope_keeps_consequential_tools_from_unscoped_tokens` |
| Any workspace owner could claim another company's email domain in a SAML config, and the login page redirected that company's users to the attacker's "identity provider". | Discovery only consults domains the organisation verified by a DNS TXT record (`_proofvisor-challenge.<domain>`); one domain belongs to one organisation; the login page names the provider and asks before leaving. | `identity-hardening.test.mjs`, `saml-browser-e2e.mjs` |
| Accepting an invitation for an address someone had pre-registered (unverified) granted the invited role to the squatter's account. | For an unverified existing account, accepting the invitation sets the password the invitee enters, fences every session, revokes the account's API keys and deletes its passkeys, then grants the membership. | `identity-hardening.test.mjs` |
| A SCIM group named `owner` granted the owner role, so a compromised SCIM token could mint owners. | A group named `owner` grants admin. Owners are only made in the console. | `scim.test.mjs` |
| No per-account cooldown on password-reset requests: an attacker rotating IPs could keep invalidating a victim's reset link. | One reset link per account per minute; the earlier link stays valid. | `external-auth.test.mjs` |
| Webhook URLs (Slack and Discord embed their secret in the path) were copied into the audit log and its CSV export. | The audit entry keeps the host only. | type check, `e2e.mjs` |
| The webhook SSRF blocklist lacked multicast, reserved, benchmarking and TEST-NET ranges. | Added. | type check |
| Five open advisories against `quinn-proto`, and three unmaintained crates (`unsafe-libyaml` through `serde_yaml`, `rustls-pemfile` through `redis` 0.27, `paste` through `tokenizers`). | `quinn-proto` updated; `serde_yaml` replaced by its maintained fork `serde_norway` (same API); `redis` upgraded to 0.32, which drops `rustls-pemfile` (the daemon now computes Redis Cluster hash slots itself, pinned against `CLUSTER KEYSLOT`). `paste` remains, reachable only through `tokenizers` behind the optional `onnx` feature; no release of `tokenizers` without it exists. | `cargo audit` (one previously dispositioned advisory left), Redis contract and revocation tests against a live single node and a live six-node cluster |

Also closed from section 7: the daemon's AuthZEN client now runs against
the public Cerbos demo decision server with `[authzen.resources]`
mapping the tool to a `todo` resource (allow and deny as expected), and
a budget, allowlist, rate or schema policy saved before the JSON spec
existed is marked "Needs the JSON spec: edit and re-save" in the
console instead of silently counting on a daemon's unsupported report.

Gates on the tree that closes section 10, on the same laptop: Rust
workspace 1,865 tests passed, 0 failed, 5 ignored (`--all-features`,
no fail-fast); `cargo fmt --check` and `cargo clippy --workspace
--all-targets --all-features -D warnings` clean; `cargo audit` down to
the one advisory dispositioned in `deny.toml`; API tests 111 of 111 and
the type check clean; contract suite 146 of 146; policy-push script 55
of 55 with the rebuilt daemon and `pvctl`; SAML browser suite 8 of 8;
console browser suite all checks; Redis contract (8) and revocation (7)
suites against a live single node and a live six-node cluster; the
daemon's AuthZEN client against the public Topaz and Cerbos servers.

## 11. Semantic judge (added on 2026-11-01)

The judge scores questions that schemas and rules cannot answer, such
as "do these arguments fit the agent's task?", and returns a probability
for each label. Policy turns the probabilities into allow, ask or deny,
and the signed audit trail records every verdict. The configuration is
in `docs/reference/CONFIGURATION.md` (section "Semantic judge") and the
runbook in `docs/reference/OPERATIONS.md`. `scripts/judge-scenarios.py`
runs 17 scenarios against the release binaries, with a stand-in model
provider, billing backend and judge service. The numbers in the table
refer to those scenarios.

| Feature | Proof |
|---|---|
| Tool calls on `/v1/mcp` for tools listed in `[[judge.tools]]` are scored after the schema gate and before policy; other tools take the same path as before. | `e2e_judge.rs`; scenarios 1 and 7a |
| Thresholds and WASM policies (interface version 2, `evaluate_v2`) decide allow, ask (`APPROVAL_REQUIRED`) or deny (`JUDGE_DENIED`), naming the predicate. | `e2e_judge.rs`; version 2 policies in `e2e_judge_edges.rs` and `e2e_judge_full_stack.rs`; scenarios 2 and 3 |
| A delegated agent retrying what an agent above it was refused is caught from the session's recorded refusals. | `e2e_judge.rs`; scenario 4 |
| Timeouts, outages, malformed answers, saturation and model-pin mismatches refuse or hold the call, never allow it silently. | `e2e_judge_edges.rs`, `e2e_process_restart.rs` (`judge_enforces_across_kill_and_restart_and_fails_closed_when_it_dies`); scenarios 5, 6 and 7b |
| Each verdict (all label probabilities, the model pin, the latency, the threshold that decided) is in the signed event chain and the trajectory; editing it breaks the receipt. | `e2e_judge.rs` (`the_receipt_signs_the_verdict_and_tampering_breaks_it`), `e2e_judge_full_stack.rs`; scenario 9 |
| A local ONNX scorer refuses to load a model or tokenizer whose hash differs from its pin; a cloud judge needs a per-tool opt-in and receives redacted input. | `local_onnx.rs`, `cloud_contract.rs`; scenario 9 (no personal data or prompt text reached the judge) |
| `pvctl judge-calibrate` and a build-time test enforce a measured floor of separation between labels. | `calibrate.rs`, `e2e_judge_cli.rs`; scenario 11 |
| Reviewed verdicts feed a drift check by confidence band; when accuracy stops rising with confidence, judged calls are held for approval, and this survives a restart. | `e2e_judge.rs`; scenario 8 |
| Shadow mode scores and never blocks, and publishes each would-be block as an `agent.judge` event; a capped pilot blocks at most a set number of calls per tool per day. | `e2e_judge_background.rs`; scenarios 10, 12 and 14 |
| Recorded tool outputs and model answers are judged in the background, and findings are published as `agent.judge` events (OCSF class 9907) that the receipt covers. A slow verdict does not delay the reply, and a session close waits for it. | `e2e_judge_background.rs`; scenario 13 |
| The loop breaker asks the judge when a step's change is ambiguous: repetition that is progress is spared, and a real loop trips the breaker. | `e2e_judge_background.rs`, `crates/pv-loopdetect` unit tests; scenario 16 |
| A standing rule that compression cut is put back after the leading system messages, and the token count is recomputed. | `e2e_judge_background.rs`; scenario 15 |
| An embedded Bridge created before the `agent.judge` topic existed gains it at start when `[judge]` is set. | `crates/pv-bridge/tests/embedded_contract.rs` (`missing_topics_are_added_to_an_existing_bridge`) |

What is not proven or not built is listed in section 7.
