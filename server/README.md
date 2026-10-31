# ProofVisor hosted console — API server

Multi-tenant control plane for the ProofVisor console. Users sign up here,
register `proofvisord` deployments, and view sessions/receipts posted by
those daemons. Live LLM and tool requests run through the customer's daemon.
Console sync uploads session metadata, captured event messages and observations,
and Ed25519 signed receipts. Event content can include prompts, completions, and
tool payloads after the daemon's configured redaction; this API stores those
uploaded fields and restricts their visibility by role.

**For deployment (Render, Cloud Run, Neon, self-host) see [DEPLOY.md](./DEPLOY.md).**
The live instance is a Render web service (`agentvisor-api`, reachable at
`https://agentvisor-api.onrender.com`; the custom domain `api.proofvisor.com`
is pending DNS). Nothing runs on Fly.io; `fly.toml` is an unused template.

## Architecture

```
┌────────────────┐        ┌───────────────────────┐        ┌──────────────┐
│  proofvisord   │──HTTPS─▶  api.proofvisor.com  │──HTTPS─▶  console UI  │
│ (self-hosted   │  ingest│  (this server)        │  read  │  (Pages)     │
│  by customer)  │◀───────│  Postgres (any host)  │◀───────│              │
└────────────────┘        └───────────────────────┘        └──────────────┘
       │                          ▲                                 │
       └── LLM + tool traffic stays local; captured evidence is uploaded
                                  └── auth (JWT cookie) ────────────┘
```

## Requirements

- Node.js ≥ 22
- Postgres 15+ (any provider — Neon / Supabase / Render Postgres / self-host)
- Docker (for local reproducibility via `docker-compose`)

## Local dev

```sh
cd server
cp .env.example .env               # edit JWT_SECRET (openssl rand -hex 48)
docker compose up -d db            # local Postgres on :5433
npm install
npm run prisma:migrate:dev
npm run dev                        # http://localhost:8080
```

Point the console at it by editing `docs/app/config.js`:

```js
window.MOCK_MODE = false;
window.API_BASE = "http://localhost:8080"; // bare origin — paths already carry /api/v1
```

Two footguns (both caught by CI's Browser E2E job, which makes these
exact edits before driving the SPA in headless Chromium):

- `API_BASE` is the **origin only**. The datasource calls
  `apiFetch("/api/v1/…")`, so a base that already ends in `/api/v1`
  doubles the prefix and 404s everything.
- `docs/app/index.html` ships a strict meta CSP whose `connect-src`
  allows only `'self'` and `https://api.proofvisor.com`. Add your API
  origin there or the browser silently blocks every fetch.
- Serve the SPA **under `/app/` with `logo.png` one level up** (the
  production topology). The console references `../logo.png` for the
  brand mark and favicon; a flat copy of `docs/app` alone 404s both.

## Production container

Build the image with `docker build -t proofvisor-api server/` from the repository
root. The pinned runtime uses Node 22 on Debian 13 Distroless, runs as UID 65532,
and contains no shell or package manager. The build generates the Prisma client
on Debian 13 and retains the Prisma CLI and migrations as production dependencies.

The image starts `container-entrypoint.mjs` directly with Node. It runs the
packaged `prisma migrate deploy` first and starts the API only after migrations
succeed. A migration failure preserves its nonzero exit status. SIGTERM and
SIGINT reach the active child and its process group, including Prisma's schema
engine. Deployment platforms should use the image's entrypoint and command.

Supply the production settings described in [DEPLOY.md](./DEPLOY.md), including
the database, JWT secret, allowed origin, public URLs, and mailer. The runtime
supports a read-only root filesystem with a writable temporary directory:

```sh
docker run --read-only --tmpfs /tmp:uid=65532,gid=65532,mode=0700 \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file /secure/path/proofvisor-api.env -p 8080:8080 proofvisor-api
```

The container healthcheck requests `/readyz`, which checks database availability.
Use `docker logs` for diagnostics. For a one-off Prisma command, run the packaged
CLI with Node, for example `docker exec <container> node
/app/node_modules/prisma/build/index.js migrate status`. Do not rely on `sh`,
`npm`, or `npx` inside the runtime.

Run `node --test server/ci/container-entrypoint.test.mjs` to verify process exit
and signal handling. `python3 scripts/container-smoke.py --console-image
proofvisor-api` tests the actual image with its own temporary PostgreSQL container,
including migration refusal, native engine loading, API calls, database recovery,
and clean shutdown. Add `--proofvisord /path/to/proofvisord --pvctl /path/to/pvctl`
to include the daemon crash and console synchronization drill.

## API surface

All routes are prefixed `/api/v1`.

### Auth (cookie session)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/signup` | `{ email, password, orgName, displayName? }` — creates user + owner org, sets `pv_session` cookie |
| `POST` | `/auth/login` | `{ email, password }`; answers `{ mfaRequired: true }` uniformly for passkey-enrolled accounts **and** bad credentials (no oracle) |
| `POST` | `/auth/logout` | Clears the cookie and fences prior JWTs |
| `POST` | `/auth/logout-all` | `{ password }` step-up; fences every session, re-mints the caller's cookie — "sign out other devices" |
| `GET`  | `/auth/me` | `{ user (incl. pendingEmail), org, memberships[] }` for the active session |
| `POST` | `/auth/switch-org` | `{ orgId }` — re-mints the cookie bound to another membership |
| `POST` | `/auth/change-password` | `{ currentPassword, newPassword }` — fences other sessions, keeps API keys |
| `POST` | `/auth/change-email` | `{ newEmail, password }` — uniform 202; confirm link goes to the new mailbox |
| `POST` | `/auth/change-email/confirm` | `{ email, token }` — anonymous; rotates the address, fences all sessions |
| `POST` | `/auth/change-email/cancel` | Clears the pending change |
| `PATCH`| `/auth/me/profile` | `{ displayName }` — empty clears |
| `POST` | `/auth/me/export` | Password step-up; streams the whole org as NDJSON (owner only) |
| `POST` | `/auth/me/delete-account` | Password + type-phrase; deletes org (+ account unless other memberships remain — response carries `accountDeleted`) |
| `POST` | `/auth/reset-request` / `/auth/reset-confirm` | Email reset flow; confirm revokes sessions **and** API keys (break-glass) |

### MFA / SSO

| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/webauthn/register/challenge` + `/verify` | Passkey enrollment (verify requires the account password) |
| `POST` | `/auth/webauthn/authenticate/challenge` + `/verify` | Passkey MFA step at login; requires the single-use `pv_mfa_gate` cookie `/auth/login` sets on its `mfaRequired` response (passkey possession alone cannot sign in) |
| `GET`/`PATCH`/`DELETE` | `/auth/webauthn/credentials[/:id]` | List / rename / revoke (revoke = break-glass: fences sessions, revokes keys) |
| `GET`  | `/auth/oauth/providers`, `/auth/oauth/:provider/start` + `/callback` | Google / Microsoft / generic-OIDC sign-in when configured |
| — | `/auth/saml/*` | SAML 2.0 SP: config CRUD, `/:configId/metadata.xml`, `/login`, `/acs`, `/slo`, `/keypair`, `/discover` |

### Org & members

| Method | Path | Notes |
|---|---|---|
| `PATCH`| `/org` | Rename the workspace (owner; slug/id stable) |
| `GET`/`PATCH` | `/org/retention` (+ `POST /org/retention/sweep-now`) | Retention windows + manual sweep |
| `GET`/`PATCH` | `/org/ip-allowlist` | CIDR allowlist (refuses to lock the caller out) |
| `GET`  | `/members` | Members incl. `mfaEnrolled` flag |
| `PATCH`/`DELETE` | `/members/:userId` | Role change / remove (rank guards, last-owner guard; self-DELETE = leave) |
| `POST` | `/members/:userId/reset-mfa` | Admin break-glass for a lost passkey (own-password step-up) |
| `POST`/`GET`/`DELETE` | `/members/invites[/:id]` | Invite CRUD; re-POST the same email = resend (fresh token, old link dies) |
| `POST` | `/members/invites/accept` | Anonymous accept (`{ token, email, password? }`) |

### Deployments, keys, policies, webhooks

| Method | Path | Notes |
|---|---|---|
| `GET`/`POST` | `/deployments` | Token returned **once** on create. Each row carries `sessions24h` and `spend24hUsdMicros` (the spend is `null` for members), `isDemo`, and `policyBundle: {etag, appliedAt, daemonVersion, stale, applied, unsupported}` (or `null` before the daemon first reports) |
| `PATCH`/`DELETE` | `/deployments/:id` (+ `POST /:id/rotate-token`) | Rename/env edit (labels only), delete (409 if sealed receipts unless forced), rotate |
| `GET`/`POST`/`PATCH`/`DELETE` | `/keys[/:id]` | API keys: list / mint (shown once) / rename / revoke — rank-guarded. `POST` accepts `role` (`owner`, `admin`, or `member`; default `admin`; never above the caller's own role, else 403 `cannot_grant_role_above_own`). The console sends the role chosen in its create dialog |
| `GET`/`POST`/`PATCH`/`DELETE` | `/policies[/:id]` | Policy CRUD (name/kind/scope/description/body/enabled). For the daemon-enforceable kinds (`budget`, `allowlist`, `rate`, `schema`) the body must be a JSON spec of that kind's shape (see `src/lib/policy-bundle.ts`); an invalid spec is refused with 400 `invalid_input` and a `specError` explanation. `guardrail` and `transform` bodies are free text that documents a rule and attributes the daemon's own guard hits. Reads add `enforceable`, the parsed `spec`, and `enforcement: {deployments, applied, stale, unsupported}`, which counts daemons against the org's current policy bundle. Members may read but not write |
| `GET`/`POST`/`DELETE` | `/demo`, `/demo/attack` | Live-mode "Simulate an attack" (owner/admin): `POST /demo/attack {pace: "staged"\|"instant"}` stages a blocked-payment session under a `demo-attack` deployment flagged `isDemo`, sealed with a receipt signed by the public demo key; `GET /demo` reports whether demo rows exist; `DELETE /demo` removes them. Demo deployments are never counted as daemons, and a real deployment named `demo-attack` makes the attack answer 409 |
| `GET`/`POST`/`PATCH`/`DELETE` | `/webhooks[/:id]` (+ `POST /:id/test`, `GET /:id/deliveries`) | Endpoints (SSRF-guarded), HMAC-signed deliveries with retries, cursor-paginated delivery log. Emitted events: `test`; `member.invited`; `policy.block` (every ingest batch that contains a blocked tool call); `session.blocked` (once per session, on its first blocked tool call or on a `status: "blocked"` upsert, with a `reason` of `first_blocked_event` or `status_blocked`); `apikey.created` (carries the key's display hint and role only, never the plaintext) |

### Ingest (daemon → API)

Auth: `Authorization: Bearer <ingest_token>` + `X-PV-Deployment: <deployment_id>`.

**Token shape.** Ingest tokens are minted as `pv_live_` followed by 32
base64url characters (24 random bytes). The stored and displayed hint is
the first 16 characters (`pv_live_` plus 8). Tokens minted before the
prefix existed have no prefix and keep working; their hint is 8 raw
characters. Programmatic API keys use a different prefix, `pv_srv_`.

**Connecting a daemon.** The console's "Connect your daemon" card on a
deployment page prints exactly the three variables `pvctl console-sync`
reads (`crates/pv-cli/src/console_sync.rs`):

```sh
PV_CONSOLE_URL=https://api.proofvisor.com      # the bare API origin, no path
PV_CONSOLE_DEPLOYMENT=<deployment id>
PV_CONSOLE_TOKEN=<ingest token, shown once at create or rotate>
pvctl console-sync --watch
```

`PV_CONSOLE_URL` is the API origin only; `pvctl` appends `/api/v1/ingest`
itself. (While `api.proofvisor.com` is pending DNS, the origin is
`https://agentvisor-api.onrender.com`; for a self-hosted API it is that
server's origin.) The daemon never calls the console on its own: the
uploader is this separate, opt-in command.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/ingest/pubkey` | `{ publicKeyHex }` — anchored on first set; rotation refused |
| `POST` | `/ingest/sessions` | Upsert a session (idempotent on `externalId`); `quarantined_crash_evidence` permanently marks incomplete recovered evidence |
| `POST` | `/ingest/events` | Array of events, deduped on `(session, seq)` |
| `POST` | `/ingest/receipts` | Signed receipt at seal (key-id must match the anchor) |
| `GET` | `/ingest/policies` | The org's enabled policies as one bundle: `{version: 1, orgId, deploymentId, generatedAt, etag, policies: [{id, name, kind, scope, enabled, updatedAt, spec, body}]}`, sorted by name. `etag` is the SHA-256 hex of the canonical JSON of `policies` and is also sent as the `ETag` header; `If-None-Match` with the current etag (bare, quoted, weak or in a list) answers 304. Pulled by `pvctl console-sync --watch --pull-policies` |
| `POST` | `/ingest/policy-status` | `{etag, appliedAt, daemonVersion?, applied: [policy ids], unsupported: [{id, reason}]}` — what the daemon now enforces. One row per deployment; an etag change writes a `policy.applied` audit entry. Answers `{ok, etag, currentEtag, stale}` |

### Public (no auth)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/public/receipt-keys/:deploymentId` | The Ed25519 key a deployment's daemon pinned, for the `/verify` page: `{deploymentId, deploymentName, publicKeyHex, publicKeyB64, keyId, pinnedAt, orgName}`, or 404 before a key is pinned. CORS `*` without credentials, rate limited to 60 per minute per IP, cacheable for 5 minutes. A verify link shared from the console carries `&deployment=<id>&api=<origin>`, and the page compares the receipt's key with this pinned key |

### Read (authed user)

| Method | Path | Notes |
|---|---|---|
| `GET`  | `/overview` | Session totals and time-series for the selected UTC bucket window, plus fleet counts and recent sessions. `stats` includes `events` (total event count) alongside `sessions`, `live`, `sealed`, `blocked`, cost and tool counters |
| `GET`  | `/sessions` (+ `/sessions/:id`) | Cursor-paginated list; detail with cursor-paginated events + receipt; `eventCount` remains the total across all pages. Both the list rows and the detail carry `policiesFired`, the names of the policies that fired in that session |
| `GET`  | `/receipts/:sessionId` | Raw receipt + deployment public key for offline verify |
| `GET`  | `/audit` (+ `/audit.csv`) | Cursor-paginated audit trail; CSV streams up to 10k rows |
| `GET`  | `/stream` | SSE: session/event/receipt updates, multi-instance via PG LISTEN/NOTIFY |

### SCIM 2.0 provisioning

Owners manage SCIM under `/api/v1/scim`: `GET`/`PATCH /settings`
(`enabled`, `defaultRole` member|admin, `deprovisionAction`
deactivate|remove) and `GET`/`POST`/`DELETE /tokens[/:id]`. A token is
`pv_scim_` plus 32 base64url characters, shown once and stored as an
argon2 hash. Every change is audited (`scim.*`).

The identity provider talks to `<API origin>/scim/v2` with
`Authorization: Bearer pv_scim_…` (the org comes from the token):
`ServiceProviderConfig`, `ResourceTypes`, `Schemas`, and `Users` and
`Groups` with `filter` (`userName eq`, `externalId eq`, `displayName
eq`), `startIndex`/`count` paging, `POST`, `PUT`, `PATCH`
(add/replace/remove) and `DELETE`. Responses use
`application/scim+json` and SCIM error bodies with `scimType`.

- Creating a user whose email is new makes an account with a random
  password and a verified email, and a membership with the default role.
- `active: false` or `DELETE` runs the deprovision action: `deactivate`
  revokes the member's sessions and API keys and blocks sign-in to this
  org until the IdP re-activates them; `remove` deletes the membership.
- Groups map to roles by name: a group called `owner`, `admin` or
  `member` gives its members that role; removing someone from a role
  group falls back to the default role; other groups have no effect.
- The last active owner can never be deactivated, removed or demoted.
- SCIM never attaches an account that already belongs to another
  workspace (409 `uniqueness`; invite that person instead). For an
  account shared with another workspace through an invite, SCIM changes
  only this workspace's membership: never the login email, the name, or
  the sessions the person has in other workspaces. SCIM-created
  accounts are not marked as having a verified mailbox, like SAML
  just-in-time accounts, so they can never capture a later Google or
  Microsoft sign-in.

### Billing and plan limits

`GET /api/v1/billing` returns the plan, its status and renewal date,
the limits, current usage, and two flags: `configured` (Stripe is set
up) and `enforced` (limits apply). `POST /checkout {plan}` and
`POST /portal` (owner only) return a Stripe Checkout or Customer Portal
URL. `POST /webhook` verifies the `Stripe-Signature` over the raw body,
ignores a repeated event id, and handles `checkout.session.completed`
and `checkout.session.async_payment_succeeded` (a checkout still
`unpaid` grants nothing), `customer.subscription.created|updated|deleted`
and `invoice.payment_failed` (status `past_due`).

| Variable | Purpose |
| --- | --- |
| `STRIPE_SECRET_KEY` | Enables billing. Without it checkout and portal answer 503 `billing_not_configured`. |
| `STRIPE_WEBHOOK_SECRET` | Required to accept webhooks. |
| `STRIPE_PRICE_TEAM_MONTHLY`, `STRIPE_PRICE_ENTERPRISE_MONTHLY` | Recurring Price ids of the paid plans. |
| `PLAN_LIMITS_ENFORCED` | `true` to enforce the limits below; requires `STRIPE_SECRET_KEY`. Default `false`: every workspace keeps every feature. |
| `PLAN_<PLAN>_<LIMIT>` | Override one limit, for example `PLAN_FREE_DEPLOYMENTS=5` or `PLAN_TEAM_SAML=true`; `0` or `unlimited` removes a cap. |
| `STRIPE_API_BASE` | Test-only stand-in for api.stripe.com; refused in production. |

Default limits, applied only when `PLAN_LIMITS_ENFORCED=true`, and only
to new creations (nothing a workspace already has is removed):

| Plan | Deployments | Members + invites | Max retention | Webhooks | SAML | SCIM |
| --- | --- | --- | --- | --- | --- | --- |
| free | 2 | 3 | 30 days | 1 | no | no |
| team | 10 | 25 | 365 days | 10 | yes | yes |
| enterprise | unlimited | unlimited | unlimited | unlimited | yes | yes |

A refused creation answers 402 `plan_limit_reached` naming the limit,
the current plan and the plan that lifts it.

## Testing

Five layers, all runnable locally and (except the browser drills'
prod target) wired into CI:

- **`npm test`** — the `node:test` unit and recovery suites under
  `ci/*.test.mjs` (startup env guard, container entrypoint, bus and
  datasource recovery, multi-instance, external auth). No database or
  running server is needed. On 2026-10-30 this was 66 tests across
  8 files, all passing.
- **`ci/e2e.mjs`** — API contract suite (141 checks as of 2026-10-31).
  Boot the server, then `API_BASE=http://127.0.0.1:<port> node ci/e2e.mjs`.
  Runs in the Console + API workflow.
- **`scripts/run-drill-battery.sh`** — the 17 DB-backed drills
  (apikey ×2, invite ×2, ip-allowlist, retention, saml ×2, webauthn ×2,
  webhook ×3, oidc, crash-evidence quarantine, policy push, and the
  public receipt key with the live demo). Boots a fresh server per drill
  on 204xx and 207xx ports. Needs a Postgres the drills can `docker exec psql` into:
  `PG_CONTAINER=<container> PG_USER=pv PG_DB=pvdb bash scripts/run-drill-battery.sh [drill…]`.
  Runs in CI on every `server/**` change (api-drills workflow).
  Set `SPA_ORIGIN` when running `scripts/quarantine-drill.mjs` directly
  to also check the live browser's incomplete-evidence warning and disabled
  receipt actions. Recovered events remain appendable and idempotent;
  quarantined sessions cannot return to live status or receive a receipt.
- **Browser drills** (`scripts/a11y-audit.mjs`, `interactive-drill.mjs`,
  `mobile-smoke.mjs`, `engine-matrix.mjs`, …) — Playwright suites the
  console-smoke workflow runs against the deployed console after every
  Pages deploy. Point `SITE=` at any served copy for local runs.
- **Daemon drills** (repo root `scripts/`) — `demo-agent.mjs` (offline
  storyline, exit 0 = 10 beats), `crash-drill.mjs` (SIGKILL durability
  + quarantine semantics; sync leg needs `CONSOLE_URL`/`DEPLOYMENT_ID`/
  `TOKEN_FILE`). Probe gotcha: `/mcp` tool executions are
  idempotency-keyed by (session, JSON-RPC id, tool, args) — reuse an id
  and you get the cached outcome, not a re-execution; use unique ids
  unless you are testing replay.
  With current binaries already built, run the complete console contract with
  `API_BASE=http://127.0.0.1:8985 PROOFVISORD=/absolute/path/proofvisord PVCTL=/absolute/path/pvctl node scripts/daemon-console-drill.mjs`.
  This runner creates its own test workspace and credentials, runs the real
  SIGKILL/restart/sync drill, and deletes only that workspace afterward.
  Missing binaries fail the run instead of skipping synchronization.

## Security posture

Full production checklist is in [DEPLOY.md](./DEPLOY.md#security-posture-2026-baseline).
In short:

- `/metrics` (Prometheus) answers 404 in production unless
  `ALLOW_METRICS_IPS` lists the scraper's addresses or CIDRs; it used to
  be public whenever that variable was unset.

- Argon2id password hashing.
- HttpOnly, SameSite=Lax, Secure session cookies. HS256 JWT.
- Uniform login response time regardless of user existence.
- Every read query is org-scoped through the session claim — no route
  accepts a user-supplied org id.
- Ingest tokens are argon2-hashed at rest; plaintext returned only once.
- Global rate limit: 300 rpm per client IP on each API instance (not per user — the global
  bucket keys on `req.ip` per R93 F1 / R100 F1 in `src/index.ts`;
  a cookie/sub-derived key would let an attacker plant a fresh random
  cookie per request and bypass the cap). Buckets are held in process memory:
  restarting an instance resets them, and requests spread across multiple
  instances receive a separate allowance on each. Enforce a fleet-wide limit
  at the ingress if the deployment requires one. Auth-tree endpoints
  (`/login`, `/signup`, `/reset-*`, `/webauthn/*`) use tighter per-IP route
  buckets that replace the global bucket. Cookie session listing and detail
  reads have limits of 30 and 60 requests/minute respectively; authenticated
  API-key clients are exempt from those two route limits. Ingest is exempt
  from the global limit.
- CORS locked to `ALLOWED_ORIGINS`.
- `helmet` sets HSTS 2y (preload), strict CSP, X-Frame-Options: deny.
- The container runs as UID 65532. Its Node entrypoint forwards shutdown signals
  to the API or migration process group and preserves the child's exit status.
- Request body cap: 4 MiB.

## Evidence storage

Uploaded event content can contain prompts, completions, and tool arguments
after the daemon's configured redaction. The console stores that captured
content along with session metadata and signed receipts, and restricts access
by organization and role. The customer's daemon runs on their infrastructure
and controls which evidence it uploads. Configured provider API keys remain
with the daemon and are not part of console synchronization.
