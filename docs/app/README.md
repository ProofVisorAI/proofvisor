# ProofVisor Console

> **Changing this code?** Read [HANDBOOK.md](./HANDBOOK.md) first — the
> invariants, bug classes, and harness traps from the hardening campaign,
> each backed by a CI guard.

The console served at `proofvisor.com/app/` is a real multi-tenant SPA:
sign in, view your fleet of policed agent sessions, add & rotate deployment
ingest tokens, and inspect any session's event stream and signed receipt.

## Two operating modes

The console is built as a client-side app with a swappable data source. The
switch lives at the top of [`index.html`](./index.html):

```html
<script>
  window.MOCK_MODE = true;
  window.API_BASE = "";
</script>
```

### Mock mode (default — investor / preview use)

When `MOCK_MODE=true` the console runs against built-in **Northwind Traders**
fixtures baked into [`datasource.js`](./datasource.js). Anyone landing on the
URL sees a fully populated workspace: 2 deployments, 7 sessions with events
and receipts, headline KPIs. Any email + password combination signs you in.

This is what powers the investor pitch and the public demo. The backend is
deployed (see [Live mode](#live-mode)), but mock mode stays the default so a
visitor needs no account. Mock mode also ships three investor-facing extras
(all inert in live mode):

- **Guided tour** ([`tour.js`](./tour.js)) — a six-step spotlight walkthrough
  of the money story: prevented losses → the blocked session → the exact
  blocked event → the signed receipt → the public verifier. Launched from
  the floating "See the full flow" pill, the command palette, or the
  `/app/?tour=1` deep link used by the landing-page CTA.
- **Simulate an attack** (Overview header, also in the palette) — stages a
  live blocked payment: an in-progress purchase session appears, the
  payment gets blocked ~4.5 s later, and every stat, chart, and receipt on
  screen catches up in real time.
- **Onboarding checklist** (Overview, fresh workspaces) — after signup a
  four-step "Getting started" card (workspace → daemon → sessions →
  first block) ticks itself live as the fresh-workspace simulation
  progresses, without a reload.

### Live mode

Append `?live=1` to the console URL (persists in `localStorage`;
`?live=0` reverts to mock), or set statically in `config.js`:

```js
window.MOCK_MODE = false;
window.API_BASE = "https://api.proofvisor.com";
```

(The origin only — request paths already include `/api/v1`.)

…and the same UI now talks to the real hosted backend defined in [`../../server/`](../../server/).
Signup / login create real users and orgs. Deployments mint real ingest
tokens. Session data is streamed by real `proofvisord` daemons.

Live mode also has the guided tour (steps whose target is missing
are skipped), a "Getting started" checklist built from real state (a
deployment exists, a real session arrived, a policy exists, a second
member or a pending invite), which disappears when everything is done
and can be dismissed, and "⚡ Simulate an attack" for owners and
admins. The attack stages one blocked-payment session under a
`demo-attack` deployment; every table labels its rows "demo", its
receipt is signed with the public demo key (so `/verify` calls it a
demo receipt), and "Remove demo data" on the Overview or the
deployment page deletes it.

See [`server/README.md`](../../server/README.md) for the full deploy runbook.

## Structure

| File | Purpose |
|---|---|
| `index.html` | Entry, sets `MOCK_MODE`, mounts `#app` |
| `styles.css` | Design tokens + shell / auth / cards / tables |
| `datasource.js` | Swappable data layer — `MockDataSource` vs `ApiDataSource` |
| `app.js` | Hash router, auth, view renderers |
| `pitch/` | The original scripted narrative walkthrough (kept for reference) |

## Views

- `#/login`, `#/signup`, `#/reset`, `#/confirm-email` — unauth
- `#/overview` — 24h fleet KPIs + recent sessions
- `#/sessions` — full list
- `#/sessions/:id` — event stream + signed receipt for one session. The
  event drawer shows the event body exactly as the daemon journaled it;
  the waterfall places bars by timestamp (ingested events carry no
  measured duration); the header shows the model recorded on the
  session's LLM events, or nothing — never a default model. Each session
  also lists the names of the policies that fired (`policiesFired`).
- `#/deployments` — create, rotate token, delete; each row shows the
  last 24 hours' sessions and spend (spend is hidden from members). The
  deployment page's "Connect your daemon" card prints exactly
  `PV_CONSOLE_URL=<API origin>`, `PV_CONSOLE_DEPLOYMENT=<deployment id>`,
  `PV_CONSOLE_TOKEN=<token shown once>` and the command
  `pvctl console-sync --watch`. The URL is the bare API origin; `pvctl`
  appends `/api/v1/ingest` itself. Ingest tokens look like `pv_live_`
  plus 32 characters, and the table shows only the first 16.
- `#/policies` — policy definitions (create, edit, enable/disable).
  The create dialog starts from a template (spend cap, vendor
  allowlist, tool allowlist, token rate limit, PII guard) and writes
  the JSON spec for the daemon-enforceable kinds (`budget`,
  `allowlist`, `rate`, `schema`), validated before saving exactly as
  the server validates it. Daemons that run
  `pvctl console-sync --watch --pull-policies` pull every enabled
  policy as one bundle; each policy shows an enforcement badge such as
  "Enforced by 2 of 3 daemons", names a daemon that still has an older
  bundle, or says "Not enforceable by daemons" for `guardrail` and
  `transform` policies, which document a rule and attribute the
  daemon's own guard hits to its name. A deployment's page shows the
  bundle etag and time its daemon last applied.
- `#/settings` — tabbed: `general` (org/user metadata + mock-mode escape
  hatch), `members` (roles and invites; the table columns are Person,
  Role, Joined), `keys` (API keys with prefix `pv_srv_`; the table has a
  Role column and the create dialog has a role selector — owner, admin
  or member, never above your own role), `sso` (SAML / OIDC / passkeys),
  `webhooks` (endpoints and deliveries; the server emits `test`,
  `member.invited`, `policy.block`, `session.blocked` and
  `apikey.created`), `audit` (trail + CSV export), `billing` (free
  preview; the Team and Enterprise plans shown there are not purchasable
  yet, and SCIM provisioning does not exist on the server)

## The scripted pitch demo

The linear investor walkthrough previously served at this URL now lives at
[`pitch/`](./pitch/). It's a scripted narrative — Northwind Traders onboards,
first agent session flows through, a rogue purchase order is blocked, a
signed receipt is minted, and audit evidence is exported. Useful when the
audience needs the story, not a playground.
