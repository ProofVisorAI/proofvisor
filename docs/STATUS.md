# ProofVisor status

Service status and SLO targets, edited by hand. Nothing on this page is
updated automatically.

## Current status

**Demo surfaces operational · hosted API live (demo-scale)** — last
verified: 2026-11-01.

- **Console** (`proofvisor.com/app/`) — nominal (mock mode by
  default: the full product experience against built-in fixtures;
  nothing leaves the browser. Append `?live=1` to run the same page
  against the hosted API; `?live=0` reverts)
- **Site + verifier** (`proofvisor.com`, `/verify/`) — nominal. Both
  are GitHub Pages, served from the snapshot repository
  `ProofVisorAI/proofvisorai.github.io` with `proofvisor.com` as the
  custom domain. DNS for `proofvisor.com` points at GitHub Pages
  (A records 185.199.108–111.153; `www` CNAME to
  `proofvisorai.github.io`), and HTTPS is enforced.
- **Installer + public repo** (`proofvisor.com/install.sh`,
  `github.com/ProofVisorAI/proofvisor`) — nominal, exercised nightly
  by the `public-consumer` workflow
- **Hosted API** — **live** on the free-tier stack from
  `server/DEPLOY.md`: a Render web service named `proofvisor-api` (created as `agentvisor-api`)
  (Ohio, Docker image from `server/Dockerfile`), reachable at
  `https://api.proofvisor.com`, plus Neon Postgres
  (us-east-2, direct/unpooled URL so the LISTEN/NOTIFY bus works) and
  the Resend mailer (domain `proofvisor.com` verified; sender
  `ProofVisor <no-reply@proofvisor.com>`). The custom
  domain `api.proofvisor.com` is **live** (CNAME to
  `agentvisor-api.onrender.com`, certificate issued by Render, set up
  2026-11-01; `api.agentvisorai.me` and the Render hostname
  `https://agentvisor-api.onrender.com` still answer). Auto-Deploy
  is on and set to "After CI Checks Pass" (since 2026-11-01): a merge to
  `main` deploys once that commit's GitHub checks are green. Manual Deploy
  in the Render dashboard is still available, but note that it, and saving
  environment variables, deploy the latest commit without waiting for CI. Nothing runs on Fly.io;
  `server/fly.toml` and the `deploy-fly` workflow job are unused. A
  `keepalive.yml` cron pings `/healthz` every 10 min to avoid
  free-tier spin-down. The SLO table below is still the launch
  template: no uptime monitor has been pointed at the live instance
  yet, so no SLI has been measured. Treat any claim to the contrary as
  a bug in this page.

## Service level objectives

The demo runs on the free tier of everything. These SLOs are what the
demo-scale deployment aims for; anything above 100 daily active users
should upgrade to paid plans (see `server/DEPLOY.md`).

| SLI | Target | Current | Measured over |
|---|---|---|---|
| API availability (`GET /readyz` 2xx) | 99.5% | not yet measured (no uptime monitor attached) | 30 days |
| API p95 latency | < 200 ms | not yet measured (no Prometheus scrape of the live instance) | 30 days |
| API p99 latency | < 500 ms | not yet measured | 30 days |
| Ingest success rate | 99.9% | not yet measured | 30 days |
| Real-time delivery latency | < 1 s | not yet measured | 30 days |

The targets are goals, not observed values. The "Current" column is
filled in only once a monitor has run against the live instance for
the full measurement window.

## Incident history

_(new deployments log incidents here — one row per incident)_

| Date (UTC) | Duration | Impact | Postmortem |
|---|---|---|---|
| _(none yet)_ | | | |

## Uptime monitoring

No external uptime monitor is attached yet. The only scheduled check is
`keepalive.yml`, which requests `/healthz` every 10 minutes to keep the
free instance awake; it does not record availability. Recommended
free-tier providers:

- [BetterStack](https://betterstack.com/uptime) — free 10 monitors, 3 min
  cadence, email + Slack alerts.
- [Cronitor](https://cronitor.io) — free 5 monitors + heartbeat checks
  for the nightly `backup.yml` cron.
- [UptimeRobot](https://uptimerobot.com) — free 50 monitors, 5 min
  cadence.

Point the monitor at the custom domain. The Render hostname also answers
and can serve as a second check:

```
https://api.proofvisor.com/healthz
https://agentvisor-api.onrender.com/healthz   # Render hostname
```

Expect a 200 with `{"ok":true,"version":"…"}`. Also monitor the static
surfaces: `https://proofvisor.com/app/` and
`https://proofvisor.com/build.txt` (the deploy-convergence marker).

For deeper checks, prod-mode healthchecks should hit `/readyz` too — a
503 there means the DB (or the LISTEN/NOTIFY bridge) is degraded.

## Contact

Incidents: post in-repo issues tagged `incident:`. For anything
sensitive, open a private security advisory at
https://github.com/ProofVisorAI/proofvisor/security/advisories/new .
