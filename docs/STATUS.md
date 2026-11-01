# ProofVisor status

Real-time SLO tracker. Curated by the on-call.

## Current status

**Demo surfaces operational · hosted API live (demo-scale)** — last
verified: 2026-10-30.

- **Console** (`proofvisor.com/app/`) — nominal (mock mode by
  default: the full product experience against built-in fixtures;
  nothing leaves the browser. Append `?live=1` to run the same page
  against the hosted API; `?live=0` reverts)
- **Site + verifier** (`proofvisor.com`, `/verify/`) — nominal. Both
  are GitHub Pages, served from the snapshot repository
  `ProofVisorAI/proofvisorai.github.io` with `proofvisor.com` as the
  custom domain. DNS for `proofvisor.com` is being pointed at GitHub
  Pages (A records 185.199.108–111.153; `www` CNAME to
  `proofvisorai.github.io`).
- **Installer + public repo** (`proofvisor.com/install.sh`,
  `github.com/ProofVisorAI/proofvisor`) — nominal, exercised nightly
  by the `public-consumer` workflow
- **Hosted API** — **live** on the free-tier stack from
  `server/DEPLOY.md`: a Render web service named `proofvisor-api` (created as `agentvisor-api`)
  (Ohio, Docker image from `server/Dockerfile`), reachable today at
  `https://agentvisor-api.onrender.com`, plus Neon Postgres
  (us-east-2, direct/unpooled URL so the LISTEN/NOTIFY bus works) and
  the Resend mailer (no verified domain yet — delivery restricted to
  the operator address until DNS records are added). The custom
  domain `api.proofvisor.com` is **live** (CNAME to
  `agentvisor-api.onrender.com`, certificate issued by Render, set up
  2026-11-01; `api.agentvisorai.me` still answers). Auto-Deploy is off:
  deploy with Manual Deploy in the Render dashboard. Nothing runs on Fly.io;
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

The pitch demo uses a single external prober checking `/healthz` every
60 s. Recommended free-tier providers:

- [BetterStack](https://betterstack.com/uptime) — free 10 monitors, 3 min
  cadence, email + Slack alerts.
- [Cronitor](https://cronitor.io) — free 5 monitors + heartbeat checks
  for the nightly `backup.yml` cron.
- [UptimeRobot](https://uptimerobot.com) — free 50 monitors, 5 min
  cadence.

Point the monitor at the Render hostname today, and switch to the
custom domain once its CNAME resolves:

```
https://agentvisor-api.onrender.com/healthz   # live now
https://api.proofvisor.com/healthz            # once DNS resolves
```

Expect a 200 with `{"ok":true,"version":"…"}`. Also monitor the static
surfaces: `https://proofvisor.com/app/` and
`https://proofvisor.com/build.txt` (the deploy-convergence marker).

For deeper checks, prod-mode healthchecks should hit `/readyz` too — a
503 there means the DB (or the LISTEN/NOTIFY bridge) is degraded.

## Contact

Incidents: post in-repo issues tagged `incident:` or email
security@proofvisor.com for anything sensitive.
