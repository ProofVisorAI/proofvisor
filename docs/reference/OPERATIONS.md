# ProofVisor Operations Guide

This document is the operator's tour of the harness. It covers boot,
health probes, upgrade, key rotation, spool recovery, and the metrics
you should alert on.

## Boot

`proofvisord` reads its TOML from `$PV_CONFIG` (if set), then
`./proofvisor.toml`, `./config/harness.toml`, `./agentvisor.toml`, and
`$HOME/.proofvisor/proofvisor.toml`. The example file
(`config/harness.example.toml`) is NOT searched.

Installations made before the ProofVisor rename keep working:
`./agentvisor.toml` is still found (after the new names), so is
`$HOME/.agentvisor/agentvisor.toml` when the new per-user file does not
exist, and both `proofvisord` and `pvctl` copy every `AV_*` environment
variable to its `PV_*` name when the `PV_*` one is unset, printing which
ones on stderr. Rename them when convenient; the old names will be
removed in a later release.

On boot the harness logs a dedicated event on the `trust_anchor`
target:

```
signer_key_id=<32-hex fingerprint>
signer_public_key_hex=<64-hex Ed25519 public key>
signer_seed_path=<path the seed was loaded from>
freshly_generated=<true only when the seed was created this boot>
```

Every restart re-emits this pair unconditionally: the `trust_anchor`
target is pinned to INFO inside the process regardless of `RUST_LOG`,
so it survives `RUST_LOG=warn`, `error`, and even `off`. When the seed
is freshly generated at startup (no seed file was present at the
configured path), a WARN is added on the same always-on target: this is
normal for a first-run container but is a hard escalation for a
persistent deployment — you've lost your seed file and the new key
won't verify old receipts.

Pipe these lines into your log store and diff them across restarts;
any change is a rotation event that must be reflected in the
downstream trust store.

## Health probes

Three routes with distinct semantics:

| Route | Purpose | Failure mode |
| --- | --- | --- |
| `/health` | Legacy constant 200 (kept for backwards compatibility with pre-`/livez/readyz` deployments; identical to `/livez` today). | Only fails when the axum runtime is dead; prefer `/livez`/`/readyz` for new probes so the semantic split is explicit. |
| `/livez` | Kubernetes-style liveness. Returns 200 constant. | Only fails when the axum runtime is dead; use as `livenessProbe`. |
| `/readyz` | Kubernetes-style readiness. 200 while accepting new traffic; 503 during drain. | Fails immediately when SIGTERM is received AND while the spool is not **writable** (probe file create+remove — a full disk or read-only remount flips readiness even though the directory stays readable). Use as `readinessProbe`. |

`readinessProbe` is the one that turns off the tap during pod
deregistration — flip a request-counter graph and you'll see the
last 5 seconds of traffic drop off before the process actually
terminates.

The included Kubernetes manifest at
`deploy/kubernetes/proofvisor.yaml` wires **liveness and readiness**
(via `startupProbe`, `readinessProbe`, and `livenessProbe` against
`/livez` and `/readyz`) and uses the daemon's own readiness-controlled
pre-drain window (ConfigMap key `shutdown_ready_drain_s = 5`) instead
of a `preStop` shell hook — the shipped runtime base image
(`chainguard/glibc-dynamic`) is distroless and has no `/bin/sh` /
`/bin/sleep`, so a `preStop: exec: ["sh", "-c", "sleep 5"]` hook would
have failed `FailedPreStopHook` and kubelet would have proceeded
straight to SIGTERM. `/health` exists only for pre-`/livez`/`/readyz`
deployments and mirrors `/livez` — new deployments should probe
`/livez` and `/readyz` directly.

## Shutdown

`proofvisord` shuts down cleanly on SIGTERM. The order is:

1. Set the `draining` flag → `/readyz` starts returning 503.
2. If `shutdown_ready_drain_s > 0` (default 0), keep ACCEPTING
   connections for that long so an external load balancer polling
   `/readyz` actually observes the 503 before the listener closes.
   Without it, step 3 begins immediately and a fresh readiness probe
   sees connection-refused instead. This applies to every deployment
   target — Kubernetes distroless images (like the shipped
   `chainguard/glibc-dynamic` runtime) cannot use a preStop shell
   hook, and docker-compose / systemd / bare-LB deployments have no
   preStop equivalent at all. Set this to your LB's poll interval
   plus one reconciliation (5 s covers a typical kube-proxy /
   ingress reconciliation and matches the shipped ConfigMap).
3. Await axum's graceful shutdown (in-flight requests complete;
   new TCP accepts are refused).
4. Abort background tasks (reconciler tick, retention sweep, etc.).
5. Flush and close the state store, broker, and Bridge.

On Windows there are no POSIX signals: the daemon runs the same five
steps on Ctrl-C (`tokio::signal::ctrl_c`, which also covers the console
close and logoff control events). A service manager that stops the
process without a console control event ends it without a drain; see
[`docs/PLATFORMS.md`](../PLATFORMS.md#windows) for the other Windows
differences (no `0600` checks on secret files, no directory fsync).

Step-3 tail latency that exhausts the drain budget shows up as
`pv_http_shutdown_drain_timeouts_total`. Alert on any increase — it
usually means a request was stuck waiting on the upstream and the
worker pool couldn't drain before the timeout. The pre-drain window
counts against the orchestrator's kill grace period ON TOP of the
drain budget.

## Key rotation

1. Generate a new seed: `pvctl keygen --output signer.new.seed`.
2. Publish its public key to your downstream trust store BEFORE the
   next step. Use `pvctl pubkey --seed signer.new.seed` to derive
   `public_key_hex` and `key_id` without exposing the seed.
3. Replace the running seed file atomically (`mv`, not `cp`).
4. `SIGHUP` is **not** wired for reloading; you must restart the
   process. Rolling restarts across a fleet are fine — each pod
   emits a startup log with the new key id.
5. The `pv_receipts::keys::Keyring` on the verifier side must have
   the new key added; old receipts continue to verify against the
   old key until they age past your retention.

## Spool recovery

The reconciler runs every `reconcile_tick_s` seconds and handles:

* **Pending-close sessions:** an ATIF spool file exists but the
  close bridge event wasn't emitted (crash mid-close). Recovery
  re-adopts the on-disk journal, emits `SESSION_CLOSE`, and
  finalizes.
* **Orphan .json files (round 51 §8.5):** a `.json` with no
  `.atif-auth` sidecar is quarantine-renamed to
  `<name>.json.corrupt-<uid>` — but only after (a) age > 60s and
  (b) the stem is not that of a currently-open session. The
  live-stem check closes the race where a mid-close write is
  quarantined out from under the finalize path.
* **Sealed pair retention (round 51 §8.1):** when
  `atif_retention_days` is set, sealed pairs are pruned every hour.
  Unpaired remnants are LEFT for the orphan sweep. The same sweep is
  available manually as `pvctl spool-prune --spool <atif_spool_dir>
  --retention-days N` (external cron, one-off reclaims).
* **Signed-workflow recovery:** if a signed session's receipt is
  missing but its journal is intact, recovery re-signs and emits.

Recovery is idempotent — a killed-then-restarted-then-killed pod
does the same work each tick without duplicating events.

## Console sync

`pvctl console-sync` uploads durable local spool evidence to the hosted
console ingest API. It reads ATIF trajectories from `atif_spool_dir`
(default `spool/atif`), skips archived collision artifacts, posts one
session upsert plus ordered event batches of at most 500 events, then
uploads signed receipts from `receipts/`. When `--bridge-dir` is set it
also tails the embedded Bridge topic logs after the ATIF pass so signed
workflow sessions (which have receipts but no ATIF trajectory) publish
their durable OCSF events.

```
pvctl console-sync --spool-dir /var/lib/proofvisor/spool/atif \
  --bridge-dir /var/lib/proofvisor/data/bridge \
  --console-url https://console.example.com \
  --deployment dep_123 \
  --token-file /run/secrets/pv-console-token
```

The console URL is the API's bare origin (`https://api.proofvisor.com`
for the hosted console; a self-hosted API's origin otherwise). `pvctl` appends `/api/v1/ingest` itself, so do not include a
path. The console's deployment page prints these three values ready to
paste, together with `pvctl console-sync --watch`.

Configuration precedence is CLI flags, then `PV_CONSOLE_URL`,
`PV_CONSOLE_DEPLOYMENT`, `PV_CONSOLE_TOKEN`,
`PV_CONSOLE_BRIDGE_DIR`, then an optional `~/.proofvisor/console.toml`
file (or legacy `[console]` table in the effective `proofvisor.toml`):

```toml
[console]
url = "https://console.example.com"
deployment = "dep_123"
token_file = "/run/secrets/pv-console-token"
bridge_dir = "/var/lib/proofvisor/data/bridge"
```

The token is never printed; token files are read with trailing
whitespace trimmed. Replays are idempotent: the state file
(`--state-file`, default `.console-sync-state.json` inside the spool)
records each session's last synced event sequence and whether its
receipt was accepted, plus the last synced Bridge offset per
topic/partition. The state file is bound to the console URL and
deployment that produced it; use a separate `--state-file` when syncing
to a different destination. ATIF-synced session ids are recorded so
Bridge events for unsigned sessions are not duplicated. Receipts are
posted only after all events visible in the current pass for that
session (ATIF or Bridge) are acknowledged, because sealing rejects later
event uploads. Use `--dry-run` to count what would be sent, or `--watch
--interval 30` to poll until Ctrl-C.

Bridge OCSF topics map to ingest events as follows:

| Bridge topic | Ingest kind | Notes |
| --- | --- | --- |
| `agent.session` | `sys` | `opened` sets `openedAt`; `closed` carries `workflow`. |
| `agent.tool_call` | `tool` / `block` | Allowed calls increment `addToolsAllowed`; blocked/denied calls increment `addToolsBlocked` and blocked payout micros when present. |
| `agent.stop_reason` | `guard` | Stop reason tag/body preserve the OCSF reason. |
| `agent.compression` | `audit` | Body includes metrics including pruned token count when present. |
| `agent.identity` | `audit` | Identity validation evidence. |
| `agent.receipt` | skipped | Receipts are uploaded separately from the receipt spool. |
| `agent.judge` | `audit` | Tag `judge`, with `trace`, `breaker` or `shadow` as the sub-label; never counted as a block. Uploaded only for sessions that first synced with a `pvctl` that knows this topic. A session that was already syncing before keeps its event numbering, so its judge events are not uploaded; read them from the Bridge (`pvctl event-tail --topic agent.judge`). |

`pvctl setup` can create the console config for you. At the end of the
guided setup, answer yes to "Connect to the hosted console?", accept or
enter the console URL, paste the deployment id and ingest token, then run:

```sh
pvctl console-sync --watch
```

### Pulling policies from the console

Policies created in the console reach a daemon only through
`console-sync` on the same host; the daemon itself never calls the
console. Set `policy_bundle_file` in the daemon config (see
[CONFIGURATION.md](CONFIGURATION.md#console-pushed-policy)) and add
the same path to the sync command:

```sh
pvctl console-sync --watch --pull-policies \
  --policy-bundle-file /var/lib/proofvisor/policies.json
```

Each pass sends `If-None-Match` with the bundle's etag and writes a
changed bundle atomically with owner-only permissions. The daemon
checks the file every `policy_bundle_poll_s` seconds, applies it, and
writes `policies.json.status.json` with the policy ids it now enforces
and the ones it could not enforce (with a reason, for example a kind or
spec field newer than the daemon). `pvctl` posts that file to the
console, which then shows "Enforced by N of M daemons" and names
daemons that still run an older bundle. Without `--watch`, `pvctl`
waits up to 20 seconds for the daemon to apply a new bundle before it
reports.

Pushed policies only tighten the host's own config: a pushed budget
cap binds only when it is stricter than the local `[budget]`, and
pushed allowlists and schemas run in addition to the local ones. If
the console were compromised it could block calls, but it could not
allow a call the local config refuses. A newer bundle file the daemon
cannot apply leaves the rules in force unchanged and records the error
in the status file; at boot, such a file stops the daemon, so it never
silently runs without rules it was given. `guardrail` and `transform`
policies are enforced when their body is the JSON spec described
below, and are documentation otherwise.

### Guardrail policies

A guardrail is a list of regular expressions that must not appear in
what an agent sends. The console accepts two kinds of guardrail body:

- **A JSON spec** (below). The console marks the policy enforceable,
  puts the parsed spec in the bundle, and daemons enforce it.
- **Free text** (anything that is not a JSON object). The console
  stores it as documentation only; a daemon lists such a policy in
  `unsupported` with the reason "guardrail policy has no JSON spec".
  Guardrails written before this spec existed keep working this way.

The spec:

```json
{
  "applies_to": "tool.args",
  "deny_patterns": ["\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b"],
  "effect": "block"
}
```

| Field | Meaning |
| --- | --- |
| `applies_to` | `tool.args`: every string value in the arguments of a tool call, for the tools the policy scope names (`tool.*`, `tool.<name>`, `tool.payments.*`). `llm.ingress`: every string value under `messages` in a chat request; the scope must be `llm`, `llm.*`, `llm.request` or `llm.ingress`. `llm.egress`: the text of every choice of a model response, as the daemon captures it; the scope must be `llm`, `llm.*`, `llm.response` or `llm.egress`. |
| `deny_patterns` | 1 to 64 regular expressions in the syntax of the Rust `regex` crate (no lookaround, no backreferences), each 1 to 512 bytes. A value that contains a match anywhere fires the rule. Daemons compile each pattern with the same bounds as `redaction_patterns` (`pv_redact::compile_pattern`): a pattern over the size or nesting limit, or one the daemon cannot compile, makes the whole policy unsupported on that daemon, with the reason shown in the console. |
| `effect` | Optional; only `block` is accepted, and it is the default. |

A JSON object that is not a valid spec is refused when the policy is
saved, with the reason, so a mistyped spec cannot silently become
documentation.

How a daemon enforces a guardrail:

- `tool.args` rules run at the policy stage, after the local policy
  chain and the pushed allowlists, before any budget is spent. The
  refusal is the usual JSON-RPC policy denial, naming the console
  policy: `policy "privacy.pii_egress": tool arguments match deny
  pattern 1 of 2 (at /customer/ssn)`.
- `llm.ingress` rules run at the sanitize stage of a chat request,
  before compression and before any token is charged. The refusal
  names the policy the same way, and the stop-reason event carries it
  in `payload.policy`, so `pvctl console-sync` uploads the refusal as a
  block attributed to that policy.
- `llm.egress` rules run on the response as the daemon captures it. A
  buffered (non-streaming) response is held until it is complete, so a
  match is refused with HTTP 403 naming the policy and no byte of the
  response reaches the client. A streamed response is scanned frame by
  frame (with a 1 KiB overlap, so a match that straddles two frames is
  still found, and a full rescan at the end of the body): a match in
  the first frame is refused with HTTP 403 like a buffered one; a
  match later, after frames have already been relayed, ends the stream
  with an error frame (`"type": "policy_blocked"`, `"code":
  "guardrail"`) naming the policy, and the frame that completed the
  match is never relayed. Either way the turn is attested as "Policy
  Blocked" with `payload.policy`, so the console counts the block.
  The response text, the reasoning content and tool-call arguments are
  all scanned; the refusal names the part that matched ("model
  reasoning matches deny pattern 1 of 2").
- The refusal, the log line and the audit event say which pattern
  (by position) matched and where (a JSON pointer); the matched text
  itself is never copied anywhere.
- Like every pushed rule, a guardrail only adds a restriction: a call
  the local config refuses stays refused.

### Transform policies

A transform is a list of regular expressions whose matches are
replaced before a call goes any further. Like a guardrail, the console
accepts two kinds of transform body: the JSON spec below (enforced) or
free text (documentation only, listed by daemons in `unsupported` with
the reason "transform policy has no JSON spec").

```json
{
  "applies_to": "tool.args",
  "redact_patterns": ["TCK-[0-9]{4}"],
  "replacement": "[ticket]"
}
```

| Field | Meaning |
| --- | --- |
| `applies_to` | `tool.args`: every string value in the arguments of a tool call, for the tools the policy scope names. `llm.ingress`: every string value under `messages` in a chat request; the scope must be `llm`, `llm.*`, `llm.request` or `llm.ingress`. `llm.egress`: the text, reasoning content and tool-call arguments of every choice of a model response; the scope must be `llm`, `llm.*`, `llm.response` or `llm.egress`. |
| `redact_patterns` | 1 to 64 regular expressions, with the same syntax and bounds as a guardrail's `deny_patterns`. Every match of every pattern is replaced. |
| `replacement` | Optional; the text each match becomes, 1 to 64 bytes, no control characters. `[REDACTED]` when omitted. `$` is literal, never a group reference. |

How a daemon enforces a transform:

- `tool.args` rules run before the tool call reaches the sandbox: the
  rewritten arguments are what the local policies and schemas check,
  what the verdict event journals, and what the backend receives. A
  body the strict JSON-RPC parser refuses (a duplicate key, say) is
  left alone, so the parse gate still refuses it.
- `llm.ingress` rules run after the sanitize stage (so a guardrail
  still sees the original text) and before compression, the token
  budget and dispatch. The compression record for the turn lists the
  transforms that fired as `payload.transforms` (policy name and the
  number of replacements); the matched text is stored nowhere.
- `llm.egress` rules run once the response is complete, after the
  egress guardrails have seen the original text. A buffered response is
  rewritten in its captured text and in the body before either is used,
  so the journal and the client see the same rewritten text, and the
  capture lists the transforms that fired (`payload.transforms`). A
  streamed response is held (nothing is relayed while it arrives) and
  then relayed with the provider's own frames: the first frame that
  carried a choice's content carries the whole rewritten text and later
  content deltas are empty; reasoning and tool-call argument deltas are
  handled the same way, and ids, finish reasons, usage and `[DONE]` are
  as the provider sent them. Streaming latency is therefore lost for
  the deployments that push such a rule.
- Every rewrite is logged with the policy name and counted in
  `pv_pushed_transform_rewrites_total`.
- A transform never widens anything: it only removes text, and every
  refusal a daemon would make on the original call it still makes on
  the rewritten one, except a guardrail over the very text that was
  removed.

### Releasing a quarantined session id

A SIGKILL / OOMKill / node loss mid-request leaves a sealed marker
under `<atif_spool_dir>/inflight-responses/`. On restart the
reconciler quarantines that session ("quarantining sessions with
incomplete effects") and the id returns
`400 session is already closed` from then on — by design, because
the provider may have observed a request whose response was never
captured, and silently resuming would put an unattested turn in the
audit chain.

If an agent derives its session id from a stable conversation id,
that conversation is locked out until an operator intervenes. The
manual release procedure:

1. Confirm the turn's outcome out of band (provider dashboard,
   upstream logs). You are asserting the uncaptured response either
   never happened or is acceptable to lose from the trail.
2. Stop routing traffic for that session id (or drain the pod).
3. Delete the session's marker file under
   `<atif_spool_dir>/inflight-responses/` — filenames are
   `sha256(session_id:attempt_id)[..32].json`, so a stuck session may
   have MULTIPLE markers (one per response attempt). Grep the
   directory for a `session_id` field match inside each file (they
   are small JSON blobs) rather than computing the digest by hand.
   Keep a copy if your compliance posture requires evidence of the
   intervention.
4. Restart the harness (or wait one reconcile tick). The quarantine
   set is rebuilt from the markers, so the id admits traffic again.

Do NOT delete markers as routine hygiene — each one is the only
evidence that a crash window may contain an unaudited provider
interaction.

## Semantic judge

The `[judge]` section is described in
[CONFIGURATION.md](CONFIGURATION.md#semantic-judge-judge). This section
covers running it.

### Rollout

| Phase | Configuration | What happens |
| --- | --- | --- |
| Shadow | `mode = "shadow"` | The judge scores every tagged call and never blocks. Each `agent.tool_call` event's `payload.judge.would_block` says whether judge-aware policy would have blocked a call the rest of policy allowed, and each such call is also published as its own `agent.judge` event (`payload.kind = "shadow"`). Compare that against what actually happened before enforcing. |
| Capped pilot | `mode = "enforce"` with `[judge.pilot] daily_block_cap` | Policy acts on the verdicts for the tagged tools, but at most `daily_block_cap` score-based blocks per tool per UTC day. Later ones are recorded (`pilot_cap_reached: true`) and let through. Tag only a few tools per design partner. |
| Scale | `mode = "enforce"`, no `[judge.pilot]` | Widen `[[judge.tools]]` once calibration holds. |

### Failure modes

| Failure | Behaviour | Denial code |
| --- | --- | --- |
| Deadline expired (`deadline_ms`) | `[judge.on_failure] timeout`: deny (default) or ask. | `JUDGE_UNAVAILABLE` or `APPROVAL_REQUIRED` |
| Judge crashed or unreachable | `unavailable`: deny (default) or ask. | `JUDGE_UNAVAILABLE` or `APPROVAL_REQUIRED` |
| Malformed output (wrong labels, not a probability distribution) | `malformed`: ask (default) or deny. Treated as the uncertain band. | `APPROVAL_REQUIRED` or `JUDGE_UNAVAILABLE` |
| Low confidence (top label below `min_confidence`) | Ask. | `APPROVAL_REQUIRED` |
| Judge saturated (`max_concurrency` calls in flight) | `saturated`: deny (default) or ask, for tagged tools only. Untagged tools are unaffected. Never a silent allow. | `JUDGE_UNAVAILABLE` or `APPROVAL_REQUIRED` |
| Model answers with an unpinned identity (cloud) | Deny, and an error log line. | `JUDGE_UNAVAILABLE` |
| Local model or tokenizer file does not hash to its pin | The daemon refuses to start and logs the hash it found. | none (boot error) |
| Local adapter configured in a build without the `onnx` feature | The daemon refuses to start; `pvctl config-validate` reports it. | none (boot error) |
| Background judge (`[judge.trace]`) fails, times out, or is saturated (`background_max_concurrency` verdicts in flight) | Nothing is blocked. The `agent.judge` event records the failure in its `verdict.status`, with no finding. | none |
| Breaker second opinion fails | The loop breaker keeps its own decision for that step. | none |
| Audit queue full when a finding is published | The finding is dropped and counted in `pv_judge_events_dropped_total`. | none |

Shadow mode never blocks, whatever fails; the failure is recorded in
the verdict's `status`. The process-level test
`judge_enforces_across_kill_and_restart_and_fails_closed_when_it_dies`
in `crates/pv-harness/tests/e2e_process_restart.rs` runs these paths
against the real binary across a SIGKILL and restart.

### Calibration

Before enforcing a model, measure it on a labelled set (JSON Lines;
format in `crates/pv-judge/src/calibration.rs`), seeded from shadow-mode
traces and design-partner calls:

```bash
pvctl judge-calibrate --config proofvisor.toml --adapter local-args \
  --set labelled.jsonl --min-examples 200 --min-auroc 0.9 \
  --min-separation 0.5 --require-monotone
```

It prints AUROC, separation, accuracy, and accuracy by confidence band
for each predicate, and exits non-zero when a floor is not met. Run it
in CI for the pinned model, and record the measured values next to the
floors with the date and the set they came from.

At runtime, `[judge.drift]` samples scored verdicts for human review.
A sampled verdict carries `review_id` in its record. A reviewer reports
whether the judge's most probable label was right:

```bash
curl -X POST https://proofvisor.internal/admin/v1/judge/reviews \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -d '{"review_id": "<review_id>", "correct": true}'
```

Accuracy is tracked per confidence band. When a higher band becomes
less accurate than a lower one (each with at least
`min_reviews_per_band` reviews, beyond `tolerance`), the predicate
switches to ask-by-default: judged calls that policy would allow are
held with `APPROVAL_REQUIRED`, and denials still deny. The switch logs a
warning, is saved to `[judge.drift] state_file` (the review response
says `"persisted": true`; a failed save is logged and counted in
`pv_judge_drift_persist_failures_total`), survives restarts, and stays
until an operator resets it, after recalibrating or replacing the
model:

```bash
curl -X POST https://proofvisor.internal/admin/v1/judge/drift/reset \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -d '{"predicate_id": "arg_matches_task@1"}'
```

`GET /admin/v1/judge/drift` returns the per-band counts. These routes
exist only when `operator_tokens` and `[judge.drift]` are both set.

### State kept per instance

The prior-denial log holds the refusals the judge sees as context. With
`state_backend = "redis"` it is kept in Redis as well as in each
process, so a delegated agent served by another instance sees the
refusals of the agents above it. Each list keeps the newest 16 refusals
and expires 24 hours after its last refusal. If Redis cannot be read,
the judge uses the instance's own entries and counts the failure in
`pv_judge_shared_denials_errors_total`. With the in-memory backend the
log lives only in the process. The sampled verdicts waiting for review
and the concurrency limit live in each harness process and start empty
after a restart; a review of a verdict sampled before a restart answers
`unknown_review_id`. The drift
statistics and switches are saved to each instance's `state_file`, so
they survive that instance's restarts but are not shared: give every
instance its own file, send each review to the instance that sampled
the verdict, and reset a switch on every instance where it tripped
(`GET /admin/v1/judge/drift` shows which). The pilot cap counters live
in the state store and are shared.

## Metrics you should alert on

| Metric | Alert condition | What it means |
| --- | --- | --- |
| `pv_atif_retention_pruned_total` | Sudden increase | Retention sweep ran (usually just noise, but confirm the `atif_retention_days` you set). |
| `pv_reconciler_last_tick_completed_seconds` | `time() - value > 5 × tick interval` | The reconciler tick is stalled (hung filesystem, lifecycle-lock deadlock) or has never completed since boot. Closes, promotion retries, idle finalization and outbox replay are all stopped with it. The series exists from boot and reads 0 until the first tick completes. |
| `pv_atif_recovery_skipped_total{reason="unauthenticated"}` | Rate > 0 sustained | Someone/something is planting sidecar-less .json files. Escalate. |
| `pv_atif_recovery_skipped_total{reason="too_large"}` | Rate > 0 | Adversarial ATIF payload attempts (> `MAX_ATIF_RECOVERY_BYTES`). Investigate the spool contents. |
| `pv_atif_recovery_skipped_total{reason="read_error"}` | Rate > 0 sustained | Recovery failed to open a spool file after `MAX_ATIF_RECOVERY_BYTES` metadata pre-check — disk / permission fault, or a symlink-plant beat the pre-check. Investigate the disk. |
| `pv_atif_recovery_skipped_total{reason="invalid_json"}` | Any occurrence | ATIF file bytes could not parse as JSON. Adversarial payload or bit-rot. Escalate. |
| `pv_atif_recovery_skipped_total{reason="nonconformant"}` | Any occurrence | ATIF parsed as JSON but failed strict-mode structural validation. Same class as `invalid_json` — either a hostile plant or a schema-version mismatch that the operator needs to reconcile. Escalate. |
| `pv_atif_recovery_skipped_total{reason="provenance"}` | Any occurrence | `.atif-auth` sidecar HMAC failed to verify against the current signer key. This is a cryptographic integrity failure — either a key rotation that missed the retirement window, or a tampered/planted trajectory. **Escalate immediately.** |
| `pv_incomplete_sessions_total` | Sudden increase | Sessions where `capture_failed` was set on the audit chain. After round 51 §6.2 (D7) this is genuinely rare and represents unrecoverable pipeline state, not client disconnects. Escalate. |
| `pv_events_dropped_total{stage="response_slot"}` | Rate > 0 sustained | Response capture backpressure — the worker pool is saturated or the state store is slow. Scale up workers or investigate the state backend. |
| `pv_http_shutdown_drain_timeouts_total` | Any increase | A graceful drain hit its timeout with requests still in flight; usually upstream latency. |
| `pv_ephemeral_close_failures_total` | Any increase | The auto-close spawned for a stock-SDK one-shot session (no `X-PV-Session` header — the OpenAI-compatibility contract auto-closes it after the response) failed. The session is stranded open until the idle sweeper (`session_idle_close_s`) reaps it, delaying the receipt. If this fires steadily, the finalizer is unhealthy — investigate. |
| `pv_stream_abort_close_failures_total` | Any increase | A background close spawned from a stream-abort drop path failed. Same class as ephemeral-close: the session is left open until the idle sweeper. Steady-state 0 on healthy nodes. |
| `pv_stream_abort_no_runtime_total` | Any increase | A stream-abort drop path ran with no live Tokio runtime (harness shutdown, blocking-thread drop). Capture is marked failed so the reconciler retries on next tick. Any increase after boot suggests unclean shutdown ordering. |
| `pv_reconciler_panics_total` | Any increase | The reconciler tick body panicked and was caught. The reconciler continues on the next tick, but a panic here indicates a bug or an environmental fault (allocator OOM, disk corruption); investigate the coincident logs. |
| `pv_worker_shard_panics_total` | Any increase | A worker shard job body panicked and was caught. The shard continues serving subsequent jobs, but any occurrence is a bug or a hostile input that reached beyond the parser guards; capture the coincident session for triage. |
| `pv_bridge_maintenance_panics_total` | Any increase | The bridge maintenance loop tick body panicked. The loop continues on the next interval. Same triage class as reconciler panics. |
| `pv_bridge_maintenance_errors_total` | Rate > 0 sustained | The bridge maintenance loop tick returned an error (retention rewrite failed, cold-outbox stage failed). Steady errors indicate a persistent broker/disk fault. |
| `pv_bridge_maintenance_join_errors_total` | Any increase | The bridge maintenance loop's spawned task failed to join (panic or cancellation). Any increase after boot is a signal of shutdown-ordering issues or a hostile panic in the maintenance body. |
| `pv_atif_retention_panics_total` | Any increase | The hourly ATIF retention sweep tick body panicked and was caught. The loop continues on the next hour, but retention is the ONLY in-process reclaim path — a repeated firing lets the spool grow unbounded until the disk fills. Same triage class as `pv_bridge_maintenance_panics_total`. |
| `pv_atif_retention_errors_total` | Rate > 0 sustained | The hourly ATIF retention sweep returned an error (permission drift on the spool subtree, a corrupt sidecar the pass keeps re-tripping on). Steady errors here mean the spool is not being reclaimed; investigate before the disk fills. |
| `pv_tcp_nodelay_failures_total` | Sustained rate > 0 | TCP_NODELAY setsockopt failed on an accepted connection. Single events are noise (ECONNRESET race between accept and setsockopt); a sustained rate is either (a) a client half-open flood / SYN flood exhausting sockets before setsockopt runs, or (b) an embedded target without full socket-option support. Under (a) the log is rate-limited to one `warn!` per process to avoid a log storm — this counter is the primary observability signal instead. |
| `pv_http_accept_failures_total` | Sustained rate > 0 | `accept()` on the front-door listener failed (EMFILE/ENFILE fd exhaustion, aborted handshakes). The accept loop sleeps 50 ms and continues, so a sustained rate means the daemon is refusing new connections — check `ulimit -n`, connection leaks, or an active slowloris flood. Like `pv_tcp_nodelay_failures_total`, the log line is rate-limited to one `warn!` per process (under EMFILE this arm loops at ~20 Hz for the whole incident); this counter is the primary observability signal instead. |
| `pv_stream_abort_panics_total` | Any increase | A background close spawned from the stream-abort drop path PANICKED (caught). The session is left open until the idle sweeper. Same class as `pv_stream_abort_close_failures_total` but for panics rather than returned errors. |
| `pv_ephemeral_close_panics_total` | Any increase | Same as `pv_ephemeral_close_failures_total` but for panics rather than returned errors — the auto-close of a completed one-shot ephemeral session panicked in a Drop-spawned task. |
| `pv_admission_refund_panics_total` | Any increase | The admission-debit refund closure panicked inside its Drop-spawned `spawn_blocking` refund. The session and principal ledgers RETAIN the debit; a repeated firing drains the principal budget under real load. Investigate the state backend (Redis) and the store trait implementors' allocator health. |
| `pv_idle_close_timeouts_total` | Any sustained rate > 0 | The reconciler's idle-close sweep hit its 90 s per-session deadline. The session is deferred to the next tick. A steady rate > 0 indicates a session with a lease that never drops (stuck stream, hung worker, unresponsive bridge) — inspect the coincident tracing warn line for the session id. |
| `pv_shutdown_session_close_timeouts_total` | Any occurrence during a rollout | The shutdown-time per-session close hit its 3 s deadline. The session's finalize is deferred to the daemon's next-boot spool recovery (idempotent, no receipts lost). Distinct from `pv_http_shutdown_drain_timeouts_total` which fires on the OUTER phase timeout. Any occurrence on a rollout indicates a class of sessions that hang close — leaked SessionLease, dropped worker permit, unresponsive bridge publish. Inspect the coincident tracing warn line for the session id. |
| `pv_shutdown_mcp_drain_timeouts_total` | Any occurrence during a rollout | The shutdown MCP-inflight drain hit its 5 s deadline before every detached `mcp_call_inner` spawn completed. `mcp_call` decouples the tool-execution body from axum's per-connection cancellation to keep durable state consistent under client disconnect; the drain waits for those bodies between HTTP graceful drain and `worker.wait_idle` so a late worker submission can't race the per-session close deadline. On drain timeout, shutdown still proceeds; sessions whose detached body was interrupted may be quarantined at restart-time recovery. Any occurrence on a rollout indicates a class of tool calls that regularly outlive the drain window (long-running upstream tool, hung sandbox). Distinct from `pv_shutdown_session_close_timeouts_total` (per-session close deadline) and `pv_http_shutdown_drain_timeouts_total` (outer HTTP-drain phase). |
| `pv_lifecycle_outbox_pending` (gauge) | Sustained > 0, or growth rate | Count of unacked lifecycle outbox files (RECEIPT + SESSION_CLOSE) sitting in the spool at the last reconciler tick. Steady-state 0 on a healthy node. A rising baseline is the earliest signal of a broker outage — outboxes persist across restarts, so the disk-bounded queue grows until the bridge is reachable again. Investigate the bridge/broker health when this alerts. |
| `pv_recovery_scan_capped_total{pass="…"}` | Any sustained rate > 0 | A recovery pass hit its per-tick entry-scan cap (10 000 entries) and returned early. The next tick re-opens the directory and resumes. A steady rate > 0 indicates a POISONED SPOOL (millions of stale files) that will starve legitimate recovery work until an operator quarantines the offending files. The `pass` label identifies which pass hit the cap: `adopt_strict_atif`, `recover_signed_journals`, `consolidate_step_journals`, `retry_marked_promotions`, `remove_acked_outboxes`, `replay_lifecycle_outboxes`, or `quarantine_orphan_json`. |
| `pv_authzen_decisions_total{decision="error"}` | Any sustained rate > 0 | The external AuthZEN policy decision point timed out, answered a non-200 status, or returned no boolean decision. Every affected tool call was refused with 503 (fail closed). Check the PDP's health and `[authzen].timeout_ms`. `decision="deny"` counts policy denials and is not an outage signal. |
| `pv_mcp_discovery_failures_total{backend="…"}` | Sustained rate > 0 | `tools/list` could not discover a backend's tools (handshake refused, backend down, or the caller holds no usable credential for it). That backend's tools are missing from tool lists until it recovers; tool calls to it fail with 502. |
| `pv_mcp_tools_withheld_total{reason="…"}` | Sudden increase in `invalid_name` or `unrouted` | Backends advertise tools the gateway cannot accept (names with uppercase or non-ASCII characters) or that routing sends elsewhere. `scope` and `policy` reasons reflect normal filtering by caller permissions. |
| `pv_content_records_dropped_total` | Any sustained rate > 0 | Full-content tenant telemetry is falling behind: the queue to the tenant exporter was full, or the sink failed, and records were dropped. The audit journal and receipts are unaffected. Check the tenant collector's reachability and throughput. |
| `pv_judge_calls_total{predicate="…",status="…"}` | Sustained rate > 0 of `timeout`, `unavailable`, `saturated`, or `model_mismatch` | The semantic judge is failing; in enforce mode each such call was refused or held. `saturated` means `max_concurrency` is too low for the traffic or the model is too slow; `model_mismatch` means the cloud judge changed models without a new pin. |
| `pv_judge_wait_seconds` | p99 near the adapter `deadline_ms` | Judged calls are waiting close to the deadline; timeouts follow. |
| `pv_judge_decisions_total{mode="…",decision="…",enforced="…"}` | Sudden change in the `deny` or `ask` share | The judge's behaviour shifted (new traffic, a model change, drift). In shadow mode this is the would-have-blocked rate. |
| `pv_judge_pilot_cap_reached_total` | Any increase | The pilot's daily block cap was reached and score-based blocks are being let through for the rest of the day. |
| `pv_judge_drift_tripped` (gauge) | > 0 | A predicate is in ask-by-default mode after the calibration drift check. Recalibrate, then reset it. |
| `pv_judge_trace_findings_total{source="…"}` | Sudden increase | Recorded tool or model outputs the judge flagged (for example instructions planted in a tool response). Read the `agent.judge` events for the sessions involved. |
| `pv_judge_breaker_opinions_total{opinion="unavailable"}` | Sustained rate > 0 | The judge could not give the loop breaker its second opinion; the breaker is deciding alone. |
| `pv_judge_shared_denials_errors_total{op="…"}` | Any increase | The judge could not read (`read`) or write (`write`) the refusal log in Redis; delegated agents on other instances may not see a parent's refusal until Redis is reachable again. |
| `pv_judge_breaker_opinions_total{opinion="paused"}` | Any increase | The breaker's judge failed 3 times in a row, so the breaker stopped asking for 30 seconds. Check the judge before the pause ends. |
| `pv_judge_events_dropped_total{kind="…"}` | Any increase | An `agent.judge` event was dropped because the audit queue was full. The decision it described still applied. |
| `pv_judge_rules_repinned_total` | Sudden increase | Compression is cutting standing rules from long conversations and the harness is adding them back. |
| `pv_judge_drift_persist_failures_total` | Any increase | A drift switch or reset could not be saved to `[judge.drift] state_file`; it applies now but may not survive a restart. Check the file's directory and disk. |
| `pv_workload_assertions_rejected_total{reason="…"}` | Sustained rate > 0 of `chain`, `signature`, or `replay` | Workload identity assertions are refused. `chain` usually means `[workload_identity].ca_file` does not match the foundation's instance identity CA; `replay` or `signature` can indicate a stolen or forged assertion; `unregistered` means an app has no `[[workload_identities]]` entry. |

## Backup

You need **three** things to reconstruct evidence for an audit:

1. The signer seed file (default `config/signing.seed`, or the path in
   `PV_SIGNING_SEED_FILE`) — filesystem, offline, GPG.
2. The spool dir (`atif_spool_dir`) — all `.atif-auth` sidecars
   must be preserved; the corresponding `.json` trajectories are
   recoverable from the broker if lost.
3. The receipt topic (`agent.receipt` on the broker) — either the
   embedded Bridge's data-dir or the external broker's log
   retention.

Losing (1) does not break past receipts: they still verify against
the published public key. You can no longer sign with that key,
however, and the spool's journals and `.atif-auth` sidecars can no
longer be authenticated, because their HMAC key is derived from the
seed. Losing (2) sacrifices operational
forensics but does NOT compromise the cryptographic chain. Losing
(3) means downstream consumers depend on the harness's live disk
copy — restore quickly.

## Upgrade

The workspace's SemVer contract:

* Signed receipts: canonical (JCS + Ed25519) format is
  frozen. Any change is a MAJOR version bump.
* ATIF trajectories: v1.7 shape is frozen. New fields are added as
  optional; removals or renames are MAJOR bumps.
* Config: new keys added with `#[serde(default)]` and documented in
  `docs/reference/CONFIGURATION.md`. Removals are MAJOR bumps.
* `pvctl` CLI surface: adding subcommands is minor; removing them
  or renaming flags is MAJOR.

Rolling upgrades within a MAJOR version are safe: mix old and new
pods behind the same LB and the audit chain remains verifiable
under any pinned key that either version signed with.

## Verified email domains (SAML discovery)

The login page's "Continue with SAML SSO" asks for an email address and
looks its domain up. The lookup only trusts domains the organisation has
proven it controls, so a stranger's workspace cannot send your users to a
fake identity provider.

1. In the console open Settings → SSO → Verified email domains and add
   the domain, for example `acme.com`.
2. Publish the DNS TXT record the console shows:
   `_proofvisor-challenge.acme.com` with the value
   `proofvisor-domain-verification=<token>`.
3. Click "Check DNS". Once it passes, the record may be removed. The
   SAML config for that domain must still list it under allowed domains
   (or list none).

A domain can be claimed by one organisation only; a second claim answers
`409 domain_claimed`. Removing the domain stops discovery for it at once.
Owners add, verify and remove domains; admins can read them. The API
endpoints are `GET`, `POST` `/api/v1/org/domains`,
`POST /api/v1/org/domains/:id/verify` and `DELETE /api/v1/org/domains/:id`.
Outside production the API answers lookups from the JSON file named by
`PV_TEST_DNS_TXT_FILE` instead of DNS, which is how the test suite runs.
