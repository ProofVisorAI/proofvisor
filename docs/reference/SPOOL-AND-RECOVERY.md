# ProofVisor Spool and Recovery

The spool is where ProofVisor's audit chain becomes durable. This
document explains what lives there, what the reconciler does on
every tick, and how to reason about incidents that touch it.

For the operator's *day-to-day* view (metrics, alerts, backup), see
[OPERATIONS.md](OPERATIONS.md).

An incomplete capture cannot support a complete signed receipt. Close and
recovery publish an authenticated, retryable `agent.session` notification
with `action: "quarantined"` and `evidence_complete: false`. Console sync
turns this into the terminal `quarantined_crash_evidence` status and refuses
receipt upload for that session. Already captured bridge events remain
available as partial evidence; private journal files are never treated as
a complete public event stream. Previously accepted signed receipts are
not retroactively replaced by quarantine metadata.

If a tool may have executed but its result cannot be captured, the live session
also refuses close and promotion. Its authenticated primary `.intent.json`
remains in `tool-executions`, with any partial outcome, so another restart
retains the quarantine and cannot repeat that execution. Only completed triples
with authenticated outcome and audit records move to `.capturefailed-<uid>`.
A refused connection whose intent is successfully released remains retryable.

Unresolved evidence intentionally occupies the active recovery directory. The
100,000-entry recovery limit fails closed when that directory exceeds its cap;
quarantine does not create unlimited recovery capacity. Monitor and investigate
these incidents. Archive unresolved evidence only as an explicit operator
recovery action, with the affected session IDs retired from further traffic and
a consistent backup preserved. Removing the active intent removes the durable
barrier that prevents replay of an uncertain tool execution.

Close and fresh unsigned promotion also read the authenticated execution evidence
after draining admitted work. This check remains effective if an in-memory
quarantine entry was evicted. Unresolved or unreadable evidence returns a
retryable 503 without deleting it. A valid outcome whose audit marker is pending
can finish through the existing MCP replay path and then finalize; this check
does not permanently quarantine that recoverable audit failure.
Each close or fresh unsigned promotion scans the full active tool directory on a
blocking worker, authenticating primary intents, with the same 100,000-entry cap.
This adds work proportional to the active directory size. A concurrent unrelated
intent that disappears or is still being written can cause a safe, retryable 503;
the read-only check preserves all evidence and a later attempt can succeed.

Startup refuses an authenticated unresolved intent that has no recoverable
session metadata. This can occur if a crash precedes the authorization worker's
first metadata commit. Restore a consistent backup or investigate the retained
intent; recovery does not invent an identity or a clean session for it. Valid
authenticated metadata waiting beyond a recovery pass's work limit is allowed to
remain deferred, and the independent finalization check still prevents a receipt
that omits the uncertain tool effect.

## What "the spool" is

`atif_spool_dir` (default `spool/atif`, relative to the working
directory) holds the on-disk state of
every open, closing, and recently-closed session. Its file
inventory:

| File | Contents | Written by | Removed by |
| --- | --- | --- | --- |
| `.proofvisord.lock` | Exclusive process lock at the spool root; boot refuses if another daemon holds it | `main::acquire_spool_lock` at process start | on clean process exit; stale locks are healed by fresh boots |
| `{stem}.session.json` | Sealed metadata: session id, identity, workflow, journal version | worker (`append_active_event_journal`) at first event | `remove_step_journal` after successful close |
| `{stem}.events.ndjson` | Append-only sealed journal — one JSON line per audit event | worker (`append_journal`) | `remove_step_journal` after successful close |
| `{stem}.json` | ATIF trajectory (unsigned workflow) | finalizer at close | retention sweep OR archive on collision |
| `{stem}.atif-auth` | Provenance sidecar: an HMAC-sealed record of the session id and the SHA-256 digest of `{stem}.json` (the HMAC key is derived from the signing seed) | finalizer immediately after `write_atomic({stem}.json)` | retention sweep (paired with `.json`) |
| `{stem}.close-complete` | Marker: close ran to completion (both bridge event and receipt/ATIF durably committed) | finalizer at end of close | retention sweep (with its pair; orphaned markers past the window are healed) |
| `{stem}.promote` | Promotion intent (unsigned → signed retrofit) | promote route handler | finalizer after receipt lands |
| `{stem}.promote-archived` | Archived-on-collision promote intent | finalizer collision path | never (preserved collision evidence) |
| `receipts/{stem}.json` | Signed receipt (signed workflow) | finalizer at close (`persist_receipt`) | never (audit evidence; manage retention externally) |
| `receipts/{stem}.archived-<receipt-id>.json` | Prior incarnation's receipt after a recycled session id | `archive_conflicting_receipt` at the collision | never (preserved collision evidence) |
| `{stem}.archived-<trajectory-id>` (+ `.atif-auth`, `.close-complete`) | Prior incarnation's ATIF evidence after a recycled session id | `archive_conflicting_atif` at the collision | never (preserved collision evidence) |
| `outbox/{stem}.{kind}.json` where `kind` ∈ `{receipt, session-close, session-quarantine}` | Authenticated lifecycle publication intents, persisted before publishing | close or recovery | acknowledged close/receipt intents are drained; quarantine intents move to `quarantine-notices` |
| `quarantine-notices/{stem}.json` | Authenticated acknowledged quarantine notification, preserving notification identity across restarts | close, recovery, or outbox cleanup | retained with incident evidence, outside the bounded active replay scan |
| `{stem}.acks.ndjson` | Sealed broker acks, one line per published event: proves an event we tried to publish actually landed | worker after successful emit (appended; one `sync_data` per ack — round-51 §7.3) | `remove_step_journal` at close, with the other journals |
| `broker-acks/{stem}/{event_uid}.json` | Legacy pre-round-51 per-event ack layout; still read as a fallback so mid-session upgrades see their earlier acks | (no longer written) | `remove_step_journal` at close |
| `inflight-responses/{digest}.json` | Response-attempt markers (`digest = sha256(session_id:attempt_id)[..32]`). A marker is written before the request is sent upstream and removed once the response is captured, so a marker left after a crash means the response may not have been captured | `write_response_marker`, before upstream dispatch | worker once the response is captured; a leftover marker quarantines its session at recovery and stays on disk as evidence |
| `tool-executions/{key}.intent.json` | JCS-canonicalized, MAC-sealed tool invocation intent; underpins the at-most-once tool-execution state machine | mcp route handler at admission | `remove_tool_executions` at successful close |
| `tool-executions/{key}.outcome.json` | Sealed tool execution outcome (upstream response + status) | worker after tool call returns | `remove_tool_executions` at successful close |
| `tool-executions/{key}.audited` | Marker: the tool call's audit event has landed on the broker | worker after the ack lands | `remove_tool_executions` at successful close |
| `tool-executions/{key}.{suffix}.capturefailed-<uid>` | Authenticated completed tool triple (intent/outcome/audited) archived when its session is capture-failed | reconciler (`quarantine_tool_executions`) | never (preserved incident evidence) |

Every one of these files carries a `{stem}` derived as
`sha256_hex(session_id.as_bytes())[..32]` — a 128-bit fixed-width
truncation. Collision probability at 10⁹ sessions is ~10⁻²⁰,
comfortably below the audit-chain-tamper threshold set by the
Ed25519 verifier. Session ids longer than 128 bytes, or containing
anything other than visible ASCII (0x21–0x7E), are refused at admission.

## Why not a database

The spool is a filesystem because every state transition needs to
survive a hard reboot at any instruction boundary. Filesystems give
POSIX ordering guarantees (`write` → `sync_data` → `sync_all` on
containing dir) that are cheap to reason about and portable across
Linux/macOS/BSD. A database would give ACID transactions per row but
would sit above the same POSIX primitives — its atomicity is our
`write_atomic`, its durability is our per-event `sync_data`, and its
recovery log is our journal replay.

## Recovery: what runs every tick

A completed signed session is not a permanent entry in the daemon's active
session registry. After its receipt and close event are durable, the daemon
removes its recovery journal and may evict the session. After a restart,
`POST /v1/sessions/{id}/promote` can therefore return `404` for that completed
session. Its receipt remains under `receipts/` and in the event bridge; use
the persisted receipt or the synchronized console for historical evidence.
Restart verification must read that persisted artifact rather than assume
the session control endpoint is a history API.

`Finalizer::recover_spooled_sessions` runs at process start and every
`reconcile_tick_s` seconds. It runs six passes over the spool, in this
order:

1. **Quarantine sessions with incomplete effects.** A leftover marker
   under `inflight-responses/` or an unresolved intent under
   `tool-executions/` belongs to a request that was cut off by a crash.
   Each such session that is not currently open is quarantined by id,
   because its capture is incomplete. This pass runs first, before any
   session is adopted back into the registry.
2. **Replay lifecycle outboxes.** Every unacknowledged file under
   `outbox/` is published and acknowledged, so a crashed close's events
   reach the broker before its session is adopted again. Without a
   Bridge this pass does nothing.
3. **Recover signed journals.** Signed sessions interrupted by a crash
   are adopted from their authenticated (HMAC-verified) journals and
   finalized. A session that fails recovery (for example, because its
   journal fails authentication) is skipped and counted in
   `pv_signed_recovery_skipped_total`; its files stay on disk.
4. **Consolidate step journals.** Unsigned sessions interrupted by a
   crash are rebuilt from `{stem}.session.json` and
   `{stem}.events.ndjson`. Replaying the events restores token counts,
   budget debits and provenance, and broker acknowledgments from
   `{stem}.acks.ndjson` (or the legacy `broker-acks/{stem}/` files) stop
   already published events from being sent again. Failures are counted
   in `pv_unsigned_recovery_skipped_total`.
5. **Quarantine orphan `.json` files.** A `{stem}.json` that has no
   `.atif-auth` sidecar, is older than `MIN_ORPHAN_AGE` (60 s), and
   whose stem is not in the snapshot of open sessions is renamed to
   `{stem}.json.corrupt-{uid}`. It is counted in
   `pv_atif_recovery_skipped_total{reason="unauthenticated"}` and never
   deleted automatically.
6. **Adopt ATIF trajectories.** Sealed `{stem}.json` + `{stem}.atif-auth`
   pairs of closed unsigned sessions that are not in the registry are
   validated strictly and adopted again. A trajectory that fails is
   counted in `pv_atif_trajectory_recovery_skipped_total` or in
   `pv_atif_recovery_skipped_total` with its reason.

Two more jobs run on each tick after these passes: retrying marked
promotions (`{stem}.promote` files; on a collision the intent is renamed
to `{stem}.promote-archived`) and completing pending closes (failures
are counted in `pv_pending_close_completion_failed_total`).

The retention sweep is a separate hourly task. If `atif_retention_days`
is set, `prune_sealed_atif` removes sealed pairs (`.json` + `.atif-auth`)
whose mtime is older than N days, together with their digest-bound
`.close-complete` marker. Unpaired files are left for pass 5, and
archived collision evidence and signed receipts under `receipts/` are
never removed. Pruned pairs are counted in
`pv_atif_retention_pruned_total`. The same sweep can be run manually
with `pvctl spool-prune --spool <atif_spool_dir> --retention-days N`.

## Race analysis: the three tight windows

### 1. Write / sidecar seal (round-16 stress)

`finalizer.close_session_locked` writes `{stem}.json` via
`write_atomic`, then immediately writes `{stem}.atif-auth`. Between
those two calls, the reconciler's pass 5 would see a sidecar-less
`.json` and quarantine it. Mitigation:

1. Per-session lifecycle lock — the close holds
   `acquire_lifecycle(session_id)` across both writes so a second
   close on the same session can't interleave.
2. `MIN_ORPHAN_AGE = 60s` gate — a `.json` newer than 60s is
   skipped this tick.
3. Live-stem check (§8.5 fix, round 51) — a `.json` whose stem is
   in the currently-open-sessions snapshot is skipped even if
   aged.

The three gates layer: (1) prevents intra-process races, (2)
prevents inter-tick races on very-quick closes, (3) prevents races
where the tick's snapshot was taken before the close but the
close is still in-flight when the sweep visits the file.

### 2. Journal append / broker emit (round-27)

A worker appends to `{stem}.events.ndjson` and then attempts to
emit the corresponding event to the broker. If the process crashes
between append and emit, the event is durable on disk but not on
the wire. Journal recovery (passes 3 and 4) detects this by comparing the journal's
last event to the `{stem}.acks.ndjson` inventory (legacy
`broker-acks/{stem}/` files are consulted as a fallback), re-emits
any event missing an ack, and appends a fresh ack.

There is one race here: a broker that fully accepted an event but
crashed before delivering the ack causes the recovered process to
re-emit. The event is idempotent-keyed on `event_uid`, so
downstream consumers dedup on the `event_uid` field. A broker
without dedup capability WILL land the event twice — this is a
known limit; operators alerting on emit-then-ack-loss should
watch the broker-side per-topic ack-loss counter (or Kafka
`records-lag-max`) rather than an in-process metric, because the
harness's `pv_events_dropped_total` only labels admission-side
failures (`stage="worker_queue"`, `stage="worker_closed"`,
`stage="response_slot"` and `stage="quota_post_compression"`), not
post-emit ack loss.

### 3. Retention prune / live session (round-51 §8.1-§8.2)

The retention task and the live-session close path can both touch
`{stem}.json` and `{stem}.atif-auth`. Retention only touches SEALED
pairs (both files present) whose mtime is past the threshold; a
live session's freshly-closed pair has mtime = now, which is
comfortably inside any reasonable retention window.

## Backup and disaster recovery

Back up the entire spool using a consistent filesystem snapshot, or stop
writes before making a file-by-file copy. An `rsync` taken during active writes
is not guaranteed to contain a consistent set of journals, acknowledgments,
and execution intents. Retain the matching signing seed through your secret
backup process; the journal HMAC key is derived from it.

Restore the complete snapshot. Partial restoration can lose the evidence that
prevents duplicate tool execution or proves incomplete capture. Recovery
refuses detected inconsistencies; it cannot reconstruct files absent from the
backup. Verify the restored instance in isolation before accepting traffic.

Rebuild the audit chain from a fresh disk:

1. `ls <atif_spool_dir>/receipts/*.json | wc -l` — should be roughly
   the number of `agent.receipt` events the broker has for the same
   window.
2. `pvctl receipt-verify` against a known-trusted receipt (from
   before the incident) — proves the signer's public key is intact.
3. For each recovered session on disk, tail the broker and diff
   `subject.event_count` — divergence is a torn recovery.

## What the reconciler will NEVER do

* **Delete unpaired `.json` files.** These are either an in-progress
  close or forensic evidence of an attack. Quarantine + operator
  review only.
* **Retry a `.corrupt-*` file.** Once quarantined, the file is
  out-of-band; recovery skips it in O(1) on every future tick.
* **Cross-session locking.** Every action holds the per-session
  lifecycle lock only; different sessions are always processed
  concurrently. This is what gives the finalizer its
  `close_latency_scales_reasonably_under_lock_contention` shape.
* **Silent retention.** Every prune emits a counter increment; every
  quarantine emits both a counter AND a warn. An operator monitoring
  only metrics sees the shape; an operator monitoring only logs
  sees the reason. Both together triangulate.

## Round-N tags in the source

You will see comments like "Round-51 F1: …" and "Round-16 F4: …"
across the codebase. These are archaeological anchors: each Round
corresponds to a review pass, and each F-M numbers a finding within
that pass. The tags are load-bearing history — they explain WHY a
given guard exists so that a future refactor doesn't quietly remove
it. If you're editing a Round-tagged block, follow the anchor:
grep for the tag in
[EVOLUTION.md](../../EVOLUTION.md) or in the git log to find the
incident that motivated it.
