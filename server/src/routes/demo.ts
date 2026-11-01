/**
 * Live-mode demo data: the console's "Simulate an attack" for real
 * workspaces (the mock console stages the same story from fixtures).
 *
 *   POST   /api/v1/demo/attack   (owner/admin)  body { pace?: "staged" | "instant" }
 *   GET    /api/v1/demo          (any role)     → { present, deployments, sessions }
 *   DELETE /api/v1/demo          (owner/admin)  → removes every demo row
 *
 * The attack creates (or reuses) a deployment named "demo-attack" with
 * isDemo=true and the PUBLIC demo signing key pinned as its publicKeyHex,
 * then writes one session for the "vendor-onboarding" agent: an invoice
 * email tricks the agent into paying an unknown vendor, the payment is
 * blocked by the vendor allowlist, the agent escalates to a human, and
 * the session seals with a receipt signed by the demo key — the same
 * sequence the mock console shows. With pace "staged" (default) the
 * block lands 4.5 s after the call and the seal at 9 s, so a viewer
 * watches it happen; "instant" writes everything at once (tests).
 *
 * The demo key's private half ships publicly in docs/app/datasource.js,
 * which is why the /verify page shows the distinct "demo receipt"
 * verdict for it and never "authentic". Demo rows carry isDemo=true so
 * the console labels them and "Remove demo data" deletes them as one
 * unit. The demo deployment's ingest token is random and never
 * revealed: nothing can post real evidence under the demo label.
 */

import type { FastifyBaseLogger, FastifyInstance } from "fastify";
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign as edSign } from "node:crypto";
import { z } from "zod";
import { db } from "../db.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
import { hashPassword, randomToken } from "../lib/auth.js";
import { bus } from "../lib/bus.js";
import { requireSession } from "../lib/session-middleware.js";
import { INGEST_TOKEN_PREFIX } from "./deployments.js";
import { receiptSigningMessage, verifyReceiptSignature } from "./ingest.js";

export const DEMO_DEPLOYMENT_NAME = "demo-attack";
// Fixed demo keypair — NOT a secret (see docs/app/datasource.js and
// docs/.well-known/receipt-keys.json, trust: "demo").
const DEMO_PRIV_PKCS8_B64 = "MC4CAQAwBQYDK2VwBCIEILgB0YgZaAezId215njwdk9j+ZyR8Kz/gYV2oIQnZh8W";
export const DEMO_PUB_HEX = "573c8f249012fbb08b3d79973411bb93141f32719c86ada25306fde5e59e8d57";

const demoPrivateKey = createPrivateKey({
  key: Buffer.from(DEMO_PRIV_PKCS8_B64, "base64"),
  format: "der",
  type: "pkcs8",
});
{
  const derived = createPublicKey(demoPrivateKey).export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
  if (derived !== DEMO_PUB_HEX) {
    throw new Error("demo signing key does not match the published demo public key");
  }
}
const DEMO_KEY_ID = createHash("sha256").update(Buffer.from(DEMO_PUB_HEX, "hex")).digest("hex").slice(0, 32);

const BLOCK_AT_MS = 4500;
const SEAL_AT_MS = 9000;
const MODEL = "claude-3-5-sonnet";
const AGENT = "vendor-onboarding";
const VENDORS = ["Apex Supply Co", "Meridian Parts", "BlueRiver Trading", "Quantum Goods", "Vertex Wholesale"];
const VALUES_USD = [4750, 2980, 6200, 1840, 9300];

interface Story {
  vendor: string;
  valueUsd: number;
  ticket: number;
}

type DemoEvent = {
  seq: number;
  kind: string;
  tag: string;
  body: string;
  sub?: string;
  policyName?: string;
};

function storyEvents(story: Story): { open: DemoEvent[]; block: DemoEvent[]; seal: DemoEvent[] } {
  const money = "$" + story.valueUsd.toLocaleString("en-US");
  return {
    open: [
      { seq: 1, kind: "sys", tag: "start", body: "Session opened", sub: `agent=${AGENT}` },
      { seq: 2, kind: "llm", tag: "request", body: `${MODEL} · 640 tokens in · forwarded invoice email asks to settle ${money} with ${story.vendor} today`, sub: MODEL },
      { seq: 3, kind: "tool", tag: "call", body: `lookup_vendor("${story.vendor}")` },
      { seq: 4, kind: "guard", tag: "TOOL ✓ allow", body: "Read-only tool · budget $0.02 / $10.00", sub: "policy=runtime.write_scope", policyName: "runtime.write_scope" },
      { seq: 5, kind: "tool", tag: "result", body: "vendor not found in the approved directory" },
      { seq: 6, kind: "llm", tag: "request", body: `${MODEL} · 1,010 tokens in · the email insists the payment is urgent`, sub: MODEL },
      { seq: 7, kind: "tool", tag: "call", body: `create_payment(vendor="${story.vendor}", total=${money})` },
    ],
    block: [
      {
        seq: 8,
        kind: "block",
        tag: "BLOCKED",
        body: `Vendor "${story.vendor}" not in procurement allowlist`,
        sub: `policy=procurement.allowed_vendors · would-have-spent=${money}`,
        policyName: "procurement.allowed_vendors",
      },
    ],
    seal: [
      { seq: 9, kind: "llm", tag: "request", body: `${MODEL} · escalating to a human`, sub: MODEL },
      { seq: 10, kind: "tool", tag: "call", body: 'open_review_ticket(reason="unapproved vendor invoice")' },
      { seq: 11, kind: "guard", tag: "TOOL ✓ allow", body: `Write within scope · ticket=REV-${story.ticket}`, sub: "policy=runtime.write_scope", policyName: "runtime.write_scope" },
      { seq: 12, kind: "sys", tag: "end", body: "Sealed · 12 events" },
    ],
  };
}

async function insertEvents(sessionId: string, events: DemoEvent[], at: Date): Promise<void> {
  await db.event.createMany({
    data: events.map((e) => ({
      sessionId,
      seq: e.seq,
      kind: e.kind,
      tag: e.tag,
      body: e.body,
      sub: e.sub ?? null,
      policyName: e.policyName ?? null,
      occurredAt: at,
      journalCount: 1,
    })),
    skipDuplicates: true,
  });
}

// Pending stage timers per session, cleared by DELETE /demo so a
// removed session is not re-created mid-story.
const pendingTimers = new Map<string, NodeJS.Timeout[]>();

function clearTimersFor(sessionIds: string[]): void {
  for (const id of sessionIds) {
    for (const t of pendingTimers.get(id) ?? []) clearTimeout(t);
    pendingTimers.delete(id);
  }
}

async function ensureDemoDeployment(orgId: string, actor: { actorId: string; actorEmail: string | undefined }, log: FastifyBaseLogger) {
  const existing = await db.deployment.findUnique({
    where: { orgId_name: { orgId, name: DEMO_DEPLOYMENT_NAME } },
    select: { id: true, name: true, isDemo: true, publicKeyHex: true },
  });
  if (existing && !existing.isDemo) return { conflict: true as const };
  if (existing) {
    if (existing.publicKeyHex !== DEMO_PUB_HEX) {
      await db.deployment.update({ where: { id: existing.id }, data: { publicKeyHex: DEMO_PUB_HEX } });
    }
    return { conflict: false as const, id: existing.id, name: existing.name, created: false };
  }
  // The token is minted only so the row satisfies the schema; it is
  // hashed and discarded, never returned.
  const token = INGEST_TOKEN_PREFIX + randomToken(24);
  const dep = await db.deployment.create({
    data: {
      orgId,
      name: DEMO_DEPLOYMENT_NAME,
      environment: "development",
      isDemo: true,
      publicKeyHex: DEMO_PUB_HEX,
      ingestTokenHash: await hashPassword(token),
      ingestTokenHint: token.slice(0, INGEST_TOKEN_PREFIX.length + 8),
      lastIngestAt: new Date(),
    },
    select: { id: true, name: true },
  });
  writeAudit(
    {
      orgId,
      event: "deployment.create",
      ...actor,
      target: dep.name,
      metadata: { deploymentId: dep.id, environment: "development", isDemo: true },
    },
    log,
  );
  // Same first-set trail a real daemon leaves, so the public
  // receipt-keys endpoint reports when the key was pinned.
  writeAudit(
    {
      orgId,
      event: "deployment.pubkey_first_set",
      actorId: `demo:${dep.id}`,
      actorEmail: `demo@${dep.name}`,
      target: dep.name,
      metadata: { deploymentId: dep.id, publicKeyHex: DEMO_PUB_HEX, isDemo: true },
    },
    log,
  );
  return { conflict: false as const, id: dep.id, name: dep.name, created: true };
}

async function stageBlock(orgId: string, deploymentId: string, sessionId: string, story: Story, log: FastifyBaseLogger): Promise<void> {
  const now = new Date();
  await insertEvents(sessionId, storyEvents(story).block, now);
  const upd = await db.session.updateMany({
    where: { id: sessionId, isDemo: true, status: { not: "sealed" } },
    data: {
      status: "blocked",
      toolsBlocked: 1,
      blockedPayoutUsdMicros: BigInt(story.valueUsd) * 1_000_000n,
      promptTokens: { increment: 1010 },
      completionTokens: { increment: 120 },
      costUsdMicros: { increment: 9_000n },
    },
  });
  if (upd.count === 0) return; // removed mid-story
  bus.publish({ type: "events.appended", orgId, deploymentId, sessionId, count: 1, allowed: 0, blocked: 1 });
  log.info({ sessionId }, "demo_attack_blocked");
}

async function stageSeal(orgId: string, deploymentId: string, sessionId: string, story: Story, log: FastifyBaseLogger): Promise<void> {
  const session = await db.session.findUnique({
    where: { id: sessionId },
    select: { id: true, externalId: true, openedAt: true, isDemo: true, status: true },
  });
  if (!session || !session.isDemo || session.status === "sealed") return;
  const now = new Date();
  const ev = storyEvents(story);
  await insertEvents(sessionId, ev.seal, now);
  const all = [...ev.open, ...ev.block, ...ev.seal];
  const cost = 38_000;
  const chainHead = createHash("sha256")
    .update(all.map((e) => `${e.seq}:${e.kind}:${e.body}`).join("\n"), "utf8")
    .digest("hex");
  const receiptId = `rcpt_demo_${randomBytes(6).toString("hex")}`;
  const body = {
    receipt_version: 2,
    receipt_id: receiptId,
    session_id: session.externalId,
    key_id: DEMO_KEY_ID,
    public_key_b64: Buffer.from(DEMO_PUB_HEX, "hex").toString("base64"),
    issued_at: now.getTime(),
    issued_at_iso: now.toISOString(),
    stop_reason: "policy_block",
    subject: { kind: "event_chain", event_count: all.length, chain_head: chainHead },
    ai_agent: { charter: { name: AGENT } },
    tool_calls: { total: 4, allowed: 3, blocked: 1 },
    cost: { cost_usd_micros: cost },
    blocked_payout_usd_micros: story.valueUsd * 1_000_000,
    startedAt: session.openedAt.toISOString(),
    endedAt: now.toISOString(),
    policiesEnforced: ["procurement.allowed_vendors", "runtime.write_scope"],
    demo: true,
    note: "Demo receipt staged by the ProofVisor console. Signed with the PUBLIC demo key — not a production attestation.",
  };
  const rawBody = JSON.stringify(body);
  const sigB64 = edSign(null, receiptSigningMessage(rawBody), demoPrivateKey).toString("base64");
  if (!verifyReceiptSignature(DEMO_PUB_HEX, sigB64, rawBody)) {
    throw new Error("demo receipt failed self-verification");
  }
  await db.$transaction(async (tx) => {
    await tx.receipt.create({
      data: {
        sessionId,
        receiptId,
        body: rawBody,
        sigB64,
        keyIdHint: DEMO_KEY_ID.slice(0, 8),
        eventCount: all.length,
        issuedAt: now,
      },
    });
    await tx.session.update({
      where: { id: sessionId },
      data: {
        status: "sealed",
        closedAt: now,
        stopReason: "policy_block",
        toolsAllowed: 3,
        toolsBlocked: 1,
        promptTokens: 2860,
        completionTokens: 410,
        costUsdMicros: BigInt(cost),
        payoutUsdMicros: 0n,
        blockedPayoutUsdMicros: BigInt(story.valueUsd) * 1_000_000n,
      },
    });
  });
  bus.publish({ type: "events.appended", orgId, deploymentId, sessionId, count: ev.seal.length, allowed: 1, blocked: 0 });
  bus.publish({ type: "receipt.finalized", orgId, deploymentId, sessionId, receiptId });
  log.info({ sessionId, receiptId }, "demo_attack_sealed");
}

export async function demoRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const [deployments, sessions] = await Promise.all([
      db.deployment.count({ where: { orgId: claims.orgId, isDemo: true } }),
      db.session.count({ where: { orgId: claims.orgId, isDemo: true } }),
    ]);
    return reply.send({ present: deployments > 0 || sessions > 0, deployments, sessions });
  });

  app.post("/attack", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") return reply.code(403).send({ error: "forbidden" });
    const body = z
      .object({ pace: z.enum(["staged", "instant"]).default("staged") })
      .safeParse(req.body ?? {});
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    const actor = await resolveActor(claims.sub);
    const dep = await ensureDemoDeployment(claims.orgId, actor, req.log);
    if (dep.conflict) return reply.code(409).send({ error: "demo_name_in_use" });

    const n = await db.session.count({ where: { deploymentId: dep.id } });
    const story: Story = {
      vendor: VENDORS[n % VENDORS.length]!,
      valueUsd: VALUES_USD[n % VALUES_USD.length]!,
      ticket: 2400 + n + 1,
    };
    const now = new Date();
    const externalId = `demo_attack_${now.getTime().toString(36)}_${randomBytes(3).toString("hex")}`;
    const session = await db.session.create({
      data: {
        deploymentId: dep.id,
        orgId: claims.orgId,
        externalId,
        agent: AGENT,
        workflow: "signed",
        status: "live",
        policyVersion: 1,
        openedAt: now,
        isDemo: true,
        toolsAllowed: 2,
        promptTokens: 1850,
        completionTokens: 290,
        costUsdMicros: 29_000n,
      },
      select: { id: true, externalId: true },
    });
    await insertEvents(session.id, storyEvents(story).open, now);
    // Keep the demo deployment "connected" while the story runs.
    await db.deployment.update({ where: { id: dep.id }, data: { lastIngestAt: now } }).catch(() => void 0);
    bus.publish({
      type: "session.upsert",
      orgId: claims.orgId,
      deploymentId: dep.id,
      sessionId: session.id,
      externalId: session.externalId,
      agent: AGENT,
    });
    bus.publish({ type: "events.appended", orgId: claims.orgId, deploymentId: dep.id, sessionId: session.id, count: 7, allowed: 2, blocked: 0 });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "demo.attack_staged",
        ...actor,
        target: session.externalId,
        metadata: { deploymentId: dep.id, sessionId: session.id, vendor: story.vendor, valueUsd: story.valueUsd, pace: body.data.pace },
        req,
      },
      req.log,
    );

    const log = req.log;
    if (body.data.pace === "instant") {
      await stageBlock(claims.orgId, dep.id, session.id, story, log);
      await stageSeal(claims.orgId, dep.id, session.id, story, log);
    } else {
      const orgId = claims.orgId;
      const timers = [
        setTimeout(() => {
          stageBlock(orgId, dep.id, session.id, story, log).catch((err) => log.warn({ err }, "demo_attack_block_failed"));
        }, BLOCK_AT_MS),
        setTimeout(() => {
          stageSeal(orgId, dep.id, session.id, story, log)
            .catch((err) => log.warn({ err }, "demo_attack_seal_failed"))
            .finally(() => pendingTimers.delete(session.id));
        }, SEAL_AT_MS),
      ];
      for (const t of timers) t.unref();
      pendingTimers.set(session.id, timers);
    }
    return reply.code(201).send({
      deployment: { id: dep.id, name: dep.name, isDemo: true },
      session: { id: session.id, externalId: session.externalId, agent: AGENT, isDemo: true },
      vendor: story.vendor,
      valueUsd: story.valueUsd,
      pace: body.data.pace,
      blockAtMs: body.data.pace === "instant" ? 0 : BLOCK_AT_MS,
      sealAtMs: body.data.pace === "instant" ? 0 : SEAL_AT_MS,
    });
  });

  app.delete("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") return reply.code(403).send({ error: "forbidden" });
    const demoSessions = await db.session.findMany({
      where: { orgId: claims.orgId, isDemo: true },
      select: { id: true },
    });
    clearTimersFor(demoSessions.map((s) => s.id));
    // Deleting the demo deployment cascades its sessions, events,
    // receipts and policy-status row; stray demo sessions elsewhere
    // (none are expected) are removed explicitly.
    const [deployments, sessions] = await db.$transaction([
      db.deployment.deleteMany({ where: { orgId: claims.orgId, isDemo: true } }),
      db.session.deleteMany({ where: { orgId: claims.orgId, isDemo: true } }),
    ]);
    const actor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "demo.removed",
        ...actor,
        target: DEMO_DEPLOYMENT_NAME,
        metadata: { deploymentsRemoved: deployments.count, sessionsRemoved: demoSessions.length + sessions.count },
        req,
      },
      req.log,
    );
    return reply.send({ ok: true, deploymentsRemoved: deployments.count, sessionsRemoved: demoSessions.length });
  });
}
