/**
 * Org-level settings routes.
 *
 * Endpoints:
 *   GET   /retention              — current retention windows
 *   PATCH /retention              — update; owner+admin only
 *   POST  /retention/sweep-now    — manually trigger a sweep for the
 *                                    caller's org (owner+admin only).
 *                                    Returns counts so the operator can
 *                                    see what got deleted before the
 *                                    next scheduled tick.
 */
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { requireSession } from "../lib/session-middleware.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
import { sweepRetentionForOrg } from "../lib/retention.js";
import { refuseIfRetentionTooLong } from "../lib/entitlements.js";
import { ipMatchesAny, tryParseCidr } from "../lib/cidr.js";
import {
  challengeIsPublished,
  challengeRecordName,
  challengeRecordValue,
  newChallengeToken,
  normaliseDomain,
} from "../lib/domains.js";

export async function orgRoutes(app: FastifyInstance): Promise<void> {
  // Rename the workspace. Owner-only: the name is the org's public
  // identity — it appears in invite email SUBJECTS (mail.ts inviteMail),
  // the console chrome, and exports. The slug stays stable on purpose:
  // it's a join-key ingredient, and receipts/exports reference the org
  // id, so a rebrand must not invalidate anything already issued.
  // Same CRLF/NUL posture as signup's orgNameSchema (R184 F1): a CR/LF
  // smuggled into the name would otherwise inject SMTP headers via the
  // invite subject line.
  app.patch("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        name: z.string().max(80).trim().min(1)
          .refine((v) => !/[\r\n\u0000]/.test(v), "must not contain CR/LF/NUL"),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_name" });
    const prev = await db.org.findUnique({ where: { id: claims.orgId } });
    if (!prev) return reply.code(404).send({ error: "not_found" });
    if (prev.name === body.data.name) {
      return reply.send({ org: { id: prev.id, slug: prev.slug, name: prev.name } });
    }
    const updated = await db.org.update({
      where: { id: claims.orgId },
      data: { name: body.data.name },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.renamed",
        ...(await resolveActor(claims.sub)),
        target: updated.name,
        metadata: { previousName: prev.name },
        req,
      },
      req.log,
    );
    return reply.send({ org: { id: updated.id, slug: updated.slug, name: updated.name } });
  });

  app.get("/retention", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const org = await db.org.findUnique({
      where: { id: claims.orgId },
      select: {
        sessionRetentionDays: true,
        auditRetentionDays: true,
      },
    });
    if (!org) return reply.code(404).send({ error: "not_found" });
    return reply.send({ retention: org });
  });

  app.patch("/retention", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z
      .object({
        // 0 = keep forever. Otherwise 1-3650 (roughly 10 years) —
        // anything beyond that is almost certainly a typo.
        sessionRetentionDays: z.number().int().min(0).max(3650).optional(),
        auditRetentionDays: z.number().int().min(0).max(3650).optional(),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    // R145 F1: admins could historically wipe forensic evidence by
    // (1) lowering auditRetentionDays to 1, (2) POST /retention/sweep-now
    // to purge every auditEntry older than now-1day, (3) re-raising
    // auditRetentionDays back to normal. Result: member.role_changed,
    // deployment.token_rotated, saml.*, mfa.credential_revoked, etc.
    // gone; the only telltale is a single org.retention_updated row
    // showing "1", which the admin trivially explains away.
    // Same "admin destroys compliance data" class R94 F4 gated for
    // deployment.delete (?force=1) and R118 F1 gated for
    // owner-scoped API-key DELETE — retention was the outstanding
    // sibling. Require owner for RETENTION NARROWING (either
    // dimension shrinking); loosening or holding steady still
    // works at admin.
    const currentRetention = await db.org.findUnique({
      where: { id: claims.orgId },
      select: { sessionRetentionDays: true, auditRetentionDays: true, plan: true },
    });
    if (!currentRetention) return reply.code(404).send({ error: "not_found" });
    // Plan entitlement on the session window. Only LENGTHENING is
    // gated (0 = forever counts as the longest value): an org whose
    // current window already exceeds its plan keeps it and may still
    // shorten it.
    if (body.data.sessionRetentionDays !== undefined) {
      const asDays = (d: number) => (d === 0 ? Number.POSITIVE_INFINITY : d);
      const lengthening = asDays(body.data.sessionRetentionDays) > asDays(currentRetention.sessionRetentionDays);
      if (lengthening && refuseIfRetentionTooLong(req, reply, currentRetention.plan, body.data.sessionRetentionDays)) return;
    }
    const narrowingSession =
      body.data.sessionRetentionDays !== undefined &&
      body.data.sessionRetentionDays !== 0 &&
      (currentRetention.sessionRetentionDays === 0 ||
        body.data.sessionRetentionDays < currentRetention.sessionRetentionDays);
    const narrowingAudit =
      body.data.auditRetentionDays !== undefined &&
      body.data.auditRetentionDays !== 0 &&
      (currentRetention.auditRetentionDays === 0 ||
        body.data.auditRetentionDays < currentRetention.auditRetentionDays);
    if ((narrowingSession || narrowingAudit) && claims.membershipRole !== "owner") {
      // R146 F2: enrich actor email — auth.step_up_denied
      // rows benefit from operator attribution just like the
      // success-path rows.
      const narrowActor = await resolveActor(claims.sub);
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          ...narrowActor,
          note: "not_owner",
          metadata: { endpoint: "org.retention.narrow" },
          req,
        },
        req.log,
      );
      return reply
        .code(403)
        .send({ error: "only_owner_can_narrow_retention" });
    }
    const updated = await db.org.update({
      where: { id: claims.orgId },
      data: body.data,
      select: {
        sessionRetentionDays: true,
        auditRetentionDays: true,
      },
    });
    // R145 F3: enrich actor email — retention changes are exactly
    // the class of admin action ops wants attributed by email.
    const retentionActor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.retention_updated",
        ...retentionActor,
        target: claims.orgId,
        metadata: {
          sessionRetentionDays: updated.sessionRetentionDays,
          auditRetentionDays: updated.auditRetentionDays,
          // R145 F1: include prior values so a narrowing attempt
          // is spelled out for reviewers grepping the audit trail
          // — auditor can `SELECT * WHERE event='org.retention_updated'
          // AND metadata->>'previousAuditRetentionDays' > metadata->>'auditRetentionDays'`.
          previousSessionRetentionDays: currentRetention.sessionRetentionDays,
          previousAuditRetentionDays: currentRetention.auditRetentionDays,
        },
        req,
      },
      req.log,
    );
    return reply.send({ retention: updated });
  });

  app.post("/retention/sweep-now", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R145 F1: same rationale as PATCH /retention narrowing above.
    // sweep-now is the destructive execution leg — admin who
    // couldn't lower the window can't invoke the sweep either
    // (without narrowing first, this is a no-op purge of already-
    // expired rows, but by fencing owner-only we keep the primitive
    // consistent with the retention control itself).
    if (claims.membershipRole !== "owner") {
      // R146 F2: enrich actor email — sweep-now denial too.
      const sweepDeniedActor = await resolveActor(claims.sub);
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          ...sweepDeniedActor,
          note: "not_owner",
          metadata: { endpoint: "org.retention.sweep_now" },
          req,
        },
        req.log,
      );
      return reply.code(403).send({ error: "only_owner_can_sweep" });
    }
    const result = await sweepRetentionForOrg(claims.orgId, req.log);
    // R145 F3: enrich actor email — destructive purge deserves
    // clear attribution.
    const sweepActor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.retention_swept",
        ...sweepActor,
        target: claims.orgId,
        metadata: {
          sessionsPurged: result.sessionsPurged,
          auditPurged: result.auditPurged,
          webhookDeliveriesPurged: result.webhookDeliveriesPurged,
        },
        req,
      },
      req.log,
    );
    return reply.send({ result });
  });

  app.get("/ip-allowlist", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R93 F3: same read/write asymmetry as R92 F1 (invites) and
    // R91 F2 (audit). Members were able to read the org's trusted
    // CIDR blocks (recon: which corp VPN/bastion do admins egress
    // from) and their own detected req.ip (confirms whether their
    // stolen cookie would work from anywhere without alarm). The
    // sibling PATCH at line 202 gates on owner-only (per R146
    // F1); this GET stays admin-readable per R93 F3 as R146 F1
    // explicitly preserved ("GET remains admin-readable").
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const org = await db.org.findUnique({
      where: { id: claims.orgId },
      select: { ipAllowlist: true },
    });
    return reply.send({
      cidrs: org?.ipAllowlist ?? [],
      yourIp: req.ip,
    });
  });

  app.patch("/ip-allowlist", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R146 F1: owner-only for WRITE. Prior shape gated on
    // non-member so an admin could PATCH the allowlist to
    // ["<admin-ip>/32"], passing the self-lockout guard (their
    // own IP matches) — but the owner's next request through
    // requireSession would hit !ipMatchesAny(req.ip, cidrs) →
    // 403 forbidden_ip on every console endpoint including
    // PATCH /ip-allowlist itself. Owner's only recovery is a
    // DB console. Same "admin uses org-wide primitive to
    // sabotage recovery" class R145 F1 closed for retention:
    // R145 F1 shut the "destroy compliance data" leg; this
    // shuts the "deny owner access" leg. GET remains admin-
    // readable (per R93 F3 which needed admin visibility).
    if (claims.membershipRole !== "owner") {
      // R146 F2: enrich actor email.
      const ipDeniedActor = await resolveActor(claims.sub);
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          ...ipDeniedActor,
          note: "not_owner",
          metadata: { endpoint: "org.ip_allowlist.write" },
          req,
        },
        req.log,
      );
      return reply.code(403).send({ error: "only_owner_can_edit_ip_allowlist" });
    }
    const body = z
      .object({
        cidrs: z.array(z.string().min(1).max(64)).max(200),
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });

    // Reject any malformed CIDR — never silently drop rows.
    const cleaned: string[] = [];
    for (const raw of body.data.cidrs) {
      const trimmed = raw.trim();
      // Accept bare IP as /32 (v4) or /128 (v6) sugar.
      const withPrefix = trimmed.includes("/")
        ? trimmed
        : trimmed.includes(":")
          ? trimmed + "/128"
          : trimmed + "/32";
      const parsed = tryParseCidr(withPrefix);
      if (!parsed) {
        return reply.code(400).send({ error: "invalid_cidr", cidr: raw });
      }
      cleaned.push(withPrefix);
    }
    // Self-lockout guard: refuse to save a non-empty allowlist that
    // wouldn't include the caller's own current IP. The operator can
    // still deliberately shut themselves out by first opening a shell
    // and hitting the API directly, but the console UI can't do it by
    // accident.
    if (cleaned.length > 0 && !ipMatchesAny(req.ip, cleaned)) {
      return reply.code(400).send({ error: "would_lock_yourself_out", yourIp: req.ip });
    }
    const updated = await db.org.update({
      where: { id: claims.orgId },
      data: { ipAllowlist: cleaned },
      select: { ipAllowlist: true },
    });
    // R146 F2: enrich actor email — ip_allowlist changes deserve
    // owner-identifying attribution.
    const ipUpdateActor = await resolveActor(claims.sub);
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.ip_allowlist_updated",
        ...ipUpdateActor,
        target: claims.orgId,
        metadata: { cidrs: updated.ipAllowlist, byIp: req.ip },
        req,
      },
      req.log,
    );
    return reply.send({ cidrs: updated.ipAllowlist });
  });

  // ---------------------------------------------------------------
  // Verified email domains (SAML discovery). An organisation claims a
  // domain, publishes the TXT record the response describes, then asks
  // for a check. Only a verified domain takes part in anonymous SAML
  // discovery (lib/saml.ts findConfigForEmail). Reads are admin-level
  // like the IP allow-list; writes are owner-only because a verified
  // domain decides where every sign-in for that domain is sent.
  // ---------------------------------------------------------------
  function domainWire(d: { id: string; domain: string; token: string; verifiedAt: Date | null; createdAt: Date }) {
    return {
      id: d.id,
      domain: d.domain,
      verifiedAt: d.verifiedAt,
      createdAt: d.createdAt,
      txtRecord: { name: challengeRecordName(d.domain), value: challengeRecordValue(d.token) },
    };
  }

  app.get("/domains", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const rows = await db.orgDomain.findMany({
      where: { orgId: claims.orgId },
      orderBy: { createdAt: "asc" },
    });
    return reply.send({ domains: rows.map(domainWire) });
  });

  app.post("/domains", {
    config: { rateLimit: { max: 20, timeWindow: 60_000 } },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const body = z.object({ domain: z.string().min(3).max(253) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const domain = normaliseDomain(body.data.domain);
    if (!domain) return reply.code(400).send({ error: "invalid_domain" });
    const count = await db.orgDomain.count({ where: { orgId: claims.orgId } });
    if (count >= 50) return reply.code(400).send({ error: "too_many_domains" });
    const existing = await db.orgDomain.findUnique({ where: { domain } });
    if (existing) {
      // Same answer whether another org or this one holds it: a claim
      // never reveals which organisation already uses a domain.
      return reply.code(409).send({ error: "domain_claimed" });
    }
    let row;
    try {
      row = await db.orgDomain.create({
        data: { orgId: claims.orgId, domain, token: newChallengeToken() },
      });
    } catch (err) {
      if (err instanceof Error && "code" in err && (err as { code?: string }).code === "P2002") {
        return reply.code(409).send({ error: "domain_claimed" });
      }
      throw err;
    }
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.domain_added",
        ...(await resolveActor(claims.sub)),
        target: domain,
        metadata: { domainId: row.id },
        req,
      },
      req.log,
    );
    return reply.code(201).send({ domain: domainWire(row) });
  });

  app.post<{ Params: { id: string } }>("/domains/:id/verify", {
    // A DNS lookup per call; keep a stuck admin from hammering resolvers.
    config: { rateLimit: { max: 30, timeWindow: 60_000 } },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const row = await db.orgDomain.findFirst({
      where: { id: req.params.id, orgId: claims.orgId },
    });
    if (!row) return reply.code(404).send({ error: "not_found" });
    if (row.verifiedAt) return reply.send({ domain: domainWire(row), verified: true });
    const published = await challengeIsPublished(row.domain, row.token);
    if (!published) {
      return reply.code(409).send({
        error: "txt_record_not_found",
        domain: domainWire(row),
        verified: false,
      });
    }
    const verified = await db.orgDomain.update({
      where: { id: row.id },
      data: { verifiedAt: new Date() },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.domain_verified",
        ...(await resolveActor(claims.sub)),
        target: row.domain,
        metadata: { domainId: row.id },
        req,
      },
      req.log,
    );
    return reply.send({ domain: domainWire(verified), verified: true });
  });

  app.delete<{ Params: { id: string } }>("/domains/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const removed = await db.orgDomain.deleteMany({
      where: { id: req.params.id, orgId: claims.orgId },
    });
    if (removed.count === 0) return reply.code(404).send({ error: "not_found" });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.domain_removed",
        ...(await resolveActor(claims.sub)),
        target: req.params.id,
        metadata: { domainId: req.params.id },
        req,
      },
      req.log,
    );
    return reply.code(204).send();
  });
}
