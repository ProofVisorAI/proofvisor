/**
 * SCIM 2.0 provisioning (RFC 7643 schemas, RFC 7644 protocol).
 *
 * Two plugins live here:
 *
 *   scimAdminRoutes — owner-only management under /api/v1/scim
 *     GET/PATCH /settings          enabled, defaultRole, deprovisionAction
 *     GET/POST  /tokens            list / mint a bearer token (shown once)
 *     DELETE    /tokens/:id        revoke
 *
 *   scimRoutes — what the identity provider calls, under /scim/v2,
 *   authenticated with `Authorization: Bearer pv_scim_<32 chars>`:
 *     GET  /ServiceProviderConfig, /ResourceTypes, /Schemas   discovery
 *     GET  /Users?filter=userName eq "…"&startIndex=&count=   list
 *     GET/POST/PUT/PATCH/DELETE /Users[/:id]
 *     GET/POST/PUT/PATCH/DELETE /Groups[/:id]
 *
 * Resource ids: a SCIM User is the user's MEMBERSHIP in the token's
 * organisation (membership.id). That makes every id tenant-scoped by
 * construction — a token for org A can never address org B's rows —
 * and lets one person be provisioned independently by two tenants'
 * IdPs. `userName` is the email; `externalId` is stored on the user.
 *
 * Deprovisioning (`active: false` or DELETE) follows the org setting:
 *   deactivate — membership.active = false, every session of the user
 *                fenced (sessionRevokedAt), API keys they created in
 *                this org revoked. The IdP can re-activate later.
 *   remove     — the membership row is deleted (plus the key revoke).
 * The last active owner can never be deactivated, removed or demoted.
 *
 * Groups map to roles: a group named "owner", "admin" or "member"
 * (case-insensitive) assigns that role to its members. When a member
 * is added to or removed from a mapped group their role becomes the
 * highest mapped role among the groups they are in, or the org's
 * default role when none is left. Groups with any other name are
 * stored and returned but change nothing.
 *
 * Errors use the SCIM error schema (`status` as a string, optional
 * `scimType`). Audit slugs: scim.user.created|updated|deactivated|
 * removed, scim.group.created|updated|deleted, scim.settings_updated,
 * scim.token_created|revoked.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { apiPublicBase } from "../env.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
import { hashPassword, randomToken, verifyPassword } from "../lib/auth.js";
import {
  limitsFor,
  planThatLifts,
  planUsage,
  refuseIfFeatureMissing,
} from "../lib/entitlements.js";
import { requireSession } from "../lib/session-middleware.js";

export const SCIM_TOKEN_PREFIX = "pv_scim_";
const SCIM_CT = "application/scim+json";
const SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCHEMA_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const SCHEMA_RT = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema";

type Role = "owner" | "admin" | "member";
const ROLES: readonly Role[] = ["owner", "admin", "member"] as const;
const RANK: Record<Role, number> = { owner: 3, admin: 2, member: 1 };
const MAX_PAGE = 200;

function isRole(v: unknown): v is Role {
  return v === "owner" || v === "admin" || v === "member";
}

/** The role a group grants its members, or null for an unmapped group. */
export function roleForGroupName(displayName: string): Role | null {
  const n = displayName.trim().toLowerCase();
  return isRole(n) ? n : null;
}

function scimBase(): string {
  return apiPublicBase() + "/scim/v2";
}

// -------------------------------------------------------------------
// SCIM error + response helpers
// -------------------------------------------------------------------

class ScimError extends Error {
  constructor(
    public status: number,
    public detail: string,
    public scimType?: string,
  ) {
    super(detail);
  }
}

function sendScimError(reply: FastifyReply, status: number, detail: string, scimType?: string) {
  return reply
    .code(status)
    .type(SCIM_CT)
    .send({
      schemas: [SCHEMA_ERROR],
      status: String(status),
      ...(scimType ? { scimType } : {}),
      detail,
    });
}

function sendScim(reply: FastifyReply, status: number, body: unknown, location?: string) {
  if (location) reply.header("Location", location);
  return reply.code(status).type(SCIM_CT).send(body);
}

// -------------------------------------------------------------------
// Data shapes
// -------------------------------------------------------------------

const membershipSelect = {
  id: true,
  orgId: true,
  userId: true,
  role: true,
  active: true,
  createdAt: true,
  updatedAt: true,
  user: {
    select: {
      id: true,
      email: true,
      displayName: true,
      scimExternalId: true,
      scimGroupMembers: {
        select: { group: { select: { id: true, displayName: true, orgId: true } } },
      },
    },
  },
} as const;

type MembershipRow = {
  id: string;
  orgId: string;
  userId: string;
  role: string;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
  user: {
    id: string;
    email: string;
    displayName: string | null;
    scimExternalId: string | null;
    scimGroupMembers: { group: { id: string; displayName: string; orgId: string } }[];
  };
};

function splitName(displayName: string | null): { givenName?: string; familyName?: string; formatted?: string } {
  const d = (displayName ?? "").trim();
  if (!d) return {};
  const idx = d.lastIndexOf(" ");
  if (idx < 0) return { givenName: d, formatted: d };
  return { givenName: d.slice(0, idx), familyName: d.slice(idx + 1), formatted: d };
}

function serializeUser(m: MembershipRow) {
  const base = scimBase();
  return {
    schemas: [SCHEMA_USER],
    id: m.id,
    externalId: m.user.scimExternalId ?? undefined,
    userName: m.user.email,
    displayName: m.user.displayName ?? undefined,
    name: splitName(m.user.displayName),
    emails: [{ value: m.user.email, type: "work", primary: true }],
    active: m.active,
    // Extension-free hint of the role the membership currently has —
    // handy for IdP admins debugging group mapping. Read-only.
    roles: [{ value: m.role, primary: true }],
    groups: m.user.scimGroupMembers
      .filter((g) => g.group.orgId === m.orgId)
      .map((g) => ({ value: g.group.id, display: g.group.displayName, $ref: `${base}/Groups/${g.group.id}` })),
    meta: {
      resourceType: "User",
      created: m.createdAt.toISOString(),
      lastModified: m.updatedAt.toISOString(),
      location: `${base}/Users/${m.id}`,
    },
  };
}

const groupSelect = {
  id: true,
  orgId: true,
  displayName: true,
  externalId: true,
  role: true,
  createdAt: true,
  updatedAt: true,
  members: {
    select: {
      userId: true,
      user: {
        select: {
          email: true,
          memberships: { select: { id: true, orgId: true } },
        },
      },
    },
  },
} as const;

type GroupRow = {
  id: string;
  orgId: string;
  displayName: string;
  externalId: string | null;
  role: string | null;
  createdAt: Date;
  updatedAt: Date;
  members: { userId: string; user: { email: string; memberships: { id: string; orgId: string }[] } }[];
};

function serializeGroup(g: GroupRow) {
  const base = scimBase();
  return {
    schemas: [SCHEMA_GROUP],
    id: g.id,
    externalId: g.externalId ?? undefined,
    displayName: g.displayName,
    members: g.members.flatMap((m) => {
      const membership = m.user.memberships.find((x) => x.orgId === g.orgId);
      if (!membership) return [];
      return [{ value: membership.id, display: m.user.email, $ref: `${base}/Users/${membership.id}` }];
    }),
    meta: {
      resourceType: "Group",
      created: g.createdAt.toISOString(),
      lastModified: g.updatedAt.toISOString(),
      location: `${base}/Groups/${g.id}`,
    },
  };
}

// -------------------------------------------------------------------
// Filter + pagination parsing
// -------------------------------------------------------------------

/**
 * Only the equality filter IdPs actually send (`attr eq "value"`,
 * optionally with a value-path like emails[type eq "work"].value).
 * Anything else is 400 invalidFilter rather than a silent full list.
 */
function parseEqFilter(raw: string | undefined, allowed: string[]): { attr: string; value: string } | null {
  if (raw === undefined) return null;
  const m = /^\s*([A-Za-z][\w$-]*(?:\.[A-Za-z]\w*)?)(?:\[[^\]]*\])?(?:\.value)?\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i.exec(raw);
  if (!m) throw new ScimError(400, "Only filters of the form `attribute eq \"value\"` are supported.", "invalidFilter");
  const attr = m[1]!.toLowerCase();
  const value = m[2]!.replace(/\\(.)/g, "$1");
  if (!allowed.includes(attr)) {
    throw new ScimError(400, `Filtering on "${m[1]}" is not supported.`, "invalidFilter");
  }
  return { attr, value };
}

function parsePaging(q: Record<string, unknown>): { skip: number; take: number; startIndex: number } {
  const si = Number(q.startIndex ?? 1);
  const c = Number(q.count ?? 100);
  if (!Number.isInteger(si) || !Number.isInteger(c)) {
    throw new ScimError(400, "startIndex and count must be integers.", "invalidValue");
  }
  const startIndex = Math.max(1, si);
  const take = Math.min(MAX_PAGE, Math.max(0, c));
  return { skip: startIndex - 1, take, startIndex };
}

function listResponse(total: number, startIndex: number, resources: unknown[]) {
  return {
    schemas: [SCHEMA_LIST],
    totalResults: total,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

// -------------------------------------------------------------------
// Body schemas (zod 4: no defaults on fields that may be absent, so a
// PUT that omits `active` leaves it alone instead of "defaulting" it)
// -------------------------------------------------------------------

const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "must be a valid email")
  .transform((v) => v.normalize("NFC"));

const activeSchema = z.union([z.boolean(), z.string()]).transform((v, ctx) => {
  if (typeof v === "boolean") return v;
  const s = v.trim().toLowerCase();
  if (s === "true") return true;
  if (s === "false") return false;
  ctx.addIssue({ code: "custom", message: "active must be a boolean" });
  return z.NEVER;
});

const nameSchema = z
  .object({
    givenName: z.string().max(100).nullish(),
    familyName: z.string().max(100).nullish(),
    formatted: z.string().max(200).nullish(),
  })
  .loose();

const userBodySchema = z
  .object({
    schemas: z.array(z.string()).optional(),
    userName: z.string().max(320).optional(),
    externalId: z.string().max(256).nullish(),
    displayName: z.string().max(200).nullish(),
    name: nameSchema.nullish(),
    emails: z
      .array(
        z.object({ value: z.string().max(320).optional(), primary: z.boolean().optional(), type: z.string().optional() }).loose(),
      )
      .optional(),
    active: activeSchema.optional(),
  })
  .loose();

type UserBody = z.infer<typeof userBodySchema>;

/** Attribute changes the handlers apply to a membership + user. */
interface UserChanges {
  email?: string;
  externalId?: string | null;
  displayName?: string | null;
  givenName?: string | null;
  familyName?: string | null;
  active?: boolean;
}

function emailFromBody(b: UserBody): string | undefined {
  const primary = b.emails?.find((e) => e.primary && e.value)?.value ?? b.emails?.find((e) => e.value)?.value;
  const candidate = b.userName && b.userName.includes("@") ? b.userName : primary;
  if (!candidate) return undefined;
  const parsed = emailSchema.safeParse(candidate);
  if (!parsed.success) throw new ScimError(400, "userName (or a primary email) must be a valid email address.", "invalidValue");
  return parsed.data;
}

function changesFromBody(b: UserBody): UserChanges {
  const c: UserChanges = {};
  const email = emailFromBody(b);
  if (email) c.email = email;
  if (b.externalId !== undefined) c.externalId = b.externalId ?? null;
  if (b.displayName !== undefined) c.displayName = b.displayName ?? null;
  if (b.name) {
    if (b.name.givenName !== undefined) c.givenName = b.name.givenName ?? null;
    if (b.name.familyName !== undefined) c.familyName = b.name.familyName ?? null;
    if (b.name.formatted !== undefined && c.displayName === undefined) c.displayName = b.name.formatted ?? null;
  }
  if (b.active !== undefined) c.active = b.active;
  return c;
}

function resolveDisplayName(current: string | null, c: UserChanges): string | null | undefined {
  if (c.displayName !== undefined) return c.displayName === "" ? null : c.displayName;
  if (c.givenName === undefined && c.familyName === undefined) return undefined;
  const parts = splitName(current);
  const given = c.givenName === undefined ? parts.givenName : c.givenName ?? "";
  const family = c.familyName === undefined ? parts.familyName : c.familyName ?? "";
  const joined = [given, family].filter((s) => s && s.trim()).join(" ").trim();
  return joined || null;
}

// -------------------------------------------------------------------
// PATCH operation parsing (RFC 7644 §3.5.2)
// -------------------------------------------------------------------

const patchSchema = z.object({
  schemas: z.array(z.string()).optional(),
  Operations: z
    .array(
      z
        .object({
          op: z.string(),
          path: z.string().max(512).optional(),
          value: z.unknown().optional(),
        })
        .loose(),
    )
    .min(1),
});

type PatchOp = { op: "add" | "replace" | "remove"; path?: string; value?: unknown };

function parsePatch(body: unknown): PatchOp[] {
  const parsed = patchSchema.safeParse(body);
  if (!parsed.success) {
    throw new ScimError(400, "PATCH body must carry a non-empty Operations array of {op, path?, value?}.", "invalidSyntax");
  }
  if (parsed.data.schemas && !parsed.data.schemas.includes(SCHEMA_PATCH)) {
    throw new ScimError(400, `PATCH schemas must include ${SCHEMA_PATCH}.`, "invalidSyntax");
  }
  return parsed.data.Operations.map((o) => {
    const op = o.op.toLowerCase();
    if (op !== "add" && op !== "replace" && op !== "remove") {
      throw new ScimError(400, `Unsupported PATCH op "${o.op}".`, "invalidSyntax");
    }
    if (op !== "remove" && o.value === undefined) {
      throw new ScimError(400, `PATCH op "${op}" requires a value.`, "invalidValue");
    }
    return { op, path: o.path, value: o.value } as PatchOp;
  });
}

function normalizePath(path: string): string {
  // Strip the core schema URN prefix some IdPs prepend
  // ("urn:…:User:active") and lowercase for matching.
  return path.replace(new RegExp("^" + SCHEMA_USER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ":", "i"), "").trim();
}

function userChangesFromPatch(ops: PatchOp[]): UserChanges {
  const c: UserChanges = {};
  const applyAttr = (attr: string, value: unknown, remove: boolean) => {
    const a = attr.toLowerCase();
    const str = (v: unknown): string | null => {
      if (remove || v === null) return null;
      if (typeof v !== "string") throw new ScimError(400, `Attribute "${attr}" must be a string.`, "invalidValue");
      return v;
    };
    if (a === "active") {
      if (remove) throw new ScimError(400, "active cannot be removed.", "mutability");
      const parsed = activeSchema.safeParse(value);
      if (!parsed.success) throw new ScimError(400, "active must be a boolean.", "invalidValue");
      c.active = parsed.data;
    } else if (a === "username") {
      const v = str(value);
      if (v === null) throw new ScimError(400, "userName is required.", "mutability");
      const parsed = emailSchema.safeParse(v);
      if (!parsed.success) throw new ScimError(400, "userName must be a valid email address.", "invalidValue");
      c.email = parsed.data;
    } else if (a === "externalid") c.externalId = str(value);
    else if (a === "displayname") c.displayName = str(value);
    else if (a === "name.givenname") c.givenName = str(value);
    else if (a === "name.familyname") c.familyName = str(value);
    else if (a === "name.formatted") c.displayName = str(value);
    else if (a === "name") {
      if (remove || value === null) { c.displayName = null; return; }
      const parsed = nameSchema.safeParse(value);
      if (!parsed.success) throw new ScimError(400, "name must be an object.", "invalidValue");
      if (parsed.data.givenName !== undefined) c.givenName = parsed.data.givenName ?? null;
      if (parsed.data.familyName !== undefined) c.familyName = parsed.data.familyName ?? null;
      if (parsed.data.formatted !== undefined) c.displayName = parsed.data.formatted ?? null;
    } else if (a === "emails" || a.startsWith("emails[") || a === "emails.value") {
      if (remove) throw new ScimError(400, "emails cannot be removed — a user needs an address.", "mutability");
      let v: unknown = value;
      if (Array.isArray(v)) v = v.find((e) => e && typeof e === "object" && (e as { primary?: boolean }).primary) ?? v[0];
      if (v && typeof v === "object" && "value" in (v as object)) v = (v as { value: unknown }).value;
      const parsed = emailSchema.safeParse(v);
      if (!parsed.success) throw new ScimError(400, "emails must carry a valid email address.", "invalidValue");
      c.email = parsed.data;
    } else if (a === "schemas" || a === "id" || a === "meta" || a === "groups" || a === "roles" || a === "password") {
      // Read-only or unsupported, but harmless: Azure AD sends
      // `roles`/`password` in some templates. Ignore.
    } else {
      throw new ScimError(400, `Unknown or unsupported attribute path "${attr}".`, "invalidPath");
    }
  };
  for (const op of ops) {
    if (op.path) {
      applyAttr(normalizePath(op.path), op.value, op.op === "remove");
      continue;
    }
    if (op.op === "remove") throw new ScimError(400, "remove requires a path.", "noTarget");
    if (!op.value || typeof op.value !== "object" || Array.isArray(op.value)) {
      throw new ScimError(400, "A PATCH op without a path needs an object value.", "invalidValue");
    }
    for (const [k, v] of Object.entries(op.value as Record<string, unknown>)) applyAttr(normalizePath(k), v, false);
  }
  return c;
}

// -------------------------------------------------------------------
// Tenant auth for /scim/v2
// -------------------------------------------------------------------

async function authenticateScim(req: FastifyRequest, reply: FastifyReply): Promise<boolean> {
  const auth = req.headers.authorization;
  const bearer = typeof auth === "string" && /^bearer\s+/i.test(auth) ? auth.replace(/^bearer\s+/i, "").trim() : "";
  if (!bearer.startsWith(SCIM_TOKEN_PREFIX)) {
    reply.header("WWW-Authenticate", 'Bearer realm="scim"');
    await sendScimError(reply, 401, "A SCIM bearer token (pv_scim_…) is required.", "invalidValue");
    return false;
  }
  const hint = bearer.slice(SCIM_TOKEN_PREFIX.length, SCIM_TOKEN_PREFIX.length + 8);
  const candidates = await db.scimToken.findMany({
    where: { tokenHint: hint, revokedAt: null },
    select: {
      id: true,
      orgId: true,
      tokenHash: true,
      org: { select: { scimEnabled: true, scimDefaultRole: true, scimDeprovisionAction: true, plan: true } },
    },
  });
  let match: (typeof candidates)[number] | null = null;
  for (const c of candidates) {
    // argon2 verify — constant-time in the hash comparison, same as
    // API keys (lib/auth.ts verifyPassword).
    if (await verifyPassword(c.tokenHash, bearer)) { match = c; break; }
  }
  if (!match) {
    // Burn the same argon2 budget when no candidate matched so a
    // wrong hint and a wrong token are indistinguishable on the wire.
    if (candidates.length === 0) await verifyPassword("not-argon2", bearer);
    reply.header("WWW-Authenticate", 'Bearer realm="scim", error="invalid_token"');
    await sendScimError(reply, 401, "The SCIM bearer token is invalid or has been revoked.", "invalidValue");
    return false;
  }
  if (!match.org.scimEnabled) {
    await sendScimError(reply, 403, "SCIM provisioning is disabled for this organisation. An owner can enable it under Settings → SSO.");
    return false;
  }
  if (!limitsFor(match.org.plan).scim) {
    await sendScimError(reply, 402, `SCIM provisioning is not included in the ${match.org.plan} plan.`);
    return false;
  }
  req.scim = {
    orgId: match.orgId,
    tokenId: match.id,
    defaultRole: match.org.scimDefaultRole === "admin" ? "admin" : "member",
    deprovisionAction: match.org.scimDeprovisionAction === "remove" ? "remove" : "deactivate",
    plan: match.org.plan,
  };
  void db.scimToken.update({ where: { id: match.id }, data: { lastUsedAt: new Date() } }).catch(() => void 0);
  return true;
}

function scimActor(req: FastifyRequest) {
  return { actorId: "scim:" + (req.scim?.tokenId ?? "unknown"), actorEmail: null };
}

// -------------------------------------------------------------------
// Role + deprovision helpers
// -------------------------------------------------------------------

async function activeOwnerCount(orgId: string): Promise<number> {
  return db.membership.count({ where: { orgId, role: "owner", active: true } });
}

/**
 * Deactivate or remove one membership. Throws ScimError(400,
 * mutability) when the target is the last active owner.
 */
async function deprovision(req: FastifyRequest, m: MembershipRow, action: "deactivate" | "remove"): Promise<void> {
  if (m.role === "owner" && m.active && (await activeOwnerCount(m.orgId)) <= 1) {
    throw new ScimError(400, "This user is the last active owner of the organisation and cannot be deprovisioned.", "mutability");
  }
  await db.$transaction(async (tx) => {
    if (action === "remove") {
      await tx.membership.delete({ where: { id: m.id } });
      await tx.scimGroupMember.deleteMany({ where: { userId: m.userId, group: { orgId: m.orgId } } });
    } else {
      await tx.membership.update({ where: { id: m.id }, data: { active: false } });
    }
    // Fence every outstanding cookie of this user (session-middleware
    // compares the JWT mint instant against this timestamp) …
    await tx.user.update({ where: { id: m.userId }, data: { sessionRevokedAt: new Date() } });
    // … and revoke API keys they minted in this org.
    await tx.apiKey.updateMany({
      where: { orgId: m.orgId, createdById: m.userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  });
  writeAudit(
    {
      orgId: m.orgId,
      event: action === "remove" ? "scim.user.removed" : "scim.user.deactivated",
      ...scimActor(req),
      target: m.user.email,
      metadata: { membershipId: m.id, userId: m.userId, role: m.role, action },
      req,
    },
    req.log,
  );
}

/**
 * Change a membership's role the way members.ts does: fence the
 * user's sessions and revoke API keys above the new rank.
 */
async function applyRole(req: FastifyRequest, m: { id: string; orgId: string; userId: string; role: string; active: boolean; email: string }, newRole: Role, reason: string): Promise<void> {
  if (m.role === newRole) return;
  if (m.role === "owner" && m.active && (await activeOwnerCount(m.orgId)) <= 1) {
    throw new ScimError(400, `${m.email} is the last active owner of the organisation and cannot be demoted.`, "mutability");
  }
  await db.$transaction(async (tx) => {
    await tx.membership.update({ where: { id: m.id }, data: { role: newRole } });
    await tx.user.update({ where: { id: m.userId }, data: { sessionRevokedAt: new Date() } });
    await tx.apiKey.updateMany({
      where: {
        orgId: m.orgId,
        createdById: m.userId,
        revokedAt: null,
        role: { in: ROLES.filter((r) => RANK[r] > RANK[newRole]) },
      },
      data: { revokedAt: new Date() },
    });
  });
  writeAudit(
    {
      orgId: m.orgId,
      event: "scim.user.updated",
      ...scimActor(req),
      target: m.email,
      metadata: { membershipId: m.id, fromRole: m.role, toRole: newRole, reason },
      req,
    },
    req.log,
  );
}

/**
 * Recompute the role of each listed user from the mapped groups they
 * belong to in this org. Users in no mapped group get the default role.
 */
async function recomputeRoles(req: FastifyRequest, orgId: string, userIds: string[], defaultRole: Role, reason: string): Promise<void> {
  const unique = [...new Set(userIds)];
  if (unique.length === 0) return;
  const memberships = await db.membership.findMany({
    where: { orgId, userId: { in: unique } },
    select: { id: true, orgId: true, userId: true, role: true, active: true, user: { select: { email: true } } },
  });
  const groupRows = await db.scimGroupMember.findMany({
    where: { userId: { in: unique }, group: { orgId } },
    select: { userId: true, group: { select: { role: true } } },
  });
  for (const m of memberships) {
    let best: Role | null = null;
    for (const g of groupRows) {
      if (g.userId !== m.userId || !isRole(g.group.role)) continue;
      if (!best || RANK[g.group.role] > RANK[best]) best = g.group.role;
    }
    const target = best ?? defaultRole;
    await applyRole(req, { ...m, email: m.user.email }, target, reason);
  }
}

// -------------------------------------------------------------------
// Member lookups
// -------------------------------------------------------------------

async function findMembership(orgId: string, id: string): Promise<MembershipRow> {
  const m = await db.membership.findFirst({ where: { id, orgId }, select: membershipSelect });
  if (!m) throw new ScimError(404, `User ${id} not found.`);
  return m;
}

async function findGroup(orgId: string, id: string): Promise<GroupRow> {
  const g = await db.scimGroup.findFirst({ where: { id, orgId }, select: groupSelect });
  if (!g) throw new ScimError(404, `Group ${id} not found.`);
  return g;
}

/** Resolve SCIM group member references (membership ids) to user ids. */
async function resolveMemberValues(orgId: string, values: unknown): Promise<string[]> {
  if (!Array.isArray(values)) throw new ScimError(400, "members must be an array of {value}.", "invalidValue");
  const ids: string[] = [];
  for (const v of values) {
    const id = v && typeof v === "object" ? (v as { value?: unknown }).value : v;
    if (typeof id !== "string" || !id) throw new ScimError(400, "Each group member needs a string `value` (the User id).", "invalidValue");
    ids.push(id);
  }
  if (ids.length === 0) return [];
  const rows = await db.membership.findMany({ where: { orgId, id: { in: ids } }, select: { id: true, userId: true } });
  const byId = new Map(rows.map((r) => [r.id, r.userId]));
  return ids.map((id) => {
    const u = byId.get(id);
    if (!u) throw new ScimError(404, `Group member ${id} is not a User of this organisation.`, "invalidValue");
    return u;
  });
}

// -------------------------------------------------------------------
// User attribute application (shared by POST/PUT/PATCH)
// -------------------------------------------------------------------

async function applyUserChanges(req: FastifyRequest, m: MembershipRow, c: UserChanges): Promise<{ membership: MembershipRow | null; removed: boolean }> {
  const userData: { email?: string; scimExternalId?: string | null; displayName?: string | null } = {};
  if (c.email && c.email !== m.user.email) {
    // Changing the login email of an account that also belongs to
    // another organisation would let this tenant's IdP redirect the
    // other tenant's password-reset mail — refuse.
    const otherOrgs = await db.membership.count({ where: { userId: m.userId, orgId: { not: m.orgId } } });
    if (otherOrgs > 0) {
      throw new ScimError(400, "userName cannot be changed for a user who is also a member of another organisation.", "mutability");
    }
    const taken = await db.user.findUnique({ where: { email: c.email }, select: { id: true } });
    if (taken && taken.id !== m.userId) throw new ScimError(409, `userName ${c.email} is already in use.`, "uniqueness");
    userData.email = c.email;
  }
  if (c.externalId !== undefined && c.externalId !== m.user.scimExternalId) userData.scimExternalId = c.externalId;
  const dn = resolveDisplayName(m.user.displayName, c);
  if (dn !== undefined && dn !== m.user.displayName) userData.displayName = dn;

  if (Object.keys(userData).length > 0) {
    await db.user.update({ where: { id: m.userId }, data: userData });
    writeAudit(
      {
        orgId: m.orgId,
        event: "scim.user.updated",
        ...scimActor(req),
        target: userData.email ?? m.user.email,
        metadata: { membershipId: m.id, changed: Object.keys(userData), previousEmail: userData.email ? m.user.email : undefined },
        req,
      },
      req.log,
    );
  }

  if (c.active === false && m.active) {
    const action = req.scim?.deprovisionAction ?? "deactivate";
    await deprovision(req, m, action);
    if (action === "remove") return { membership: null, removed: true };
  } else if (c.active === true && !m.active) {
    await db.membership.update({ where: { id: m.id }, data: { active: true } });
    writeAudit(
      { orgId: m.orgId, event: "scim.user.updated", ...scimActor(req), target: m.user.email, metadata: { membershipId: m.id, reactivated: true }, req },
      req.log,
    );
  }
  return { membership: await findMembership(m.orgId, m.id), removed: false };
}

// -------------------------------------------------------------------
// Plugin: /scim/v2
// -------------------------------------------------------------------

const SCIM_RATE = { max: 240, timeWindow: 60_000, keyGenerator: (req: { ip: string }) => "scim:" + req.ip };

export async function scimRoutes(app: FastifyInstance): Promise<void> {
  // IdPs send application/scim+json; Fastify only parses
  // application/json by default. Parse failures surface as SCIM
  // invalidSyntax through the scoped error handler below.
  app.addContentTypeParser(["application/scim+json", "application/scim+json; charset=utf-8"], { parseAs: "string" }, (_req, body, done) => {
    const text = typeof body === "string" ? body : body.toString("utf8");
    if (text.trim() === "") return done(null, {});
    try {
      done(null, JSON.parse(text));
    } catch {
      done(new ScimError(400, "Request body is not valid JSON.", "invalidSyntax"));
    }
  });

  app.setErrorHandler(async (err: unknown, req, reply) => {
    if (err instanceof ScimError) return sendScimError(reply, err.status, err.detail, err.scimType);
    const e = err as { statusCode?: number; code?: string; message?: string };
    if (e.statusCode === 429) return sendScimError(reply, 429, "Too many requests.", "tooMany");
    if (e.statusCode === 400 || (typeof e.code === "string" && e.code.startsWith("FST_ERR_CTP"))) {
      return sendScimError(reply, 400, "Request body is not valid JSON.", "invalidSyntax");
    }
    if (e.statusCode && e.statusCode >= 400 && e.statusCode < 500) {
      return sendScimError(reply, e.statusCode, e.message ?? "Request failed.");
    }
    req.log.error({ err }, "scim_unhandled_error");
    return sendScimError(reply, 500, "An unexpected error occurred.");
  });

  app.setNotFoundHandler(async (req, reply) => sendScimError(reply, 404, `No SCIM resource at ${req.method} ${req.url}.`));

  const DISCOVERY = new Set(["/ServiceProviderConfig", "/ResourceTypes", "/Schemas"]);
  app.addHook("preHandler", async (req, reply) => {
    const path = (req.routeOptions?.url ?? req.url).replace(/^\/scim\/v2/, "").split("?")[0] ?? "";
    if (DISCOVERY.has(path) || path.startsWith("/Schemas/") || path.startsWith("/ResourceTypes/")) return;
    const ok = await authenticateScim(req, reply);
    if (!ok) return reply;
  });

  // ---------------- discovery ----------------
  app.get("/ServiceProviderConfig", { config: { rateLimit: SCIM_RATE } }, async (_req, reply) =>
    sendScim(reply, 200, {
      schemas: [SCHEMA_SPC],
      documentationUri: "https://github.com/ProofVisorAI/proofvisor/blob/main/server/README.md#scim-20-provisioning",
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: MAX_PAGE },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          type: "oauthbearertoken",
          name: "Bearer token",
          description: "Authorization: Bearer pv_scim_… — created by an organisation owner under Settings → SSO → SCIM.",
          primary: true,
        },
      ],
      meta: { resourceType: "ServiceProviderConfig", location: `${scimBase()}/ServiceProviderConfig` },
    }),
  );

  const resourceTypes = () => [
    {
      schemas: [SCHEMA_RT],
      id: "User",
      name: "User",
      endpoint: "/Users",
      description: "A member of the organisation",
      schema: SCHEMA_USER,
      meta: { resourceType: "ResourceType", location: `${scimBase()}/ResourceTypes/User` },
    },
    {
      schemas: [SCHEMA_RT],
      id: "Group",
      name: "Group",
      endpoint: "/Groups",
      description: "A group; groups named owner, admin or member assign that role",
      schema: SCHEMA_GROUP,
      meta: { resourceType: "ResourceType", location: `${scimBase()}/ResourceTypes/Group` },
    },
  ];
  app.get("/ResourceTypes", { config: { rateLimit: SCIM_RATE } }, async (_req, reply) =>
    sendScim(reply, 200, listResponse(2, 1, resourceTypes())),
  );
  app.get<{ Params: { id: string } }>("/ResourceTypes/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const rt = resourceTypes().find((r) => r.id === req.params.id);
    if (!rt) throw new ScimError(404, `Resource type ${req.params.id} not found.`);
    return sendScim(reply, 200, rt);
  });

  const attr = (name: string, type: string, extra: Record<string, unknown> = {}) => ({
    name,
    type,
    multiValued: false,
    required: false,
    caseExact: false,
    mutability: "readWrite",
    returned: "default",
    uniqueness: "none",
    ...extra,
  });
  const schemas = () => [
    {
      schemas: [SCHEMA_SCHEMA],
      id: SCHEMA_USER,
      name: "User",
      description: "Organisation member",
      attributes: [
        attr("userName", "string", { required: true, uniqueness: "server", description: "Email address; the login name." }),
        attr("externalId", "string", { description: "Identity-provider id for the user." }),
        attr("displayName", "string"),
        attr("name", "complex", {
          subAttributes: [attr("givenName", "string"), attr("familyName", "string"), attr("formatted", "string")],
        }),
        attr("emails", "complex", {
          multiValued: true,
          subAttributes: [attr("value", "string"), attr("type", "string"), attr("primary", "boolean")],
        }),
        attr("active", "boolean", { description: "false deprovisions the member per the organisation's deprovision action." }),
        attr("roles", "complex", { multiValued: true, mutability: "readOnly", subAttributes: [attr("value", "string")] }),
        attr("groups", "complex", { multiValued: true, mutability: "readOnly", subAttributes: [attr("value", "string"), attr("display", "string")] }),
      ],
      meta: { resourceType: "Schema", location: `${scimBase()}/Schemas/${SCHEMA_USER}` },
    },
    {
      schemas: [SCHEMA_SCHEMA],
      id: SCHEMA_GROUP,
      name: "Group",
      description: "Group; owner/admin/member names map to roles",
      attributes: [
        attr("displayName", "string", { required: true, uniqueness: "server" }),
        attr("externalId", "string"),
        attr("members", "complex", { multiValued: true, subAttributes: [attr("value", "string"), attr("display", "string")] }),
      ],
      meta: { resourceType: "Schema", location: `${scimBase()}/Schemas/${SCHEMA_GROUP}` },
    },
  ];
  app.get("/Schemas", { config: { rateLimit: SCIM_RATE } }, async (_req, reply) => sendScim(reply, 200, listResponse(2, 1, schemas())));
  app.get<{ Params: { id: string } }>("/Schemas/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const s = schemas().find((x) => x.id === req.params.id);
    if (!s) throw new ScimError(404, `Schema ${req.params.id} not found.`);
    return sendScim(reply, 200, s);
  });

  // ---------------- Users ----------------
  app.get<{ Querystring: Record<string, string> }>("/Users", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const { orgId } = req.scim!;
    const f = parseEqFilter(req.query.filter, ["username", "externalid", "emails", "emails.value", "id"]);
    const paging = parsePaging(req.query);
    const where: Record<string, unknown> = { orgId };
    if (f) {
      if (f.attr === "id") where.id = f.value;
      else if (f.attr === "externalid") where.user = { scimExternalId: f.value };
      else where.user = { email: f.value.trim().toLowerCase().normalize("NFC") };
    }
    const [total, rows] = await Promise.all([
      db.membership.count({ where }),
      db.membership.findMany({ where, orderBy: [{ createdAt: "asc" }, { id: "asc" }], skip: paging.skip, take: paging.take, select: membershipSelect }),
    ]);
    return sendScim(reply, 200, listResponse(total, paging.startIndex, rows.map(serializeUser)));
  });

  app.get<{ Params: { id: string } }>("/Users/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const m = await findMembership(req.scim!.orgId, req.params.id);
    return sendScim(reply, 200, serializeUser(m));
  });

  app.post("/Users", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const { orgId, defaultRole, plan } = req.scim!;
    const parsed = userBodySchema.safeParse(req.body);
    if (!parsed.success) throw new ScimError(400, "User body is malformed.", "invalidSyntax");
    const body = parsed.data;
    const email = emailFromBody(body);
    if (!email) throw new ScimError(400, "userName (an email address) is required.", "invalidValue");
    const changes = changesFromBody(body);

    const existing = await db.user.findUnique({
      where: { email },
      select: { id: true, displayName: true, scimExternalId: true, memberships: { where: { orgId }, select: { id: true } } },
    });
    if (existing && existing.memberships.length > 0) {
      throw new ScimError(409, `A user with userName ${email} already exists in this organisation.`, "uniqueness");
    }

    // Seat limit (members + pending invites) — same count the console
    // shows and POST /members/invites enforces.
    const usage = await planUsage(orgId);
    const cap = limitsFor(plan).members;
    if (cap !== null && usage.members + 1 > cap) {
      const lifts = planThatLifts("members", usage.members + 1);
      throw new ScimError(
        402,
        `The ${plan} plan allows ${cap} members (including pending invites); this workspace already has ${usage.members}.` +
          (lifts ? ` Upgrade to the ${lifts} plan to add more.` : ""),
      );
    }

    const displayName = resolveDisplayName(existing?.displayName ?? null, changes) ?? existing?.displayName ?? null;
    const active = changes.active ?? true;
    const membershipId = await db.$transaction(async (tx) => {
      let userId: string;
      if (existing) {
        userId = existing.id;
        await tx.user.update({
          where: { id: userId },
          data: {
            ...(changes.externalId !== undefined ? { scimExternalId: changes.externalId } : {}),
            ...(displayName !== existing.displayName ? { displayName } : {}),
          },
        });
      } else {
        const u = await tx.user.create({
          data: {
            email,
            // Nobody knows this password; the user signs in through the
            // IdP (SAML/OIDC) or runs the password-reset flow once.
            passwordHash: await hashPassword(randomToken(32) + randomToken(32)),
            displayName,
            scimExternalId: changes.externalId ?? null,
            // The IdP asserted this mailbox — same trust SAML JIT gets.
            emailVerifiedAt: new Date(),
          },
          select: { id: true },
        });
        userId = u.id;
      }
      const m = await tx.membership.create({ data: { userId, orgId, role: defaultRole, active }, select: { id: true } });
      return m.id;
    });
    const created = await findMembership(orgId, membershipId);
    writeAudit(
      {
        orgId,
        event: "scim.user.created",
        ...scimActor(req),
        target: email,
        metadata: { membershipId, userId: created.userId, role: created.role, active, existingAccount: !!existing, externalId: changes.externalId ?? null },
        req,
      },
      req.log,
    );
    return sendScim(reply, 201, serializeUser(created), `${scimBase()}/Users/${membershipId}`);
  });

  app.put<{ Params: { id: string } }>("/Users/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const m = await findMembership(req.scim!.orgId, req.params.id);
    const parsed = userBodySchema.safeParse(req.body);
    if (!parsed.success) throw new ScimError(400, "User body is malformed.", "invalidSyntax");
    const changes = changesFromBody(parsed.data);
    const result = await applyUserChanges(req, m, changes);
    if (result.removed || !result.membership) return reply.code(204).send();
    return sendScim(reply, 200, serializeUser(result.membership));
  });

  app.patch<{ Params: { id: string } }>("/Users/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const m = await findMembership(req.scim!.orgId, req.params.id);
    const ops = parsePatch(req.body);
    const changes = userChangesFromPatch(ops);
    const result = await applyUserChanges(req, m, changes);
    if (result.removed || !result.membership) return reply.code(204).send();
    return sendScim(reply, 200, serializeUser(result.membership));
  });

  app.delete<{ Params: { id: string } }>("/Users/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const m = await findMembership(req.scim!.orgId, req.params.id);
    const action = req.scim!.deprovisionAction;
    if (action === "deactivate" && !m.active) return reply.code(204).send();
    await deprovision(req, m, action);
    return reply.code(204).send();
  });

  // ---------------- Groups ----------------
  const groupBodySchema = z
    .object({
      schemas: z.array(z.string()).optional(),
      displayName: z.string().trim().min(1).max(200),
      externalId: z.string().max(256).nullish(),
      members: z.array(z.unknown()).optional(),
    })
    .loose();

  app.get<{ Querystring: Record<string, string> }>("/Groups", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const { orgId } = req.scim!;
    const f = parseEqFilter(req.query.filter, ["displayname", "externalid", "id"]);
    const paging = parsePaging(req.query);
    const where: Record<string, unknown> = { orgId };
    if (f) {
      if (f.attr === "id") where.id = f.value;
      else if (f.attr === "externalid") where.externalId = f.value;
      else where.displayName = { equals: f.value, mode: "insensitive" };
    }
    const [total, rows] = await Promise.all([
      db.scimGroup.count({ where }),
      db.scimGroup.findMany({ where, orderBy: [{ createdAt: "asc" }, { id: "asc" }], skip: paging.skip, take: paging.take, select: groupSelect }),
    ]);
    return sendScim(reply, 200, listResponse(total, paging.startIndex, rows.map(serializeGroup)));
  });

  app.get<{ Params: { id: string } }>("/Groups/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const g = await findGroup(req.scim!.orgId, req.params.id);
    return sendScim(reply, 200, serializeGroup(g));
  });

  app.post("/Groups", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const { orgId, defaultRole } = req.scim!;
    const parsed = groupBodySchema.safeParse(req.body);
    if (!parsed.success) throw new ScimError(400, "Group body is malformed (displayName is required).", "invalidSyntax");
    const userIds = await resolveMemberValues(orgId, parsed.data.members ?? []);
    const role = roleForGroupName(parsed.data.displayName);
    let groupId: string;
    try {
      const g = await db.scimGroup.create({
        data: {
          orgId,
          displayName: parsed.data.displayName,
          externalId: parsed.data.externalId ?? null,
          role,
          members: { create: [...new Set(userIds)].map((userId) => ({ userId })) },
        },
        select: { id: true },
      });
      groupId = g.id;
    } catch (err) {
      if ((err as { code?: string }).code === "P2002") throw new ScimError(409, `A group named ${parsed.data.displayName} already exists.`, "uniqueness");
      throw err;
    }
    writeAudit(
      { orgId, event: "scim.group.created", ...scimActor(req), target: parsed.data.displayName, metadata: { groupId, role, members: userIds.length }, req },
      req.log,
    );
    if (role) await recomputeRoles(req, orgId, userIds, defaultRole, `group ${parsed.data.displayName} created`);
    const g = await findGroup(orgId, groupId);
    return sendScim(reply, 201, serializeGroup(g), `${scimBase()}/Groups/${groupId}`);
  });

  async function replaceGroup(req: FastifyRequest, g: GroupRow, displayName: string | undefined, externalId: string | null | undefined, userIds: string[] | undefined) {
    const { orgId, defaultRole } = req.scim!;
    const before = g.members.map((m) => m.userId);
    const newName = displayName ?? g.displayName;
    const newRole = roleForGroupName(newName);
    const after = userIds ?? before;
    try {
      await db.$transaction(async (tx) => {
        await tx.scimGroup.update({
          where: { id: g.id },
          data: { displayName: newName, role: newRole, ...(externalId !== undefined ? { externalId } : {}) },
        });
        if (userIds) {
          await tx.scimGroupMember.deleteMany({ where: { groupId: g.id, userId: { notIn: after } } });
          const toAdd = after.filter((u) => !before.includes(u));
          if (toAdd.length) await tx.scimGroupMember.createMany({ data: [...new Set(toAdd)].map((userId) => ({ groupId: g.id, userId })), skipDuplicates: true });
        }
      });
    } catch (err) {
      if ((err as { code?: string }).code === "P2002") throw new ScimError(409, `A group named ${newName} already exists.`, "uniqueness");
      throw err;
    }
    writeAudit(
      {
        orgId,
        event: "scim.group.updated",
        ...scimActor(req),
        target: newName,
        metadata: { groupId: g.id, previousName: g.displayName, role: newRole, members: after.length },
        req,
      },
      req.log,
    );
    // Everyone whose mapped-group situation may have changed.
    const affected = new Set<string>();
    if (g.role !== newRole) for (const u of [...before, ...after]) affected.add(u);
    if (newRole || g.role) {
      for (const u of before) if (!after.includes(u)) affected.add(u);
      for (const u of after) if (!before.includes(u)) affected.add(u);
    }
    await recomputeRoles(req, orgId, [...affected], defaultRole, `group ${newName} updated`);
  }

  app.put<{ Params: { id: string } }>("/Groups/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const { orgId } = req.scim!;
    const g = await findGroup(orgId, req.params.id);
    const parsed = groupBodySchema.safeParse(req.body);
    if (!parsed.success) throw new ScimError(400, "Group body is malformed (displayName is required).", "invalidSyntax");
    const userIds = parsed.data.members === undefined ? [] : await resolveMemberValues(orgId, parsed.data.members);
    await replaceGroup(req, g, parsed.data.displayName, parsed.data.externalId === undefined ? undefined : parsed.data.externalId ?? null, userIds);
    return sendScim(reply, 200, serializeGroup(await findGroup(orgId, g.id)));
  });

  app.patch<{ Params: { id: string } }>("/Groups/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const { orgId } = req.scim!;
    const g = await findGroup(orgId, req.params.id);
    const ops = parsePatch(req.body);
    let displayName: string | undefined;
    let externalId: string | null | undefined;
    let members = g.members.map((m) => m.userId);
    for (const op of ops) {
      const path = (op.path ?? "").trim();
      const lower = path.toLowerCase();
      if (!path) {
        if (op.op === "remove") throw new ScimError(400, "remove requires a path.", "noTarget");
        if (!op.value || typeof op.value !== "object" || Array.isArray(op.value)) throw new ScimError(400, "A PATCH op without a path needs an object value.", "invalidValue");
        const v = op.value as Record<string, unknown>;
        if (typeof v.displayName === "string") displayName = v.displayName.trim();
        if ("externalId" in v) externalId = typeof v.externalId === "string" ? v.externalId : null;
        if (v.members !== undefined) {
          const ids = await resolveMemberValues(orgId, v.members);
          members = op.op === "replace" ? ids : [...members, ...ids];
        }
        continue;
      }
      if (lower === "displayname") {
        if (op.op === "remove" || typeof op.value !== "string" || !op.value.trim()) throw new ScimError(400, "displayName must be a non-empty string.", "invalidValue");
        displayName = op.value.trim();
      } else if (lower === "externalid") {
        externalId = op.op === "remove" ? null : typeof op.value === "string" ? op.value : null;
      } else if (lower === "members") {
        if (op.op === "remove") {
          if (op.value === undefined) members = [];
          else {
            const drop = new Set(await resolveMemberValues(orgId, op.value));
            members = members.filter((u) => !drop.has(u));
          }
        } else {
          const ids = await resolveMemberValues(orgId, op.value);
          members = op.op === "replace" ? ids : [...members, ...ids];
        }
      } else if (lower.startsWith("members[")) {
        const m = /^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$/i.exec(path);
        if (!m) throw new ScimError(400, `Unsupported members filter path "${path}".`, "invalidPath");
        const [userId] = await resolveMemberValues(orgId, [m[1]]);
        if (op.op === "remove") members = members.filter((u) => u !== userId);
        else if (userId) members = [...members, userId];
      } else {
        throw new ScimError(400, `Unknown or unsupported attribute path "${path}".`, "invalidPath");
      }
    }
    await replaceGroup(req, g, displayName, externalId, [...new Set(members)]);
    return sendScim(reply, 200, serializeGroup(await findGroup(orgId, g.id)));
  });

  app.delete<{ Params: { id: string } }>("/Groups/:id", { config: { rateLimit: SCIM_RATE } }, async (req, reply) => {
    const { orgId, defaultRole } = req.scim!;
    const g = await findGroup(orgId, req.params.id);
    const userIds = g.members.map((m) => m.userId);
    await db.scimGroup.delete({ where: { id: g.id } });
    writeAudit(
      { orgId, event: "scim.group.deleted", ...scimActor(req), target: g.displayName, metadata: { groupId: g.id, role: g.role, members: userIds.length }, req },
      req.log,
    );
    if (g.role) await recomputeRoles(req, orgId, userIds, defaultRole, `group ${g.displayName} deleted`);
    return reply.code(204).send();
  });
}

// -------------------------------------------------------------------
// Plugin: /api/v1/scim (owner-only management, cookie/API-key session)
// -------------------------------------------------------------------

export async function scimAdminRoutes(app: FastifyInstance): Promise<void> {
  const settingsOf = async (orgId: string) => {
    const org = await db.org.findUnique({
      where: { id: orgId },
      select: { scimEnabled: true, scimDefaultRole: true, scimDeprovisionAction: true, plan: true },
    });
    if (!org) return null;
    return {
      enabled: org.scimEnabled,
      defaultRole: org.scimDefaultRole,
      deprovisionAction: org.scimDeprovisionAction,
      baseUrl: scimBase(),
      plan: org.plan,
      planAllows: limitsFor(org.plan).scim,
      groupMapping: { owner: "owner", admin: "admin", member: "member" },
    };
  };

  const requireOwner = (req: FastifyRequest, reply: FastifyReply) => {
    const claims = requireSession(req, reply);
    if (!claims) return null;
    if (claims.membershipRole !== "owner") {
      reply.code(403).send({ error: "forbidden" });
      return null;
    }
    return claims;
  };

  app.get("/settings", async (req, reply) => {
    const claims = requireOwner(req, reply);
    if (!claims) return;
    const settings = await settingsOf(claims.orgId);
    if (!settings) return reply.code(404).send({ error: "not_found" });
    return reply.send({ settings });
  });

  app.patch("/settings", async (req, reply) => {
    const claims = requireOwner(req, reply);
    if (!claims) return;
    const body = z
      .object({
        enabled: z.boolean().optional(),
        defaultRole: z.enum(["member", "admin"]).optional(),
        deprovisionAction: z.enum(["deactivate", "remove"]).optional(),
      })
      .strict()
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const current = await db.org.findUnique({
      where: { id: claims.orgId },
      select: { plan: true, scimEnabled: true, scimDefaultRole: true, scimDeprovisionAction: true },
    });
    if (!current) return reply.code(404).send({ error: "not_found" });
    if (body.data.enabled === true && !current.scimEnabled && refuseIfFeatureMissing(req, reply, current.plan, "scim")) return;
    const updated = await db.org.update({
      where: { id: claims.orgId },
      data: {
        ...(body.data.enabled !== undefined ? { scimEnabled: body.data.enabled } : {}),
        ...(body.data.defaultRole !== undefined ? { scimDefaultRole: body.data.defaultRole } : {}),
        ...(body.data.deprovisionAction !== undefined ? { scimDeprovisionAction: body.data.deprovisionAction } : {}),
      },
      select: { scimEnabled: true, scimDefaultRole: true, scimDeprovisionAction: true },
    });
    writeAudit(
      {
        orgId: claims.orgId,
        event: "scim.settings_updated",
        ...(await resolveActor(claims.sub)),
        target: claims.orgId,
        metadata: {
          enabled: updated.scimEnabled,
          defaultRole: updated.scimDefaultRole,
          deprovisionAction: updated.scimDeprovisionAction,
          previous: { enabled: current.scimEnabled, defaultRole: current.scimDefaultRole, deprovisionAction: current.scimDeprovisionAction },
        },
        req,
      },
      req.log,
    );
    return reply.send({ settings: await settingsOf(claims.orgId) });
  });

  app.get("/tokens", async (req, reply) => {
    const claims = requireOwner(req, reply);
    if (!claims) return;
    const rows = await db.scimToken.findMany({
      where: { orgId: claims.orgId, revokedAt: null },
      orderBy: { createdAt: "desc" },
      select: { id: true, name: true, tokenHint: true, createdByEmail: true, lastUsedAt: true, createdAt: true },
    });
    return reply.send({
      tokens: rows.map((r) => ({
        id: r.id,
        name: r.name,
        hint: SCIM_TOKEN_PREFIX + r.tokenHint + "…",
        createdByEmail: r.createdByEmail,
        lastUsedAt: r.lastUsedAt,
        createdAt: r.createdAt,
      })),
    });
  });

  app.post("/tokens", async (req, reply) => {
    const claims = requireOwner(req, reply);
    if (!claims) return;
    const body = z.object({ name: z.string().max(80).trim().min(1) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const org = await db.org.findUnique({ where: { id: claims.orgId }, select: { plan: true } });
    if (!org) return reply.code(404).send({ error: "not_found" });
    if (refuseIfFeatureMissing(req, reply, org.plan, "scim")) return;
    const random = randomToken(24); // 32 base64url chars
    const plaintext = SCIM_TOKEN_PREFIX + random;
    const actor = await resolveActor(claims.sub);
    const token = await db.scimToken.create({
      data: {
        orgId: claims.orgId,
        name: body.data.name,
        tokenHash: await hashPassword(plaintext),
        tokenHint: random.slice(0, 8),
        createdById: claims.sub.startsWith("apikey:") ? null : claims.sub,
        createdByEmail: actor.actorEmail ?? null,
      },
      select: { id: true, name: true, tokenHint: true, createdAt: true, createdByEmail: true },
    });
    writeAudit(
      { orgId: claims.orgId, event: "scim.token_created", ...actor, target: token.name, metadata: { scimTokenId: token.id }, req },
      req.log,
    );
    return reply.code(201).send({
      token: {
        id: token.id,
        name: token.name,
        hint: SCIM_TOKEN_PREFIX + token.tokenHint + "…",
        createdByEmail: token.createdByEmail,
        createdAt: token.createdAt,
        lastUsedAt: null,
      },
      // Shown once; the IdP admin pastes it into the provisioning app.
      plaintextToken: plaintext,
    });
  });

  app.delete<{ Params: { id: string } }>("/tokens/:id", async (req, reply) => {
    const claims = requireOwner(req, reply);
    if (!claims) return;
    const existing = await db.scimToken.findFirst({ where: { id: req.params.id, orgId: claims.orgId, revokedAt: null } });
    if (!existing) return reply.code(404).send({ error: "not_found" });
    await db.scimToken.update({ where: { id: existing.id }, data: { revokedAt: new Date() } });
    writeAudit(
      { orgId: claims.orgId, event: "scim.token_revoked", ...(await resolveActor(claims.sub)), target: existing.name, metadata: { scimTokenId: existing.id }, req },
      req.log,
    );
    return reply.code(204).send();
  });
}
