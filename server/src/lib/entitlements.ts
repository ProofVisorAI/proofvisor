/**
 * Plan entitlements.
 *
 * Every organisation has a `plan` (free | team | enterprise). The plan
 * decides how many deployments, members and webhooks the org may
 * create, the longest session-retention window it may configure, and
 * whether SAML and SCIM are available. Limits are enforced at the
 * creation points only — an org that already exceeds a limit (because
 * the limits changed, or because it was downgraded) keeps everything
 * it has; it simply cannot add more until it upgrades.
 *
 * Defaults:
 *
 *   plan        deployments  members  retention max  webhooks  SCIM  SAML
 *   free        2            3        30 days        1         no    no
 *   team        10           25       365 days       10        yes   yes
 *   enterprise  unlimited    unlimited  unlimited    unlimited yes   yes
 *
 * Operators override any cell without a code change through env vars
 * named PLAN_<PLAN>_<LIMIT>, e.g. PLAN_FREE_WEBHOOKS=3,
 * PLAN_TEAM_RETENTION_DAYS=730, PLAN_FREE_SAML=true. A numeric limit of
 * 0 (or the word "unlimited") removes the cap. Booleans accept
 * true/false/1/0.
 *
 * Enforcement is opt-in: nothing is refused unless the operator sets
 * PLAN_LIMITS_ENFORCED=true (which needs Stripe configured). Without
 * it, every workspace keeps every feature and GET /api/v1/billing
 * reports `enforced: false`.
 *
 * Rejections are RFC 7807 problem+json with status 402 and
 * errorCode `plan_limit_reached`; the body names the limit that was
 * hit, the current plan, and the cheapest plan that lifts it, so the
 * console can render an upgrade prompt without guessing.
 */

import type { FastifyReply, FastifyRequest } from "fastify";
import { db } from "../db.js";
import { env } from "../env.js";

/** True when plan limits are enforced on this instance. */
export function limitsEnforced(): boolean {
  return env.PLAN_LIMITS_ENFORCED;
}

export type Plan = "free" | "team" | "enterprise";
export const PLANS: readonly Plan[] = ["free", "team", "enterprise"] as const;

export type LimitName = "deployments" | "members" | "retentionDays" | "webhooks";
export type FeatureName = "scim" | "saml";

export interface PlanLimits {
  /** null = unlimited */
  deployments: number | null;
  members: number | null;
  retentionDays: number | null;
  webhooks: number | null;
  scim: boolean;
  saml: boolean;
}

const DEFAULTS: Record<Plan, PlanLimits> = {
  free: { deployments: 2, members: 3, retentionDays: 30, webhooks: 1, scim: false, saml: false },
  team: { deployments: 10, members: 25, retentionDays: 365, webhooks: 10, scim: true, saml: true },
  enterprise: { deployments: null, members: null, retentionDays: null, webhooks: null, scim: true, saml: true },
};

const ENV_SUFFIX: Record<LimitName | FeatureName, string> = {
  deployments: "DEPLOYMENTS",
  members: "MEMBERS",
  retentionDays: "RETENTION_DAYS",
  webhooks: "WEBHOOKS",
  scim: "SCIM",
  saml: "SAML",
};

function readNumber(name: string, fallback: number | null): number | null {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const v = raw.trim().toLowerCase();
  if (v === "unlimited" || v === "0") return null;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`${name} must be a non-negative integer or "unlimited" (got "${raw}")`);
  }
  return n;
}

function readBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const v = raw.trim().toLowerCase();
  if (v === "true" || v === "1" || v === "yes") return true;
  if (v === "false" || v === "0" || v === "no") return false;
  throw new Error(`${name} must be true or false (got "${raw}")`);
}

function loadLimits(): Record<Plan, PlanLimits> {
  const out = {} as Record<Plan, PlanLimits>;
  for (const plan of PLANS) {
    const prefix = `PLAN_${plan.toUpperCase()}_`;
    const d = DEFAULTS[plan];
    out[plan] = {
      deployments: readNumber(prefix + ENV_SUFFIX.deployments, d.deployments),
      members: readNumber(prefix + ENV_SUFFIX.members, d.members),
      retentionDays: readNumber(prefix + ENV_SUFFIX.retentionDays, d.retentionDays),
      webhooks: readNumber(prefix + ENV_SUFFIX.webhooks, d.webhooks),
      scim: readBool(prefix + ENV_SUFFIX.scim, d.scim),
      saml: readBool(prefix + ENV_SUFFIX.saml, d.saml),
    };
  }
  return out;
}

// Parsed once at boot. A typo in an override crashes the process at
// import time with a clear message rather than silently applying a
// default (same posture as env.ts).
const LIMITS = loadLimits();

export function normalizePlan(raw: string | null | undefined): Plan {
  return raw === "team" || raw === "enterprise" ? raw : "free";
}

export function limitsFor(plan: string | null | undefined): PlanLimits {
  return LIMITS[normalizePlan(plan)];
}

export function allLimits(): Record<Plan, PlanLimits> {
  return LIMITS;
}

/** The cheapest plan (in rank order) whose limit covers `needed`. */
export function planThatLifts(limit: LimitName, needed: number): Plan | null {
  for (const plan of PLANS) {
    const cap = LIMITS[plan][limit];
    if (cap === null || cap >= needed) return plan;
  }
  return null;
}

export function planThatEnables(feature: FeatureName): Plan | null {
  for (const plan of PLANS) if (LIMITS[plan][feature]) return plan;
  return null;
}

export interface PlanUsage {
  deployments: number;
  members: number;
  webhooks: number;
  retentionDays: number;
  samlConfigs: number;
  scimEnabled: boolean;
}

/** Live counts the console shows against the limits. */
export async function planUsage(orgId: string): Promise<PlanUsage> {
  const [deployments, members, pendingInvites, webhooks, samlConfigs, org] = await Promise.all([
    db.deployment.count({ where: { orgId } }),
    db.membership.count({ where: { orgId, active: true } }),
    db.invite.count({
      where: { orgId, acceptedAt: null, revokedAt: null, expiresAt: { gt: new Date() } },
    }),
    db.webhookEndpoint.count({ where: { orgId } }),
    db.samlConfig.count({ where: { orgId } }),
    db.org.findUnique({
      where: { id: orgId },
      select: { sessionRetentionDays: true, scimEnabled: true },
    }),
  ]);
  return {
    deployments,
    // A pending invite reserves a seat: otherwise an org could invite
    // fifty people on a three-seat plan and only be stopped when they
    // accept, which is the wrong moment to surprise anyone.
    members: members + pendingInvites,
    webhooks,
    retentionDays: org?.sessionRetentionDays ?? 0,
    samlConfigs,
    scimEnabled: org?.scimEnabled ?? false,
  };
}

const LIMIT_LABEL: Record<LimitName, string> = {
  deployments: "deployments",
  members: "members (including pending invites)",
  retentionDays: "days of session retention",
  webhooks: "webhook endpoints",
};

export interface PlanLimitProblem {
  type: "about:blank";
  title: "Payment Required";
  status: 402;
  detail: string;
  instance: string;
  errorCode: "plan_limit_reached";
  requestId: string;
  limit: LimitName | FeatureName;
  plan: Plan;
  max: number | null;
  current?: number;
  upgradeTo: Plan | null;
}

function sendProblem(req: FastifyRequest, reply: FastifyReply, problem: PlanLimitProblem): void {
  reply.header("X-Request-Id", String(req.id));
  reply.code(402).type("application/problem+json").send(problem);
}

/**
 * Refuse a creation that would exceed a numeric limit.
 * `current` is the count before the creation; `wanted` (default 1) is
 * how many the request adds. Returns true when the request was
 * refused (the caller must `return`).
 */
export function refuseIfOverLimit(
  req: FastifyRequest,
  reply: FastifyReply,
  plan: string | null | undefined,
  limit: LimitName,
  current: number,
  wanted = 1,
): boolean {
  if (!limitsEnforced()) return false;
  const p = normalizePlan(plan);
  const cap = LIMITS[p][limit];
  if (cap === null || current + wanted <= cap) return false;
  const upgradeTo = planThatLifts(limit, current + wanted);
  const label = LIMIT_LABEL[limit];
  const detail =
    `The ${p} plan allows ${cap} ${label}; this workspace already has ${current}. ` +
    (upgradeTo ? `Upgrade to the ${upgradeTo} plan to add more.` : "No plan allows more.");
  sendProblem(req, reply, {
    type: "about:blank",
    title: "Payment Required",
    status: 402,
    detail,
    instance: req.url,
    errorCode: "plan_limit_reached",
    requestId: String(req.id),
    limit,
    plan: p,
    max: cap,
    current,
    upgradeTo,
  });
  return true;
}

/**
 * Refuse a retention value longer than the plan allows. `days === 0`
 * means "keep forever", which only an unlimited plan may set.
 */
export function refuseIfRetentionTooLong(
  req: FastifyRequest,
  reply: FastifyReply,
  plan: string | null | undefined,
  days: number,
): boolean {
  if (!limitsEnforced()) return false;
  const p = normalizePlan(plan);
  const cap = LIMITS[p].retentionDays;
  if (cap === null) return false;
  if (days !== 0 && days <= cap) return false;
  const needed = days === 0 ? Number.POSITIVE_INFINITY : days;
  let upgradeTo: Plan | null = null;
  for (const candidate of PLANS) {
    const c = LIMITS[candidate].retentionDays;
    if (c === null || c >= needed) { upgradeTo = candidate; break; }
  }
  const asked = days === 0 ? "keep forever" : `${days} days`;
  const detail =
    `The ${p} plan keeps sessions for at most ${cap} days; you asked for ${asked}. ` +
    (upgradeTo ? `Upgrade to the ${upgradeTo} plan for a longer window.` : "No plan allows that window.");
  sendProblem(req, reply, {
    type: "about:blank",
    title: "Payment Required",
    status: 402,
    detail,
    instance: req.url,
    errorCode: "plan_limit_reached",
    requestId: String(req.id),
    limit: "retentionDays",
    plan: p,
    max: cap,
    current: days,
    upgradeTo,
  });
  return true;
}

/** Refuse a feature (SAML, SCIM) the plan does not include. */
export function refuseIfFeatureMissing(
  req: FastifyRequest,
  reply: FastifyReply,
  plan: string | null | undefined,
  feature: FeatureName,
): boolean {
  if (!limitsEnforced()) return false;
  const p = normalizePlan(plan);
  if (LIMITS[p][feature]) return false;
  const upgradeTo = planThatEnables(feature);
  const name = feature === "scim" ? "SCIM provisioning" : "SAML single sign-on";
  const detail =
    `${name} is not included in the ${p} plan. ` +
    (upgradeTo ? `Upgrade to the ${upgradeTo} plan to enable it.` : "No plan includes it.");
  sendProblem(req, reply, {
    type: "about:blank",
    title: "Payment Required",
    status: 402,
    detail,
    instance: req.url,
    errorCode: "plan_limit_reached",
    requestId: String(req.id),
    limit: feature,
    plan: p,
    max: null,
    upgradeTo,
  });
  return true;
}

/** Plan of the caller's org — one indexed read. */
export async function orgPlan(orgId: string): Promise<Plan> {
  const org = await db.org.findUnique({ where: { id: orgId }, select: { plan: true } });
  return normalizePlan(org?.plan);
}
