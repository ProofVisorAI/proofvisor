/**
 * Policy push: the bundle daemons pull, the spec shapes they enforce,
 * and the enforcement roll-up the console shows.
 *
 * Wire contract (GET /api/v1/ingest/policies):
 *
 *   {
 *     "version": 1,
 *     "orgId": "…", "deploymentId": "…",
 *     "generatedAt": "<ISO>",
 *     "etag": "<sha256 hex of the canonical JSON of `policies`>",
 *     "policies": [
 *       { "id", "name", "kind", "scope", "enabled": true,
 *         "updatedAt": "<ISO>", "spec": <object|null>, "body": "<string>" }
 *     ]
 *   }
 *
 * `policies` holds only the org's ENABLED policies, sorted by name.
 * `spec` is the parsed JSON object of `body` for the daemon-enforceable
 * kinds (budget, allowlist, rate, schema) and null otherwise. The etag
 * depends on the policies array alone — not on generatedAt or on the
 * deployment id — so every daemon of an org sees the same etag for the
 * same set of rules, and a daemon can send it back as If-None-Match.
 *
 * Canonical JSON here is RFC 8785-style: object keys sorted, no
 * whitespace, JSON.stringify number/string forms. The daemon must not
 * recompute the etag from its own serialization; it treats the value
 * as opaque and echoes it in policy-status.
 */

import { createHash } from "node:crypto";
import { z } from "zod";
import { db } from "../db.js";

export const ENFORCEABLE_KINDS = ["budget", "allowlist", "rate", "schema"] as const;
export type EnforceableKind = (typeof ENFORCEABLE_KINDS)[number];

export function isEnforceableKind(kind: string): kind is EnforceableKind {
  return (ENFORCEABLE_KINDS as readonly string[]).includes(kind);
}

// Tool names are identifiers the daemon matches against tool-call
// names: no whitespace, no control characters, bounded.
const toolName = z
  .string()
  .min(1)
  .max(80)
  .regex(/^[A-Za-z0-9_.:\/-]+$/, "tool names may only contain letters, digits, _ . : / -");

const nonNegInt = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const posInt = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);

const budgetSpec = z
  .object({
    max_total_tool_calls: nonNegInt.optional(),
    max_payout_usd_micros: nonNegInt.optional(),
    max_tokens: nonNegInt.optional(),
    per_tool_max_calls: z.record(toolName, nonNegInt).optional(),
  })
  .strict()
  .refine(
    (v) =>
      v.max_total_tool_calls !== undefined ||
      v.max_payout_usd_micros !== undefined ||
      v.max_tokens !== undefined ||
      (v.per_tool_max_calls !== undefined && Object.keys(v.per_tool_max_calls).length > 0),
    "a budget needs at least one limit (max_total_tool_calls, max_payout_usd_micros, max_tokens or per_tool_max_calls)",
  );

const allowlistSpec = z
  .object({
    allow_only: z.array(toolName).max(500).optional(),
    deny_tools: z.array(toolName).max(500).optional(),
  })
  .strict()
  .refine(
    (v) => (v.allow_only && v.allow_only.length > 0) || (v.deny_tools && v.deny_tools.length > 0),
    "an allowlist needs allow_only and/or deny_tools with at least one tool name",
  );

const rateSpec = z
  .object({
    max_tokens_per_window: posInt,
    window_s: posInt.max(30 * 24 * 3600),
  })
  .strict();

const schemaSpec = z
  .object({
    tool: toolName,
    json_schema: z
      .record(z.string(), z.unknown())
      .refine((v) => !Array.isArray(v), "json_schema must be a JSON Schema object"),
  })
  .strict();

const SPEC_SCHEMAS: Record<EnforceableKind, z.ZodTypeAny> = {
  budget: budgetSpec,
  allowlist: allowlistSpec,
  rate: rateSpec,
  schema: schemaSpec,
};

export type SpecValidation =
  | { ok: true; spec: Record<string, unknown> | null }
  | { ok: false; detail: string };

/**
 * Scope → tool-name pattern. Policies of kind allowlist/schema name
 * tools; the policy's scope ("tool.*", "tool.create_payment",
 * "tool.payments.*") must cover every tool the spec names, otherwise the
 * rule can never fire. Returns null for scopes that do not name tools.
 */
function toolPatternFromScope(scope: string): RegExp | null {
  const m = /^tool(?:\.(.*))?$/.exec(scope.trim());
  if (!m) return null;
  const pattern = m[1] === undefined || m[1] === "" ? "*" : m[1];
  const re = pattern
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp("^" + re + "$");
}

function firstIssue(err: z.ZodError): string {
  const issue = err.issues[0];
  if (!issue) return "invalid spec";
  const path = issue.path.length ? issue.path.join(".") + ": " : "";
  return path + issue.message;
}

/**
 * Validate a policy body for its kind. Enforceable kinds must be a JSON
 * object matching the kind's spec shape; the other kinds (guardrail,
 * transform, anything custom) are free text and always pass with
 * spec=null. The returned `detail` is human-readable and is surfaced
 * to the console as the 400 invalid_input explanation.
 */
const REF_KEYWORDS = new Set(["$ref", "$dynamicRef", "$recursiveRef"]);

/** Meta-schemas the daemon has built in (crates/pv-sandbox/src/pushed.rs tests the same list). */
const BUILT_IN_META_SCHEMAS = new Set([
  "https://json-schema.org/draft/2020-12/schema",
  "https://json-schema.org/draft/2019-09/schema",
  "http://json-schema.org/draft-07/schema#",
  "http://json-schema.org/draft-07/schema",
  "http://json-schema.org/draft-06/schema#",
  "http://json-schema.org/draft-04/schema#",
]);

/** The first reference value that does not stay inside the document. */
function findExternalRef(node: unknown, depth = 0): string | null {
  if (depth > 64 || node === null || typeof node !== "object") return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const hit = findExternalRef(item, depth + 1);
      if (hit !== null) return hit;
    }
    return null;
  }
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (REF_KEYWORDS.has(key) && typeof value === "string" && !value.startsWith("#")) return value.slice(0, 120);
    if (key === "$schema" && typeof value === "string" && !BUILT_IN_META_SCHEMAS.has(value)) return value.slice(0, 120);
    const hit = findExternalRef(value, depth + 1);
    if (hit !== null) return hit;
  }
  return null;
}

export function validatePolicySpec(kind: string, scope: string, body: string): SpecValidation {
  if (!isEnforceableKind(kind)) return { ok: true, spec: null };
  if (!body.trim()) {
    return { ok: false, detail: `a ${kind} policy needs a JSON spec in its body` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return { ok: false, detail: `body is not valid JSON (${(e as Error).message})` };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, detail: `a ${kind} spec must be a JSON object` };
  }
  const res = SPEC_SCHEMAS[kind].safeParse(parsed);
  if (!res.success) return { ok: false, detail: `${kind} spec: ${firstIssue(res.error)}` };
  const spec = res.data as Record<string, unknown>;

  // Daemons refuse to fetch external references in a pushed schema (they
  // would reach into the customer's network or read local files), so a
  // schema that needs one could never be enforced. Say so at write time.
  if (kind === "schema") {
    const external = findExternalRef(spec.json_schema);
    if (external !== null) {
      return {
        ok: false,
        detail: `schema spec: "${external}" points outside the schema; only references inside it (starting with #) are allowed`,
      };
    }
  }

  // Tool names must fall inside the policy's scope.
  const pattern = toolPatternFromScope(scope);
  const named: string[] = [];
  if (kind === "allowlist") {
    named.push(...((spec.allow_only as string[] | undefined) ?? []));
    named.push(...((spec.deny_tools as string[] | undefined) ?? []));
  } else if (kind === "schema") {
    named.push(spec.tool as string);
  } else if (kind === "budget" && spec.per_tool_max_calls) {
    named.push(...Object.keys(spec.per_tool_max_calls as Record<string, number>));
  }
  if (named.length > 0) {
    if (!pattern) {
      return {
        ok: false,
        detail: `${kind} spec names tools but the policy scope "${scope}" is not a tool scope (use tool.* or tool.<name>)`,
      };
    }
    const outside = named.find((t) => !pattern.test(t));
    if (outside) {
      return {
        ok: false,
        detail: `${kind} spec names tool "${outside}" which is outside the policy scope "${scope}"`,
      };
    }
  }
  return { ok: true, spec };
}

/** Parsed spec for display; null when the body is not a valid spec. */
export function parseSpecOrNull(kind: string, scope: string, body: string): Record<string, unknown> | null {
  const v = validatePolicySpec(kind, scope, body);
  return v.ok ? v.spec : null;
}

/** RFC 8785-style canonical JSON: sorted keys, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

export interface BundlePolicy {
  id: string;
  name: string;
  kind: string;
  scope: string;
  enabled: true;
  updatedAt: string;
  spec: Record<string, unknown> | null;
  body: string;
}

export interface PolicyBundle {
  version: 1;
  orgId: string;
  deploymentId: string;
  generatedAt: string;
  etag: string;
  policies: BundlePolicy[];
}

export function bundleEtag(policies: BundlePolicy[]): string {
  return createHash("sha256").update(canonicalJson(policies), "utf8").digest("hex");
}

/** Enabled policies of the org as bundle entries, sorted by name. */
export async function orgBundlePolicies(orgId: string): Promise<BundlePolicy[]> {
  const rows = await db.policy.findMany({
    where: { orgId, enabled: true },
    orderBy: { name: "asc" },
    select: { id: true, name: true, kind: true, scope: true, updatedAt: true, body: true },
  });
  // Prisma sorts by the database collation; pin a byte-order sort so
  // the etag is identical across databases and locales.
  rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return rows.map((p) => ({
    id: p.id,
    name: p.name,
    kind: p.kind,
    scope: p.scope,
    enabled: true as const,
    updatedAt: p.updatedAt.toISOString(),
    spec: parseSpecOrNull(p.kind, p.scope, p.body),
    body: p.body,
  }));
}

export async function buildPolicyBundle(orgId: string, deploymentId: string): Promise<PolicyBundle> {
  const policies = await orgBundlePolicies(orgId);
  return {
    version: 1,
    orgId,
    deploymentId,
    generatedAt: new Date().toISOString(),
    etag: bundleEtag(policies),
    policies,
  };
}

export async function currentOrgEtag(orgId: string): Promise<string> {
  return bundleEtag(await orgBundlePolicies(orgId));
}

export interface PolicyEnforcement {
  deployments: number;
  /** Daemons on the current bundle whose status lists THIS policy as applied. */
  applied: number;
  /** Daemons on the current bundle, whether or not they applied this policy. */
  current: number;
  stale: number;
  unsupported: number;
}

export interface OrgEnforcementSnapshot {
  etag: string;
  /** Non-demo deployments in the org. */
  deployments: number;
  applied: number;
  stale: number;
  /** policy id → number of current-bundle deployments reporting it applied */
  appliedByPolicy: Map<string, number>;
  /** policy id → number of deployments reporting it unsupported */
  unsupportedByPolicy: Map<string, number>;
  /** Per-deployment status, keyed by deployment id. */
  byDeployment: Map<
    string,
    { etag: string; appliedAt: Date; daemonVersion: string | null; applied: string[]; unsupported: Array<{ id: string; reason: string }> }
  >;
}

/**
 * One pass over the org's deployments and their policy-status rows.
 * Demo deployments never run a daemon, so they are left out of the
 * totals ("Enforced by 1 of 2 daemons" must not count the demo).
 */
export async function orgEnforcementSnapshot(orgId: string): Promise<OrgEnforcementSnapshot> {
  const [etag, deployments] = await Promise.all([
    currentOrgEtag(orgId),
    db.deployment.findMany({
      where: { orgId, isDemo: false },
      select: {
        id: true,
        policyStatus: {
          select: { etag: true, appliedAt: true, daemonVersion: true, applied: true, unsupported: true },
        },
      },
    }),
  ]);
  const snap: OrgEnforcementSnapshot = {
    etag,
    deployments: deployments.length,
    applied: 0,
    stale: 0,
    appliedByPolicy: new Map(),
    unsupportedByPolicy: new Map(),
    byDeployment: new Map(),
  };
  for (const d of deployments) {
    const s = d.policyStatus;
    if (!s) continue;
    const applied = Array.isArray(s.applied) ? (s.applied as unknown[]).filter((x): x is string => typeof x === "string") : [];
    const unsupported = Array.isArray(s.unsupported)
      ? (s.unsupported as unknown[])
          .filter((x): x is { id: string; reason: string } =>
            typeof x === "object" && x !== null && typeof (x as { id?: unknown }).id === "string",
          )
          .map((x) => ({ id: x.id, reason: typeof x.reason === "string" ? x.reason : "" }))
      : [];
    snap.byDeployment.set(d.id, {
      etag: s.etag,
      appliedAt: s.appliedAt,
      daemonVersion: s.daemonVersion,
      applied,
      unsupported,
    });
    if (s.etag === etag) {
      snap.applied += 1;
      // A daemon on the current bundle enforces only the policies it
      // lists; one it reports unsupported (or omits) is not enforcing it.
      for (const id of new Set(applied)) {
        snap.appliedByPolicy.set(id, (snap.appliedByPolicy.get(id) ?? 0) + 1);
      }
    } else snap.stale += 1;
    const seen = new Set<string>();
    for (const u of unsupported) {
      if (seen.has(u.id)) continue;
      seen.add(u.id);
      snap.unsupportedByPolicy.set(u.id, (snap.unsupportedByPolicy.get(u.id) ?? 0) + 1);
    }
  }
  return snap;
}

export function enforcementFor(snap: OrgEnforcementSnapshot, policyId: string): PolicyEnforcement {
  return {
    deployments: snap.deployments,
    applied: snap.appliedByPolicy.get(policyId) ?? 0,
    current: snap.applied,
    stale: snap.stale,
    unsupported: snap.unsupportedByPolicy.get(policyId) ?? 0,
  };
}

/** Shape of `deployment.policyBundle` on GET /api/v1/deployments. */
export function policyBundleStatusFor(
  snap: OrgEnforcementSnapshot,
  deploymentId: string,
): { etag: string; appliedAt: string; daemonVersion: string | null; stale: boolean; applied: number; unsupported: Array<{ id: string; reason: string }> } | null {
  const s = snap.byDeployment.get(deploymentId);
  if (!s) return null;
  return {
    etag: s.etag,
    appliedAt: s.appliedAt.toISOString(),
    daemonVersion: s.daemonVersion,
    stale: s.etag !== snap.etag,
    applied: s.applied.length,
    unsupported: s.unsupported,
  };
}
