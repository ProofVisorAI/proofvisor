/**
 * Policy push drill.
 *
 * Exercises the console → daemon policy bundle end to end against a live
 * API: bundle shape and etag stability, If-None-Match → 304, invalid
 * specs refused at write time, the daemon's policy-status upsert with
 * its policy.applied audit row, enforcement counts on the read side,
 * the member role refused on writes, and cross-tenant isolation (org A's
 * ingest token never sees org B's policies).
 */

import { createHash } from "node:crypto";

const API = process.env.API_BASE || process.env.BASE || "http://127.0.0.1:20754";
const SPA_ORIGIN = process.env.SPA_ORIGIN || "http://127.0.0.1:8988";
const browser = { Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" };

let step = 0;
function check(label, condition, detail = "") {
  step += 1;
  if (!condition) {
    console.error(`FAIL [${step}] ${label}${detail ? " — " + detail : ""}`);
    process.exit(1);
  }
  console.log(`ok   [${step}] ${label}`);
}

async function call(path, { method = "GET", cookie, body, headers = {} } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      ...browser,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, json, text };
}

/** The error code, whether the body is a problem+json document or a bare {error}. */
function errorCode(res) {
  return res.json?.errorCode ?? res.json?.error;
}

async function signup(label) {
  const email = `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@policy-push.example`;
  const res = await fetch(`${API}/api/v1/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...browser },
    body: JSON.stringify({ email, password: "correcthorse42x", orgName: `PolicyPush ${label}` }),
  });
  if (res.status !== 201) throw new Error(`signup ${label}: ${res.status} ${await res.text()}`);
  const cookie = /(pv_session=[^;]+)/.exec(res.headers.get("set-cookie") ?? "")?.[1];
  if (!cookie) throw new Error(`signup ${label}: no session cookie`);
  return cookie;
}

async function deployment(cookie, name) {
  const res = await call("/api/v1/deployments", { method: "POST", cookie, body: { name, environment: "production" } });
  if (res.status !== 201) throw new Error(`deployment ${name}: ${res.status} ${res.text}`);
  return { id: res.json.deployment.id, token: res.json.ingestToken };
}

function daemonHeaders(dep, extra = {}) {
  return { Authorization: `Bearer ${dep.token}`, "X-PV-Deployment": dep.id, ...extra };
}

async function pull(dep, extra = {}) {
  const res = await fetch(`${API}/api/v1/ingest/policies`, { headers: daemonHeaders(dep, extra) });
  const text = await res.text();
  return { status: res.status, etagHeader: res.headers.get("etag"), json: text ? JSON.parse(text) : null };
}

async function report(dep, body) {
  // A daemon is not a browser: no Origin or Sec-Fetch-Site headers.
  const res = await fetch(`${API}/api/v1/ingest/policy-status`, {
    method: "POST",
    headers: { ...daemonHeaders(dep), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((key) => JSON.stringify(key) + ":" + canonical(value[key]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

async function createPolicy(cookie, policy) {
  return call("/api/v1/policies", { method: "POST", cookie, body: policy });
}

async function auditEvents(cookie, event) {
  // writeAudit is fire-and-forget; poll briefly.
  for (let i = 0; i < 20; i++) {
    const res = await call("/api/v1/audit?limit=50", { cookie });
    const hits = (res.json?.entries ?? []).filter((entry) => entry.event === event);
    if (hits.length > 0) return hits;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return [];
}

async function main() {
  const ownerA = await signup("owner-a");
  const ownerB = await signup("owner-b");
  const prod = await deployment(ownerA, "prod");
  const staging = await deployment(ownerA, "staging");
  const other = await deployment(ownerB, "other-tenant");

  // ── Empty bundle ──────────────────────────────────────────────────
  const empty = await pull(prod);
  check("empty bundle is served to a daemon", empty.status === 200, String(empty.status));
  check("bundle names the deployment and version 1", empty.json.version === 1 && empty.json.deploymentId === prod.id);
  check("empty bundle has no policies", Array.isArray(empty.json.policies) && empty.json.policies.length === 0);
  const anonymous = await fetch(`${API}/api/v1/ingest/policies`);
  check("bundle needs daemon credentials", anonymous.status === 401, String(anonymous.status));
  const wrongToken = await fetch(`${API}/api/v1/ingest/policies`, {
    headers: { Authorization: `Bearer ${other.token}`, "X-PV-Deployment": prod.id },
  });
  check("another tenant's token cannot pull this deployment", wrongToken.status === 401, String(wrongToken.status));

  // ── Spec validation on write ──────────────────────────────────────
  const invalid = [
    { name: "bad-json", kind: "budget", scope: "tool.*", body: "{not json" },
    { name: "no-limit", kind: "budget", scope: "tool.*", body: "{}" },
    { name: "unknown-field", kind: "rate", scope: "tool.*", body: '{"max_tokens_per_window":10,"window_s":60,"extra":1}' },
    { name: "zero-window", kind: "rate", scope: "tool.*", body: '{"max_tokens_per_window":10,"window_s":0}' },
    { name: "empty-allowlist", kind: "allowlist", scope: "tool.*", body: '{"allow_only":[]}' },
    { name: "out-of-scope", kind: "allowlist", scope: "tool.payments.*", body: '{"deny_tools":["shell.exec"]}' },
    { name: "schema-array", kind: "schema", scope: "tool.*", body: '{"tool":"t","json_schema":[]}' },
  ];
  for (const policy of invalid) {
    const res = await createPolicy(ownerA, policy);
    check(
      `invalid ${policy.kind} spec "${policy.name}" is refused with a reason`,
      res.status === 400 && errorCode(res) === "invalid_input" && typeof res.json?.specError === "string",
      `${res.status} ${res.text}`,
    );
  }

  // ── Valid policies ────────────────────────────────────────────────
  const valid = [
    { name: "a-budget", kind: "budget", scope: "tool.*", body: '{"max_total_tool_calls":20,"per_tool_max_calls":{"create_payment":2}}' },
    { name: "b-allowlist", kind: "allowlist", scope: "tool.*", body: '{"deny_tools":["shell.exec"]}' },
    { name: "c-rate", kind: "rate", scope: "tool.*", body: '{"max_tokens_per_window":50000,"window_s":3600}' },
    { name: "d-schema", kind: "schema", scope: "tool.create_payment", body: '{"tool":"create_payment","json_schema":{"type":"object","required":["amount"]}}' },
    { name: "e-guardrail", kind: "guardrail", scope: "tool.*", body: "Never send customer data to third parties." },
    { name: "f-disabled", kind: "budget", scope: "tool.*", body: '{"max_tokens":1000}', enabled: false },
  ];
  const ids = {};
  for (const policy of valid) {
    const res = await createPolicy(ownerA, policy);
    check(`policy ${policy.name} is created`, res.status === 201, `${res.status} ${res.text}`);
    ids[policy.name] = res.json.policy.id;
  }
  await createPolicy(ownerB, { name: "b-secret", kind: "budget", scope: "tool.*", body: '{"max_tokens":5}' });

  const bundle = await pull(prod);
  const names = bundle.json.policies.map((p) => p.name);
  check(
    "bundle lists only enabled policies, sorted by name",
    JSON.stringify(names) === JSON.stringify(["a-budget", "b-allowlist", "c-rate", "d-schema", "e-guardrail"]),
    names.join(","),
  );
  check("bundle never carries another tenant's policies", !names.includes("b-secret"));
  const byName = Object.fromEntries(bundle.json.policies.map((p) => [p.name, p]));
  check("enforceable kinds carry a parsed spec", byName["a-budget"].spec?.per_tool_max_calls?.create_payment === 2);
  check("free-text kinds carry spec null and the body", byName["e-guardrail"].spec === null && byName["e-guardrail"].body.startsWith("Never"));
  check(
    "each bundle entry has exactly the contract fields",
    bundle.json.policies.every(
      (p) => JSON.stringify(Object.keys(p).sort()) === JSON.stringify(["body", "enabled", "id", "kind", "name", "scope", "spec", "updatedAt"]),
    ),
  );
  check(
    "etag is the sha256 of the canonical policies array",
    bundle.json.etag === createHash("sha256").update(canonical(bundle.json.policies)).digest("hex"),
  );
  check("ETag header matches the body etag", bundle.etagHeader === `"${bundle.json.etag}"`, bundle.etagHeader);
  const again = await pull(prod);
  check("etag is stable while nothing changes", again.json.etag === bundle.json.etag);
  const stagingBundle = await pull(staging);
  check("every deployment of the org gets the same etag", stagingBundle.json.etag === bundle.json.etag);
  const otherBundle = await pull(other);
  check("the other tenant's bundle differs", otherBundle.json.etag !== bundle.json.etag && otherBundle.json.policies.length === 1);

  for (const offer of [bundle.json.etag, `"${bundle.json.etag}"`, `W/"${bundle.json.etag}"`, `"stale", "${bundle.json.etag}"`]) {
    const res = await pull(prod, { "If-None-Match": offer });
    check(`If-None-Match ${offer.slice(0, 12)}… answers 304`, res.status === 304 && res.json === null, String(res.status));
  }
  const changedOffer = await pull(prod, { "If-None-Match": '"0000"' });
  check("an old etag gets the full bundle", changedOffer.status === 200);

  // ── Member role cannot write ──────────────────────────────────────
  const invite = await call("/api/v1/members/invites", {
    method: "POST",
    cookie: ownerA,
    body: { email: `member-${Date.now()}@policy-push.example`, role: "member" },
  });
  const acceptUrl = invite.json?.invite?.acceptUrlDev;
  if (acceptUrl) {
    const query = (acceptUrl.split("#/")[1] ?? "").split("?")[1] ?? "";
    const token = new URLSearchParams(query).get("token");
    const accepted = await call("/api/v1/members/invites/accept", {
      method: "POST",
      body: { token, email: invite.json.invite.email, password: "membercorrecthorse77", displayName: "Member" },
    });
    const memberCookie = /(pv_session=[^;]+)/.exec(accepted.headers.get("set-cookie") ?? "")?.[1];
    check("member joins org A", accepted.status === 200 && !!memberCookie, String(accepted.status));
    const memberCreate = await createPolicy(memberCookie, { name: "member-try", kind: "guardrail", body: "x" });
    check("member cannot create a policy", memberCreate.status === 403, String(memberCreate.status));
    const memberPatch = await call(`/api/v1/policies/${ids["a-budget"]}`, {
      method: "PATCH",
      cookie: memberCookie,
      body: { enabled: false },
    });
    check("member cannot change a policy", memberPatch.status === 403, String(memberPatch.status));
    const memberRead = await call("/api/v1/policies", { cookie: memberCookie });
    check("member can read policies", memberRead.status === 200 && memberRead.json.policies.length === 6);
  } else {
    check("server returns the dev invite link (NODE_ENV must not be production)", false, invite.text);
  }

  // ── Daemon status reports ─────────────────────────────────────────
  const badStatus = await report(prod, { etag: "not-hex!", appliedAt: new Date().toISOString(), applied: [], unsupported: [] });
  check("a malformed status is refused", badStatus.status === 400, String(badStatus.status));
  const status = await report(prod, {
    etag: bundle.json.etag,
    appliedAt: new Date().toISOString(),
    daemonVersion: "0.1.0",
    applied: [ids["a-budget"], ids["b-allowlist"], ids["c-rate"], ids["d-schema"]],
    unsupported: [{ id: ids["e-guardrail"], reason: "guardrail policies are not daemon-enforceable" }],
  });
  check("prod reports the current bundle", status.status === 200 && status.json.stale === false, status.text);
  const audit = await auditEvents(ownerA, "policy.applied");
  check("the change writes a policy.applied audit entry", audit.length === 1, String(audit.length));
  const repeat = await report(prod, {
    etag: bundle.json.etag,
    appliedAt: new Date().toISOString(),
    daemonVersion: "0.1.0",
    applied: [ids["a-budget"]],
    unsupported: [{ id: ids["e-guardrail"], reason: "guardrail policies are not daemon-enforceable" }],
  });
  check("a repeat report with the same etag is accepted", repeat.status === 200);
  await new Promise((resolve) => setTimeout(resolve, 500));
  check("a repeat report does not write a second audit entry", (await auditEvents(ownerA, "policy.applied")).length === 1);
  const futureAt = new Date(Date.now() + 10 * 3600_000).toISOString();
  await report(staging, { etag: "ab12", appliedAt: futureAt, applied: [], unsupported: [] });

  // ── Read side ─────────────────────────────────────────────────────
  const listed = await call("/api/v1/policies", { cookie: ownerA });
  const budget = listed.json.policies.find((p) => p.name === "a-budget");
  check(
    "enforcement counts daemons against the current etag",
    budget.enforcement?.deployments === 2 && budget.enforcement.applied === 1 && budget.enforcement.stale === 1,
    JSON.stringify(budget.enforcement),
  );
  const guardrail = listed.json.policies.find((p) => p.name === "e-guardrail");
  check("unsupported reports are counted per policy", guardrail.enforcement.unsupported === 1, JSON.stringify(guardrail.enforcement));
  const one = await call(`/api/v1/policies/${ids["a-budget"]}`, { cookie: ownerA });
  check("the single-policy read carries enforcement too", one.json.policy?.enforcement?.applied === 1, one.text.slice(0, 200));
  const deps = await call("/api/v1/deployments", { cookie: ownerA });
  const prodRow = deps.json.deployments.find((d) => d.id === prod.id);
  const stagingRow = deps.json.deployments.find((d) => d.id === staging.id);
  check("deployments show the applied bundle", prodRow.policyBundle?.etag === bundle.json.etag && prodRow.policyBundle.stale === false);
  check("a deployment on another etag is stale", stagingRow.policyBundle?.stale === true);
  check(
    "a future appliedAt is clamped to the server clock",
    Date.parse(stagingRow.policyBundle.appliedAt) <= Date.now() + 5 * 60_000 + 1000,
    stagingRow.policyBundle.appliedAt,
  );
  const otherList = await call("/api/v1/policies", { cookie: ownerB });
  check("org B sees only its own policy", otherList.json.policies.length === 1 && otherList.json.policies[0].name === "b-secret");

  // ── A change moves the etag and makes prod stale ──────────────────
  const patched = await call(`/api/v1/policies/${ids["c-rate"]}`, {
    method: "PATCH",
    cookie: ownerA,
    body: { body: '{"max_tokens_per_window":40000,"window_s":3600}' },
  });
  check("an owner can change a policy spec", patched.status === 200, patched.text);
  const badPatch = await call(`/api/v1/policies/${ids["c-rate"]}`, {
    method: "PATCH",
    cookie: ownerA,
    body: { body: '{"window_s":3600}' },
  });
  check("an edit to an invalid spec is refused", badPatch.status === 400 && typeof badPatch.json?.specError === "string");
  const moved = await pull(prod, { "If-None-Match": `"${bundle.json.etag}"` });
  check("after a change the old etag gets the new bundle", moved.status === 200 && moved.json.etag !== bundle.json.etag);
  const after = await call("/api/v1/deployments", { cookie: ownerA });
  check("prod is now stale", after.json.deployments.find((d) => d.id === prod.id).policyBundle.stale === true);

  console.log(`policy-push-drill: ${step} checks passed`);
}

main().catch((error) => {
  console.error("policy-push-drill crashed:", error);
  process.exit(1);
});
