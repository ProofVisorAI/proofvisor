/**
 * Receipt trust anchor and live demo drill.
 *
 * Part 1: GET /api/v1/public/receipt-keys/:deploymentId publishes only a
 * deployment's pinned public key (no auth, CORS for any origin, no
 * credentials, 404 until a daemon pins a key or for a malformed id).
 *
 * Part 2: POST /api/v1/demo/attack stages a blocked-payment session in a
 * deployment flagged isDemo, sealed with a receipt; demo rows are
 * labelled, never counted as daemons, reused on a second run, refused
 * for members and for a real deployment that already holds the name,
 * and removed by DELETE /api/v1/demo.
 */

import { createHash } from "node:crypto";

const API = process.env.API_BASE || process.env.BASE || "http://127.0.0.1:20755";
const SPA_ORIGIN = process.env.SPA_ORIGIN || "http://127.0.0.1:8988";
const browser = { Origin: SPA_ORIGIN, "Sec-Fetch-Site": "same-origin" };
const DEMO_PUB_HEX = "573c8f249012fbb08b3d79973411bb93141f32719c86ada25306fde5e59e8d57";

let step = 0;
function check(label, condition, detail = "") {
  step += 1;
  if (!condition) {
    console.error(`FAIL [${step}] ${label}${detail ? " — " + detail : ""}`);
    process.exit(1);
  }
  console.log(`ok   [${step}] ${label}`);
}

async function call(path, { method = "GET", cookie, body, headers = browser } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      ...headers,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
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

async function signup(label) {
  const email = `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@demo-keys.example`;
  const res = await call("/api/v1/auth/signup", {
    method: "POST",
    body: { email, password: "correcthorse42x", orgName: `DemoKeys ${label}` },
  });
  if (res.status !== 201) throw new Error(`signup ${label}: ${res.status} ${res.text}`);
  return /(pv_session=[^;]+)/.exec(res.headers.get("set-cookie") ?? "")?.[1];
}

async function member(ownerCookie) {
  const invite = await call("/api/v1/members/invites", {
    method: "POST",
    cookie: ownerCookie,
    body: { email: `member-${Date.now()}@demo-keys.example`, role: "member" },
  });
  const url = invite.json?.invite?.acceptUrlDev;
  if (!url) throw new Error("no dev invite link: " + invite.text);
  const token = new URLSearchParams((url.split("#/")[1] ?? "").split("?")[1] ?? "").get("token");
  const accepted = await call("/api/v1/members/invites/accept", {
    method: "POST",
    body: { token, email: invite.json.invite.email, password: "membercorrecthorse77", displayName: "Member" },
  });
  return /(pv_session=[^;]+)/.exec(accepted.headers.get("set-cookie") ?? "")?.[1];
}

async function waitFor(predicate, attempts = 30) {
  for (let i = 0; i < attempts; i++) {
    const value = await predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return null;
}

async function main() {
  const owner = await signup("owner");

  // ── Part 1: public receipt keys ───────────────────────────────────
  const created = await call("/api/v1/deployments", {
    method: "POST",
    cookie: owner,
    body: { name: "keys-prod", environment: "production" },
  });
  const dep = { id: created.json.deployment.id, token: created.json.ingestToken };
  const before = await call(`/api/v1/public/receipt-keys/${dep.id}`, { headers: {} });
  check("no key is published before a daemon pins one", before.status === 404, String(before.status));
  for (const bad of ["..%2f..%2fetc", "a".repeat(65), "id%20with%20space"]) {
    const res = await call(`/api/v1/public/receipt-keys/${bad}`, { headers: {} });
    check(`malformed id ${bad.slice(0, 12)} answers 404`, res.status === 404, String(res.status));
  }
  const publicKeyHex = "11".repeat(32);
  const pinned = await fetch(`${API}/api/v1/ingest/pubkey`, {
    method: "POST",
    headers: { Authorization: `Bearer ${dep.token}`, "X-PV-Deployment": dep.id, "Content-Type": "application/json" },
    body: JSON.stringify({ publicKeyHex }),
  });
  check("the daemon pins its key", pinned.status === 200, String(pinned.status));
  const published = await call(`/api/v1/public/receipt-keys/${dep.id}`, {
    headers: { Origin: "https://somebody-else.example" },
  });
  check("the pinned key is published without authentication", published.status === 200, published.text);
  check("any origin may read it", published.headers.get("access-control-allow-origin") === "*");
  check("credentials are never allowed", published.headers.get("access-control-allow-credentials") === null);
  check(
    "only key material and labels are exposed",
    JSON.stringify(Object.keys(published.json).sort()) ===
      JSON.stringify(["deploymentId", "deploymentName", "keyId", "orgName", "pinnedAt", "publicKeyB64", "publicKeyHex"]),
    Object.keys(published.json).join(","),
  );
  check("the published key is the pinned key", published.json.publicKeyHex === publicKeyHex);
  check("base64 matches hex", Buffer.from(published.json.publicKeyB64, "base64").toString("hex") === publicKeyHex);
  check(
    "keyId is the first 32 hex chars of sha256(key)",
    published.json.keyId === createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 32),
  );
  check("pinnedAt is an ISO time", !Number.isNaN(Date.parse(published.json.pinnedAt)));

  // ── Part 2: live demo ─────────────────────────────────────────────
  const memberCookie = await member(owner);
  const memberTry = await call("/api/v1/demo/attack", { method: "POST", cookie: memberCookie, body: { pace: "instant" } });
  check("a member cannot stage the demo", memberTry.status === 403, String(memberTry.status));
  const anonymousTry = await call("/api/v1/demo/attack", { method: "POST", body: { pace: "instant" } });
  check("the demo needs a session", anonymousTry.status === 401, String(anonymousTry.status));
  const badPace = await call("/api/v1/demo/attack", { method: "POST", cookie: owner, body: { pace: "warp" } });
  check("an unknown pace is refused", badPace.status === 400, String(badPace.status));

  const first = await call("/api/v1/demo/attack", { method: "POST", cookie: owner, body: { pace: "instant" } });
  check("an owner stages the demo attack", first.status === 201, first.text);
  check("the demo deployment is flagged", first.json.deployment.isDemo === true && first.json.deployment.name === "demo-attack");
  const presence = await call("/api/v1/demo", { cookie: owner });
  check("demo data is reported present", presence.json.present === true && presence.json.sessions === 1);

  const sessions = await call("/api/v1/sessions?limit=50", { cookie: owner });
  const demoRow = sessions.json.sessions.find((s) => s.id === first.json.session.id);
  check("the demo session is listed and labelled", demoRow?.isDemo === true && demoRow.deployment?.isDemo === true);
  const detail = await waitFor(async () => {
    const res = await call(`/api/v1/sessions/${first.json.session.id}`, { cookie: owner });
    return res.json?.session?.status === "sealed" ? res : null;
  });
  check("the demo session ends sealed", !!detail, "never sealed");
  const blocked = (detail.json.session.events ?? detail.json.events ?? []).filter((e) => e.kind === "block");
  check("the story includes a blocked tool call", blocked.length >= 1, JSON.stringify(detail.json).slice(0, 300));
  const receipt = detail.json.session.receipt ?? detail.json.receipt;
  check("the demo session carries a receipt", !!receipt, JSON.stringify(detail.json).slice(0, 300));
  const demoKey = await call(`/api/v1/public/receipt-keys/${first.json.deployment.id}`, { headers: {} });
  check("the demo deployment publishes the public demo key", demoKey.json?.publicKeyHex === DEMO_PUB_HEX);

  const policies = await call("/api/v1/policies", { cookie: owner });
  await call("/api/v1/policies", {
    method: "POST",
    cookie: owner,
    body: { name: "cap", kind: "budget", scope: "tool.*", body: '{"max_tokens":100}' },
  });
  const withPolicy = await call("/api/v1/policies", { cookie: owner });
  check(
    "the demo deployment is not counted as a daemon",
    policies.status === 200 && withPolicy.json.policies[0].enforcement.deployments === 1,
    JSON.stringify(withPolicy.json.policies[0]?.enforcement),
  );

  const second = await call("/api/v1/demo/attack", { method: "POST", cookie: owner, body: { pace: "instant" } });
  check("a second run reuses the demo deployment", second.status === 201 && second.json.deployment.id === first.json.deployment.id);

  const removedByMember = await call("/api/v1/demo", { method: "DELETE", cookie: memberCookie });
  check("a member cannot remove demo data", removedByMember.status === 403, String(removedByMember.status));
  const removed = await call("/api/v1/demo", { method: "DELETE", cookie: owner });
  check("the owner removes demo data", removed.status === 200 && removed.json.deploymentsRemoved === 1 && removed.json.sessionsRemoved === 2, removed.text);
  const gone = await call("/api/v1/demo", { cookie: owner });
  check("no demo data remains", gone.json.present === false);
  const deps = await call("/api/v1/deployments", { cookie: owner });
  check("the real deployment is untouched", deps.json.deployments.length === 1 && deps.json.deployments[0].id === dep.id);
  const goneKey = await call(`/api/v1/public/receipt-keys/${first.json.deployment.id}`, { headers: {} });
  check("the removed demo deployment no longer publishes a key", goneKey.status === 404);

  const squatter = await call("/api/v1/deployments", {
    method: "POST",
    cookie: owner,
    body: { name: "demo-attack", environment: "production" },
  });
  check("a real deployment may use the name demo-attack", squatter.status === 201, squatter.text);
  const conflict = await call("/api/v1/demo/attack", { method: "POST", cookie: owner, body: { pace: "instant" } });
  check("the demo refuses to write into a real deployment", conflict.status === 409, String(conflict.status));

  console.log(`demo-and-keys-drill: ${step} checks passed`);
}

main().catch((error) => {
  console.error("demo-and-keys-drill crashed:", error);
  process.exit(1);
});
