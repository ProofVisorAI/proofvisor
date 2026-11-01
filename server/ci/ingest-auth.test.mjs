// Daemon authentication on the ingest routes. These routes skip the
// global rate limiter and every token check is an argon2 verify, while
// deployment ids travel in receipt share links. The guards in
// routes/ingest.ts must keep a wrong token from costing unbounded argon2
// work, without slowing a working daemon or outliving a token rotation.
// Demo deployments must never accept daemon traffic.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import { signupOwner, startApi } from "./helpers/api-process.mjs";

let api;
let owner;
before(async () => {
  api = await startApi();
  owner = await signupOwner(api.base, "ingestauth");
});
after(async () => {
  await api?.stop();
});

async function pull(deploymentId, token) {
  const res = await fetch(api.base + "/api/v1/ingest/policies", {
    headers: { Authorization: `Bearer ${token}`, "X-PV-Deployment": deploymentId },
  });
  await res.arrayBuffer();
  return res;
}

async function newDeployment(name) {
  const r = await owner.client.json("POST", "/api/v1/deployments", { name, environment: "production" });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return { id: r.data.deployment.id, token: r.data.ingestToken };
}

test("a working token keeps working and a rotated one stops at once", async () => {
  const dep = await newDeployment("auth-rotate");
  assert.equal((await pull(dep.id, dep.token)).status, 200);
  // Second call is served from the success cache; same answer.
  assert.equal((await pull(dep.id, dep.token)).status, 200);

  const rot = await owner.client.json("POST", `/api/v1/deployments/${dep.id}/rotate-token`, {});
  assert.equal(rot.status, 200);
  assert.equal((await pull(dep.id, dep.token)).status, 401, "the cached old token must not survive rotation");
  assert.equal((await pull(dep.id, rot.data.ingestToken)).status, 200);
});

test("an oversized bearer value is refused without hashing", async () => {
  const dep = await newDeployment("auth-oversized");
  assert.equal((await pull(dep.id, "x".repeat(10_000))).status, 401);
});

test("demo deployments refuse ingest and token rotation", async () => {
  const staged = await owner.client.json("POST", "/api/v1/demo/attack", { pace: "instant" });
  assert.equal(staged.status, 201, JSON.stringify(staged.data));
  const demoId = staged.data.deployment.id;
  const rot = await owner.client.json("POST", `/api/v1/deployments/${demoId}/rotate-token`, {});
  assert.equal(rot.status, 409);
  assert.equal(rot.data.error ?? rot.data.errorCode, "demo_deployment");
  assert.equal((await pull(demoId, "pv_live_" + "A".repeat(32))).status, 401);
});

// Runs last: it spends this address's failure budget.
test("repeated wrong tokens from one address hit 429 before argon2", async () => {
  const dep = await newDeployment("auth-budget");
  // Cache the real token first: a daemon that already authenticated
  // keeps working while someone else guesses from the same address.
  assert.equal((await pull(dep.id, dep.token)).status, 200);

  const statuses = [];
  for (let i = 0; i < 25; i++) {
    statuses.push((await pull(dep.id, `pv_live_wrong${i}`)).status);
  }
  // The budget is 20 failures per minute per address; the rotation test
  // above already spent one (the old token after rotation), while the
  // oversized and demo refusals never reach argon2 and spend none.
  const firstLimited = statuses.indexOf(429);
  assert.equal(firstLimited, 19, `statuses: ${statuses.join(",")}`);
  assert.deepEqual(statuses.slice(0, firstLimited), Array(firstLimited).fill(401));
  assert.deepEqual(statuses.slice(firstLimited), Array(25 - firstLimited).fill(429));

  const limited = await pull(dep.id, "pv_live_wrong-again");
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "60");

  assert.equal((await pull(dep.id, dep.token)).status, 200, "a cached daemon is not locked out");
});
