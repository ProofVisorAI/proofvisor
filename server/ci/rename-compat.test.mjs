// Clients set up before the ProofVisor rename must keep working once the
// renamed API is deployed: API keys minted as av_srv_…, daemons that send
// X-AV-Deployment, console tabs that pin X-AV-Org, and webhook receivers
// that verify X-AgentVisor-Signature.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { hash } from "@node-rs/argon2";
import pg from "pg";

import { DATABASE_URL, signupOwner, startApi } from "./helpers/api-process.mjs";

let api;
let owner;
let db;
before(async () => {
  api = await startApi({ ALLOW_INTERNAL_WEBHOOK_TARGETS: "true", WEBHOOK_SWEEPER_INTERVAL_MS: "1000" });
  owner = await signupOwner(api.base, "renamecompat");
  db = new pg.Client({ connectionString: DATABASE_URL });
  await db.connect();
});
after(async () => {
  await db?.end();
  await api?.stop();
});

test("an API key minted as av_srv_ still authenticates and lists with its real prefix", async () => {
  const body = randomBytes(21).toString("base64url"); // 28 chars, like randomToken(28)
  const plaintext = "av_srv_" + body;
  // The row as the pre-rename API wrote it: no tokenPrefix (the column
  // default fills in av_srv_).
  await db.query(
    'INSERT INTO api_keys (id, "orgId", name, "tokenHash", "tokenHint", role, "createdAt") VALUES ($1, $2, $3, $4, $5, $6, NOW())',
    ["legacykey" + Date.now().toString(36), owner.org.id, "legacy CI key", await hash(plaintext), body.slice(0, 8), "admin"],
  );
  const res = await fetch(api.base + "/api/v1/deployments", { headers: { Authorization: "Bearer " + plaintext } });
  assert.equal(res.status, 200, await res.text());

  const fresh = await owner.client.json("POST", "/api/v1/keys", { name: "new key", role: "member" });
  assert.equal(fresh.status, 201, JSON.stringify(fresh.data));
  assert.match(fresh.data.plaintextToken, /^pv_srv_/);

  const list = await owner.client.json("GET", "/api/v1/keys");
  const hints = list.data.keys.map((k) => k.hint);
  assert.ok(hints.includes("av_srv_" + body.slice(0, 8) + "…"), hints.join(","));
  assert.ok(hints.some((h) => h.startsWith("pv_srv_")), hints.join(","));
});

test("a daemon that sends X-AV-Deployment is accepted", async () => {
  const dep = await owner.client.json("POST", "/api/v1/deployments", { name: "legacy-daemon", environment: "production" });
  assert.equal(dep.status, 201);
  const res = await fetch(api.base + "/api/v1/ingest/policies", {
    headers: { Authorization: "Bearer " + dep.data.ingestToken, "X-AV-Deployment": dep.data.deployment.id },
  });
  assert.equal(res.status, 200, await res.text());
});

test("a console tab pinned with X-AV-Org is still refused after the workspace changed", async () => {
  const res = await owner.client.json("POST", "/api/v1/deployments", { name: "pinned", environment: "production" }, {
    headers: { "X-AV-Org": "some-other-org" },
  });
  assert.equal(res.status, 409, JSON.stringify(res.data));
});

test("webhook deliveries carry the signature under both header names", async () => {
  const seen = [];
  const recv = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => { seen.push({ headers: req.headers, raw }); res.writeHead(200).end("ok"); });
  });
  await new Promise((r) => recv.listen(0, "127.0.0.1", r));
  try {
    const url = `http://127.0.0.1:${recv.address().port}/hook`;
    const ep = await owner.client.json("POST", "/api/v1/webhooks", { name: "legacy receiver", url, events: ["test"] });
    assert.equal(ep.status, 201, JSON.stringify(ep.data));
    const sent = await owner.client.json("POST", `/api/v1/webhooks/${ep.data.endpoint?.id ?? ep.data.id}/test`, {});
    assert.ok(sent.status < 300, JSON.stringify(sent.data));
    for (let i = 0; i < 50 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(seen.length, 1);
    const h = seen[0].headers;
    const expected = "sha256=" + createHmac("sha256", ep.data.secret).update(h["x-proofvisor-timestamp"]).update(".").update(seen[0].raw).digest("hex");
    assert.equal(h["x-proofvisor-signature"], expected);
    assert.equal(h["x-agentvisor-signature"], expected);
    assert.equal(h["x-agentvisor-timestamp"], h["x-proofvisor-timestamp"]);
    assert.equal(h["x-agentvisor-event"], "test");
    assert.equal(h["x-agentvisor-delivery"], h["x-proofvisor-delivery"]);
  } finally {
    recv.close();
  }
});
