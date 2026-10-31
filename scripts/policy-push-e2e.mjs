#!/usr/bin/env node
// Console → daemon policy push, end to end with the real binaries.
//
// 1. A workspace on the console API gets a deployment and five policies
//    (deny-list, budget, schema, token rate, guardrail).
// 2. proofvisord starts with `policy_bundle_file` and a local budget.
// 3. `pvctl console-sync --pull-policies` pulls the bundle, the daemon
//    applies it, and pvctl reports the daemon's own status.
// 4. Tool calls and chat requests are blocked by the pushed rules, each
//    naming the console policy; the local config is never loosened.
// 5. The console shows "applied" for this daemon; a policy edit makes it
//    stale until the next pull; a daemon restart keeps the rules.
//
// Env: API_BASE (running console API), SPA_ORIGIN (an allowed origin),
// PROOFVISORD, PVCTL (built binaries). No external network is used.
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const API = process.env.API_BASE || "http://127.0.0.1:8990";
const ORIGIN = process.env.SPA_ORIGIN || "http://127.0.0.1:8790";
const daemonBin = process.env.PROOFVISORD;
const pvctlBin = process.env.PVCTL;
if (!daemonBin || !pvctlBin) {
  console.error("set PROOFVISORD and PVCTL to built binaries");
  process.exit(2);
}

let step = 0;
let daemon;
function check(label, ok, detail = "") {
  step += 1;
  console.log(`${ok ? "ok  " : "FAIL"} [${step}] ${label}${!ok && detail ? " — " + detail : ""}`);
  if (!ok) {
    if (daemon) {
      console.log("--- daemon log tail ---\n" + daemon.log().split("\n").slice(-25).join("\n"));
      daemon.proc.kill("SIGKILL");
    }
    process.exit(1);
  }
}

// ── Console side ────────────────────────────────────────────────────
let cookie = "";
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      Origin: ORIGIN,
      "Sec-Fetch-Site": "same-origin",
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const set = res.headers.get("set-cookie");
  const match = set && /(pv_session=[^;]+)/.exec(set);
  if (match) cookie = match[1];
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  return { status: res.status, json, text };
}

const signup = await api("/api/v1/auth/signup", {
  method: "POST",
  body: { email: `push-e2e-${Date.now()}@policy.example`, password: "correcthorse42x", orgName: "Policy Push E2E" },
});
check("console workspace created", signup.status === 201, signup.text);
const dep = await api("/api/v1/deployments", { method: "POST", body: { name: "push-e2e", environment: "production" } });
check("deployment created", dep.status === 201, dep.text);
const deploymentId = dep.json.deployment.id;
const policies = {
  deny: { name: "runtime.no_wires", kind: "allowlist", scope: "tool.*", body: '{"deny_tools":["send_wire"]}' },
  budget: { name: "runtime.call_cap", kind: "budget", scope: "tool.*", body: '{"max_total_tool_calls":3}' },
  schema: {
    name: "procurement.vendors", kind: "schema", scope: "tool.create_purchase_order",
    body: JSON.stringify({ tool: "create_purchase_order", json_schema: { type: "object", required: ["vendor"], properties: { vendor: { enum: ["Contoso", "Fabrikam"] } } } }),
  },
  rate: { name: "llm.velocity", kind: "rate", scope: "llm.request", body: '{"max_tokens_per_window":250,"window_s":3600}' },
  guard: { name: "privacy.pii_egress", kind: "guardrail", scope: "llm.egress", body: "documentation only" },
};
const ids = {};
for (const [key, policy] of Object.entries(policies)) {
  const res = await api("/api/v1/policies", { method: "POST", body: policy });
  check(`policy ${policy.name} created`, res.status === 201, res.text);
  ids[key] = res.json.policy.id;
}

// ── Local mocks and daemon ──────────────────────────────────────────
const listen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
const llm = createServer((req, res) => {
  req.on("data", () => {});
  req.on("end", () => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "cc", object: "chat.completion", created: 1, model: "m", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 40, completion_tokens: 10, total_tokens: 50 } }));
  });
});
const tools = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let rpc = {};
    try { rpc = JSON.parse(body); } catch { /* tolerate */ }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 1, result: { content: [{ type: "text", text: "{}" }] } }));
  });
});
const llmPort = await listen(llm);
const toolPort = await listen(tools);
const probe = createServer();
const daemonPort = await listen(probe);
await new Promise((resolve) => probe.close(resolve));

const work = mkdtempSync(join(tmpdir(), "pv-push-e2e-"));
const bundleFile = join(work, "policies.json");
const statusFile = bundleFile + ".status.json";
const tokenFile = join(work, "ingest.token");
writeFileSync(tokenFile, dep.json.ingestToken);
chmodSync(tokenFile, 0o600);
const configPath = join(work, "harness.toml");
writeFileSync(configPath, `config_version = 1
listen = "127.0.0.1:${daemonPort}"
upstream_url = "http://127.0.0.1:${llmPort}"
tool_upstream_url = "http://127.0.0.1:${toolPort}"
ignore_client_authorization = true
default_workflow = "unsigned"
consequential_tools = []
atif_spool_dir = "${work}/spool/atif"
bridge_data_dir = "${work}/data/bridge"
require_tool_schema = false
policy_bundle_file = "${bundleFile}"
policy_bundle_poll_s = 1

[budget]
max_total_tool_calls = 10
`);
const daemonUrl = `http://127.0.0.1:${daemonPort}`;

function startDaemon() {
  const proc = spawn(daemonBin, ["--config", configPath], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, PV_SIGNING_SEED_FILE: join(work, "signing.seed"), RUST_LOG: "info" },
  });
  let log = "";
  proc.stdout.on("data", (c) => (log += c));
  proc.stderr.on("data", (c) => (log += c));
  return { proc, log: () => log };
}
async function waitHealthy(timeoutMs = 20000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try { if ((await fetch(`${daemonUrl}/health`)).ok) return true; } catch { /* booting */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}
async function stopDaemon() {
  const exited = new Promise((resolve) => daemon.proc.once("exit", resolve));
  daemon.proc.kill("SIGTERM");
  await exited;
}
let rpcId = 0;
const callTool = (session, name, args) => fetch(`${daemonUrl}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json", "x-pv-session": session },
  body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } }),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));
const chat = (session, text) => fetch(`${daemonUrl}/v1/chat/completions`, {
  method: "POST",
  headers: { "content-type": "application/json", "x-pv-session": session },
  body: JSON.stringify({ model: "m", messages: [{ role: "user", content: text }] }),
}).then(async (r) => ({ status: r.status, text: await r.text() }));
const blockedBy = (reply) => JSON.stringify(reply.body);

function pull() {
  return spawnSync(pvctlBin, [
    "console-sync", "--spool-dir", join(work, "spool/atif"),
    "--console-url", API, "--deployment", deploymentId, "--token-file", tokenFile,
    "--state-file", join(work, "sync-state.json"),
    "--pull-policies", "--policy-bundle-file", bundleFile,
  ], { encoding: "utf8", timeout: 60000 });
}

daemon = startDaemon();
check("daemon boots without a bundle file", await waitHealthy());
const before = await callTool("s-before", "send_wire", {});
check("before the pull, send_wire is allowed", before.status === 200 && !before.body.error, blockedBy(before));

// ── Pull ────────────────────────────────────────────────────────────
const first = pull();
check("pvctl pulls the bundle and reports the daemon's status", first.status === 0, first.stderr + first.stdout);
check("the bundle file is owner-only", (readFileSync(bundleFile) && (await import("node:fs")).statSync(bundleFile).mode & 0o077) === 0);
const status = JSON.parse(readFileSync(statusFile, "utf8"));
check("the daemon applied the four enforceable policies",
  [ids.deny, ids.budget, ids.schema, ids.rate].every((id) => status.applied.includes(id)) && status.applied.length === 4,
  JSON.stringify(status));
check("the guardrail is neither applied nor reported unsupported", !status.applied.includes(ids.guard) && status.unsupported.length === 0);

const wire = await callTool("s1", "send_wire", {});
check("send_wire is now blocked by runtime.no_wires", wire.status !== 200 || !!wire.body.error, blockedBy(wire));
check("the refusal names the console policy", blockedBy(wire).includes("runtime.no_wires"), blockedBy(wire));
const badVendor = await callTool("s1", "create_purchase_order", { vendor: "Initech" });
check("an unlisted vendor is blocked by procurement.vendors", blockedBy(badVendor).includes("procurement.vendors"), blockedBy(badVendor));
const ok1 = await callTool("s1", "create_purchase_order", { vendor: "Contoso" });
const ok2 = await callTool("s1", "search_inventory", {});
const ok3 = await callTool("s1", "search_inventory", {});
check("allowed calls still run", [ok1, ok2, ok3].every((r) => r.status === 200 && !r.body.error), blockedBy(ok1) + blockedBy(ok2) + blockedBy(ok3));
const fourth = await callTool("s1", "search_inventory", {});
check("the pushed cap of 3 calls (stricter than the local 10) binds", blockedBy(fourth).includes("runtime.call_cap"), blockedBy(fourth));

const longPrompt = "Please summarise the procurement status for every warehouse in the region in detail. ".repeat(4);
const c1 = await chat("chat-a", longPrompt);
check("the first chat request fits the token rate", c1.status === 200, c1.text.slice(0, 200));
let refused = null;
for (let i = 0; i < 4 && !refused; i++) {
  const reply = await chat("chat-b" + i, longPrompt);
  if (reply.status !== 200) refused = reply;
}
check("the principal is refused once its token window is full", !!refused && refused.text.includes("llm.velocity"), refused ? refused.text.slice(0, 200) : "never refused");

// ── Console view ────────────────────────────────────────────────────
const listed = await api("/api/v1/policies");
const deny = listed.json.policies.find((p) => p.id === ids.deny);
check("the console shows the policy enforced by 1 of 1 daemon",
  deny.enforcement.deployments === 1 && deny.enforcement.applied === 1, JSON.stringify(deny.enforcement));
const deps = await api("/api/v1/deployments");
const row = deps.json.deployments.find((d) => d.id === deploymentId);
check("the deployment shows the applied bundle as current", row.policyBundle && row.policyBundle.stale === false, JSON.stringify(row.policyBundle));

// ── Edit, re-pull, restart ──────────────────────────────────────────
const edit = await api(`/api/v1/policies/${ids.deny}`, { method: "PATCH", body: { body: '{"deny_tools":["send_wire","delete_records"]}' } });
check("a policy edit is accepted", edit.status === 200, edit.text);
const stale = await api("/api/v1/deployments");
check("the daemon is stale until it pulls again", stale.json.deployments.find((d) => d.id === deploymentId).policyBundle.stale === true);
const second = pull();
check("a second pull applies the edit", second.status === 0, second.stderr + second.stdout);
const deleted = await callTool("s2", "delete_records", {});
check("the edited rule is enforced", blockedBy(deleted).includes("runtime.no_wires"), blockedBy(deleted));
const fresh = await api("/api/v1/deployments");
check("the console shows the daemon current again", fresh.json.deployments.find((d) => d.id === deploymentId).policyBundle.stale === false);
const unchanged = pull();
check("an unchanged bundle is a 304 and keeps the file", unchanged.status === 0 && !/written to/.test(unchanged.stderr), unchanged.stderr);

await stopDaemon();
daemon = startDaemon();
check("the daemon restarts with the bundle file in place", await waitHealthy());
const afterRestart = await callTool("s3", "send_wire", {});
check("the pushed rules are in force after the restart", blockedBy(afterRestart).includes("runtime.no_wires"), blockedBy(afterRestart));

await stopDaemon();
writeFileSync(bundleFile, "{ broken");
chmodSync(bundleFile, 0o600);
daemon = startDaemon();
const exitCode = await new Promise((resolve) => {
  daemon.proc.once("exit", resolve);
  setTimeout(() => resolve("still running"), 15000);
});
check("a corrupt bundle file stops the boot instead of running without rules", typeof exitCode === "number" && exitCode !== 0, String(exitCode));
check("the boot error explains the fix", /policy bundle/.test(daemon.log()), daemon.log().slice(-400));
daemon = null;

llm.close();
tools.close();
console.log(`policy-push-e2e: ${step} checks passed`);
process.exit(existsSync(work) ? 0 : 0);
