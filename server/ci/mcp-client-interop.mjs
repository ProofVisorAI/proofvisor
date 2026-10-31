#!/usr/bin/env node
/*
 * Interoperability test: the OFFICIAL MCP TypeScript SDK client
 * (`@modelcontextprotocol/sdk`, pinned below) talking to proofvisord's
 * `/mcp` endpoint with `StreamableHTTPClientTransport`.
 *
 * The script owns every process it needs:
 *   - the third-party reference MCP server
 *     (`@modelcontextprotocol/server-everything`, Streamable HTTP mode),
 *   - `proofvisord` with that server as its `[[backends]]` entry,
 *   - the SDK, installed into a private temporary directory (never into
 *     server/package.json) unless MCP_SDK_DIR points at an existing
 *     install.
 *
 * It then connects with the SDK's `Client`, lists tools, calls the allowed
 * `echo` tool, is refused on the unlisted `get-sum` tool, pings, terminates
 * the session through the SDK (HTTP DELETE), and checks that the gateway
 * sealed a receipt recording one allowed and one blocked call.
 *
 * Run: PROOFVISORD=target/debug/proofvisord node server/ci/mcp-client-interop.mjs
 * Needs Node.js 24+ and `npx`/`npm` (network on the first run).
 */
import { spawn, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const PROOFVISORD = path.resolve(process.env.PROOFVISORD || path.join(ROOT, "target/debug/proofvisord"));
const SDK_VERSION = process.env.MCP_SDK_VERSION || "1.32.2";
const SERVER_PACKAGE = process.env.MCP_SERVER_PACKAGE || "@modelcontextprotocol/server-everything@2.1.0";
const NPX = process.env.NPX || "npx";
const NPM = process.env.NPM || "npm";
const ALLOWED_TOOL = "echo";
const BLOCKED_TOOL = "get-sum";

let passed = 0;
let failed = 0;
function check(name, ok, detail) {
  if (ok) {
    passed++;
    console.log(`PASS ${name}`);
  } else {
    failed++;
    console.log(`FAIL ${name}${detail === undefined ? "" : " " + JSON.stringify(detail).slice(0, 800)}`);
    throw new Error(name);
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}

const children = [];
function start(command, args, { cwd, env, log }) {
  const out = fs.openSync(log, "a");
  const child = spawn(command, args, { cwd, env, stdio: ["ignore", out, out], detached: true });
  children.push(child);
  return child;
}
function stopAll() {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, "SIGTERM"); } catch { /* already gone */ }
    }
  }
}

async function waitFor(label, child, probe, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`${label} exited early (${child.exitCode})`);
    try {
      if (await probe()) return;
    } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`${label} did not become ready within ${timeoutMs} ms`);
}

function mint(secret, scopes) {
  const b64 = (s) => Buffer.from(s).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const header = b64(JSON.stringify({ alg: "HS256", typ: "JWT", kid: "dev-hmac" }));
  const claims = b64(JSON.stringify({
    iss: "mcp-client-interop", aud: "proofvisor", sub: "user:sdk@example.test",
    jti: crypto.randomUUID(), iat: now, exp: now + 600,
    instance_uid: "agent-sdk-1", version: "1", charter: "interop", scopes,
  }));
  const sig = crypto.createHmac("sha256", secret).update(`${header}.${claims}`).digest("base64url");
  return `${header}.${claims}.${sig}`;
}

async function main() {
  if (!fs.existsSync(PROOFVISORD)) throw new Error(`proofvisord not found at ${PROOFVISORD}; build it first`);
  const work = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), "pv-mcp-client-interop-"));
  fs.chmodSync(work, 0o700);
  console.log(`work directory: ${work}`);

  // 1. Third-party MCP server over Streamable HTTP.
  const serverPort = await freePort();
  const serverUrl = `http://127.0.0.1:${serverPort}/mcp`;
  const server = start(NPX, ["-y", SERVER_PACKAGE, "streamableHttp"], {
    cwd: work, env: { ...process.env, PORT: String(serverPort) }, log: path.join(work, "everything-server.log"),
  });
  const initBody = JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "probe", version: "1" } },
  });
  await waitFor("third-party MCP server", server, async () => {
    const r = await fetch(serverUrl, {
      method: "POST", body: initBody,
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    });
    return r.status === 200;
  }, 180_000);

  // 2. proofvisord with that server as an MCP backend.
  const secret = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(path.join(work, "hmac.secret"), secret, { mode: 0o600 });
  fs.writeFileSync(path.join(work, "signing.seed"), crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
  const gatewayPort = await freePort();
  const gateway = `http://127.0.0.1:${gatewayPort}`;
  const toml = `config_version = 1
listen = "127.0.0.1:${gatewayPort}"
upstream_url = "http://127.0.0.1:${serverPort}"
require_identity = true
enforce_identity_scopes = true
identity_hmac_secret_file = ${JSON.stringify(path.join(work, "hmac.secret"))}
require_tool_schema = false
require_intent_mapping = true
default_workflow = "signed"
dashboard_enabled = false
atif_spool_dir = ${JSON.stringify(path.join(work, "spool"))}
bridge_data_dir = ${JSON.stringify(path.join(work, "bridge"))}
mcp_request_timeout_s = 30
shutdown_drain_timeout_s = 5

[intent_map]
${JSON.stringify(ALLOWED_TOOL)} = "demo.echo"

[[backends]]
name = "everything"
url = ${JSON.stringify(serverUrl)}
transport = "mcp"
tools = [${JSON.stringify(ALLOWED_TOOL)}, ${JSON.stringify(BLOCKED_TOOL)}]
`;
  fs.writeFileSync(path.join(work, "proofvisor.toml"), toml);
  const daemonEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("PV_")));
  daemonEnv.PV_SIGNING_SEED_FILE = path.join(work, "signing.seed");
  daemonEnv.RUST_LOG = "info";
  const daemon = start(PROOFVISORD, ["--config", path.join(work, "proofvisor.toml")], {
    cwd: work, env: daemonEnv, log: path.join(work, "proofvisord.log"),
  });
  await waitFor("proofvisord", daemon, async () => (await fetch(`${gateway}/readyz`)).status === 200, 60_000);

  // 3. The official SDK, from a private install.
  let sdkDir = process.env.MCP_SDK_DIR;
  if (!sdkDir) {
    sdkDir = path.join(work, "sdk");
    fs.mkdirSync(sdkDir);
    fs.writeFileSync(path.join(sdkDir, "package.json"), JSON.stringify({ name: "pv-mcp-client-interop", private: true }));
    execFileSync(NPM, ["install", "--no-audit", "--no-fund", "--no-package-lock", `@modelcontextprotocol/sdk@${SDK_VERSION}`],
      { cwd: sdkDir, stdio: "pipe" });
  }
  const sdkRoot = path.join(sdkDir, "node_modules/@modelcontextprotocol/sdk");
  const sdkVersion = JSON.parse(fs.readFileSync(path.join(sdkRoot, "package.json"), "utf8")).version;
  console.log(`official SDK version: ${sdkVersion}`);
  const { Client } = await import(pathToFileURL(path.join(sdkRoot, "dist/esm/client/index.js")));
  const { StreamableHTTPClientTransport } = await import(pathToFileURL(path.join(sdkRoot, "dist/esm/client/streamableHttp.js")));

  const token = mint(secret, [`tool:${ALLOWED_TOOL}`, `tool:${BLOCKED_TOOL}`, "session:close"]);
  const transport = new StreamableHTTPClientTransport(new URL(`${gateway}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: "official-sdk-interop", version: "1.0.0" });
  await client.connect(transport);
  check("SDK client connects and negotiates a protocol version",
    typeof transport.protocolVersion === "string" || typeof transport.sessionId === "string",
    { protocolVersion: transport.protocolVersion, sessionId: transport.sessionId });
  check("gateway issues an MCP session id the SDK retains", typeof transport.sessionId === "string" && transport.sessionId.length > 0);
  const serverVersion = client.getServerVersion();
  check("gateway reports serverInfo through the SDK", !!serverVersion?.name, serverVersion);

  await client.ping();
  check("SDK ping succeeds", true);

  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  check("SDK listTools shows the third-party tool", names.includes(ALLOWED_TOOL), names);
  check("SDK listTools withholds the tool outside the allow-list", !names.includes(BLOCKED_TOOL), names);
  const echoTool = tools.find((t) => t.name === ALLOWED_TOOL);
  check("third-party input schema is relayed intact", echoTool?.inputSchema?.properties?.message?.type === "string", echoTool);

  const message = `sdk interop ${crypto.randomUUID().slice(0, 8)}`;
  const result = await client.callTool({ name: ALLOWED_TOOL, arguments: { message } });
  check("SDK callTool on the allowed tool is answered by the third-party server",
    result?.content?.[0]?.text === `Echo: ${message}`, result);

  let refusal = null;
  try {
    await client.callTool({ name: BLOCKED_TOOL, arguments: { a: 1, b: 2 } });
  } catch (error) {
    refusal = error;
  }
  const refusalText = `${refusal?.message ?? ""} ${JSON.stringify(refusal?.data ?? null)}`;
  check("SDK callTool on the unlisted tool is refused with UNMAPPED_TOOL",
    refusal !== null && /UNMAPPED_TOOL/.test(refusalText), refusalText.slice(0, 500));

  await transport.terminateSession();
  check("SDK terminateSession (DELETE) clears the session", transport.sessionId === undefined, transport.sessionId);
  await client.close();

  const receiptsDir = path.join(work, "spool", "receipts");
  const receipts = fs.existsSync(receiptsDir)
    ? fs.readdirSync(receiptsDir).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(fs.readFileSync(path.join(receiptsDir, f), "utf8")))
    : [];
  check("gateway sealed exactly one receipt for the SDK session", receipts.length === 1, receipts.length);
  check("receipt records one allowed and one blocked tool call",
    JSON.stringify(receipts[0].tool_calls) === JSON.stringify({ total: 2, allowed: 1, blocked: 1 }), receipts[0].tool_calls);

  fs.writeFileSync(path.join(work, "result.json"), JSON.stringify({
    status: "passed", sdk_version: sdkVersion, server_package: SERVER_PACKAGE, passed, failed,
    receipt_id: receipts[0].receipt_id,
  }, null, 2));
  console.log(`result: passed (${passed} checks); logs in ${work}`);
}

main().then(
  () => { stopAll(); process.exit(0); },
  (error) => {
    console.error(`result: failed after ${passed} passing check(s): ${error.message}`);
    stopAll();
    process.exit(1);
  },
);
