// Boots the API as a child process against a real Postgres and tears it
// down. Used by ci/scim.test.mjs and ci/billing.test.mjs (node:test) —
// the SCIM and billing contracts span the session middleware, Prisma
// transactions and content-type parsing, which in-process mocks would
// hide. DATABASE_URL defaults to the local docker-compose database the
// drill battery uses; set it to point elsewhere.

import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import path from "node:path";

const serverDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export const DATABASE_URL = process.env.DATABASE_URL ?? "postgresql://pv:pv@localhost:5433/pvdb";

export async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

export async function startApi(extraEnv = {}) {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const env = {
    ...process.env,
    NODE_ENV: "test",
    PORT: String(port),
    HOST: "127.0.0.1",
    LOG_LEVEL: "warn",
    JWT_SECRET: "ci-fixture-secret-not-for-production-0123456789abcdef",
    APP_BASE_URL: base,
    API_PUBLIC_URL: base,
    ALLOWED_ORIGINS: base,
    SESSION_COOKIE_SECURE: "false",
    DATABASE_URL,
    DISABLE_RETENTION_SWEEPER: "true",
    ...extraEnv,
  };
  const child = spawn(process.execPath, [path.join(serverDir, "node_modules/.bin/tsx"), "src/index.ts"], {
    cwd: serverDir,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (d) => { log += d; if (log.length > 200_000) log = log.slice(-100_000); });
  child.stderr.on("data", (d) => { log += d; if (log.length > 200_000) log = log.slice(-100_000); });
  const deadline = Date.now() + 60_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`API exited early (code ${child.exitCode}):\n${log.slice(-4000)}`);
    try {
      const r = await fetch(base + "/healthz");
      if (r.ok) break;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      throw new Error(`API did not become healthy on ${base}:\n${log.slice(-4000)}`);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return {
    base,
    port,
    log: () => log,
    async stop() {
      if (child.exitCode !== null) return;
      child.kill("SIGTERM");
      await new Promise((resolve) => {
        const t = setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 5000);
        child.on("exit", () => { clearTimeout(t); resolve(); });
      });
    },
  };
}

/**
 * Minimal cookie-aware JSON client. `client.json(method, path, body,
 * opts)` resolves to { status, data, headers }. Set-Cookie pv_session
 * values are remembered per client, so one client is one browser.
 */
export function makeClient(base) {
  const client = {
    cookie: null,
    bearer: null,
    async json(method, path, body, opts = {}) {
      const headers = { ...(opts.headers ?? {}) };
      if (body !== undefined && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      if (client.cookie && !client.bearer) headers.Cookie = `pv_session=${client.cookie}`;
      if (client.bearer) headers.Authorization = `Bearer ${client.bearer}`;
      const res = await fetch(base + path, {
        method,
        headers,
        body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
        redirect: "manual",
      });
      const sc = res.headers.get("set-cookie") ?? "";
      const m = /pv_session=([^;]+)/.exec(sc);
      if (m) client.cookie = m[1] === "" ? null : m[1];
      const text = await res.text();
      let data = text;
      try { data = text ? JSON.parse(text) : null; } catch { /* keep text */ }
      return { status: res.status, data, headers: res.headers };
    },
  };
  return client;
}

let counter = 0;
export function uniqueEmail(tag) {
  counter++;
  return `${tag}+${Date.now().toString(36)}${counter}${Math.random().toString(36).slice(2, 6)}@example.test`;
}

/** Sign up a fresh owner + org. Returns { client, email, password, org, user }. */
export async function signupOwner(base, tag = "owner") {
  const client = makeClient(base);
  const email = uniqueEmail(tag);
  const password = "ci-fixture-password-" + Math.random().toString(36).slice(2, 10) + "!";
  let r = await client.json("POST", "/api/v1/auth/signup", { email, password, orgName: `CI ${tag} ${Date.now().toString(36)}` });
  if (r.status === 429) {
    // /signup is capped at 5 per minute per IP. Test files keep under
    // that budget; this wait is a safety net for slow or retried runs.
    const wait = Number(r.headers.get("retry-after") ?? 60);
    await new Promise((resolve) => setTimeout(resolve, (Number.isFinite(wait) ? wait : 60) * 1000 + 500));
    r = await client.json("POST", "/api/v1/auth/signup", { email, password, orgName: `CI ${tag} ${Date.now().toString(36)}` });
  }
  if (r.status !== 201 && r.status !== 200) throw new Error(`signup failed: ${r.status} ${JSON.stringify(r.data)}`);
  return { client, email, password, org: r.data.org, user: r.data.user };
}

/**
 * Invite + accept a member into the owner's org (dev-only acceptUrlDev
 * carries the token). Returns { client, email, password, userId }.
 */
export async function provisionMember(base, owner, role = "member", tag = "member") {
  const email = uniqueEmail(tag);
  const inv = await owner.client.json("POST", "/api/v1/members/invites", { email, role });
  if (inv.status !== 201) throw new Error(`invite failed: ${inv.status} ${JSON.stringify(inv.data)}`);
  const url = inv.data.invite.acceptUrlDev;
  const token = new URLSearchParams((url.split("#/")[1] ?? "").split("?")[1] ?? "").get("token");
  if (!token) throw new Error("no token in acceptUrlDev: " + url);
  const client = makeClient(base);
  const password = "ci-member-password-" + Math.random().toString(36).slice(2, 10) + "!";
  const acc = await client.json("POST", "/api/v1/members/invites/accept", { token, email, password, displayName: "CI " + tag });
  if (acc.status !== 200) throw new Error(`accept failed: ${acc.status} ${JSON.stringify(acc.data)}`);
  return { client, email, password, userId: acc.data.user?.id };
}
