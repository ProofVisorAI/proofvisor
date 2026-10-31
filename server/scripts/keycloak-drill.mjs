#!/usr/bin/env node
/*
 * Real identity provider drill: Keycloak as the OIDC provider AND the SAML
 * IdP of the hosted console, driven through a real browser.
 *
 * What it does, in order:
 *   1. Configures a fresh Keycloak realm through the admin REST API: an
 *      OIDC confidential client with the console's callback, two users with
 *      verified e-mail addresses, and (after the SP exists) a SAML client
 *      for the console's service provider.
 *   2. Applies the console database migrations and boots the console API
 *      (`node node_modules/.bin/tsx src/index.ts`) with OIDC_* pointing at
 *      the realm.
 *   3. OIDC login in headless Chromium: /api/v1/auth/oauth/oidc/start ->
 *      Keycloak login page -> callback -> console session. Asserts the JIT
 *      user and org, the session cookie (/me), and the audit rows.
 *   4. Creates a SAML config through the console API from Keycloak's SAML
 *      IdP descriptor, registers the console SP in Keycloak, and performs
 *      a SP-initiated SAML login in a fresh browser context: /login ->
 *      Keycloak -> auto-posted SAMLResponse -> ACS -> session. Asserts JIT
 *      provisioning into the same org, the session, and the audit rows.
 *   5. Deletes the users and orgs it created, the Keycloak realm, and stops
 *      the API.
 *
 * Prerequisites (the CI job does these; locally run them once):
 *   docker run -d --name pv-keycloak -p 8180:8080 \
 *     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=<pw> \
 *     quay.io/keycloak/keycloak:26.8.1 start-dev
 *   (cd server && npm ci && npx prisma generate && npx playwright install chromium)
 *   an empty PostgreSQL database, e.g. postgresql://pv:pv@localhost:5433/pvdb_c
 *
 * Run from server/:
 *   KEYCLOAK_ADMIN_PASSWORD=<pw> node scripts/keycloak-drill.mjs
 *
 * Environment: KEYCLOAK_URL (default http://127.0.0.1:8180), KEYCLOAK_ADMIN_USER
 * (admin), KEYCLOAK_ADMIN_PASSWORD (required), DATABASE_URL (default
 * postgresql://pv:pv@localhost:5433/pvdb_c), PORT (8994), KEYCLOAK_DRILL_OUTPUT
 * (directory for the API log and report.json; default a temp dir).
 */
import { spawn, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const KC = (process.env.KEYCLOAK_URL || "http://127.0.0.1:8180").replace(/\/$/, "");
const KC_ADMIN_USER = process.env.KEYCLOAK_ADMIN_USER || "admin";
const KC_ADMIN_PASSWORD = process.env.KEYCLOAK_ADMIN_PASSWORD;
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://pv:pv@localhost:5433/pvdb_c";
const PORT = Number(process.env.PORT || 8994);
const API = `http://127.0.0.1:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || "c-secret-not-for-production-0123456789abcdef0123456789abcdef";
const RUN = crypto.randomBytes(4).toString("hex");
const REALM = `pv-drill-${RUN}`;
const OIDC_CLIENT_ID = "pv-console";
const OIDC_CLIENT_SECRET = crypto.randomBytes(24).toString("base64url");
const OIDC_DOMAIN = `oidc-${RUN}.keycloak-drill.example`;
const SAML_DOMAIN = `saml-${RUN}.keycloak-drill.example`;
const OIDC_USER = { username: `oidc.user.${RUN}`, email: `oidc.user@${OIDC_DOMAIN}`, password: crypto.randomBytes(12).toString("base64url"), first: "Rick", last: "Sanchez" };
const SAML_USER = { username: `saml.user.${RUN}`, email: `saml.user@${SAML_DOMAIN}`, password: crypto.randomBytes(12).toString("base64url"), first: "Beth", last: "Smith" };
const OUTPUT = process.env.KEYCLOAK_DRILL_OUTPUT || fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), "pv-keycloak-drill-"));
fs.mkdirSync(OUTPUT, { recursive: true });

const report = { status: "running", keycloak: null, realm: REALM, checks: [], cleanup: {} };
let passed = 0;
let failed = 0;
function check(name, ok, detail) {
  report.checks.push({ name, passed: !!ok });
  if (ok) {
    passed++;
    console.log(`PASS ${name}`);
  } else {
    failed++;
    console.log(`FAIL ${name}${detail === undefined ? "" : " " + JSON.stringify(detail).slice(0, 800)}`);
    throw new Error(name);
  }
}

async function json(response) {
  const text = await response.text();
  try { return JSON.parse(text); } catch { return { raw: text.slice(0, 500) }; }
}

/* ---------------- Keycloak admin REST API ---------------- */

let adminToken = null;
let adminTokenAt = 0;
async function admin(method, route, body) {
  if (!adminToken || Date.now() - adminTokenAt > 45_000) {
    const r = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: KC_ADMIN_USER, password: KC_ADMIN_PASSWORD }),
    });
    if (r.status !== 200) throw new Error(`Keycloak admin token: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
    adminToken = (await r.json()).access_token;
    adminTokenAt = Date.now();
  }
  const r = await fetch(`${KC}/admin${route}`, {
    method,
    headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json", Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status >= 300) throw new Error(`Keycloak admin ${method} ${route}: HTTP ${r.status} ${(await r.text()).slice(0, 300)}`);
  return r;
}

async function waitForKeycloak() {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${KC}/realms/master`);
      if (r.status === 200) return;
    } catch { /* booting */ }
    await new Promise((res) => setTimeout(res, 1000));
  }
  throw new Error(`Keycloak at ${KC} did not answer within 180 s`);
}

async function createUser(user) {
  await admin("POST", `/realms/${REALM}/users`, {
    username: user.username, email: user.email, emailVerified: true, enabled: true,
    firstName: user.first, lastName: user.last, requiredActions: [],
    credentials: [{ type: "password", value: user.password, temporary: false }],
  });
}

/* ---------------- console API process ---------------- */

const children = [];
function stopChildren() {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, "SIGTERM"); } catch { /* gone */ }
    }
  }
}

async function bootApi(env) {
  const tsx = path.join(SERVER_DIR, "node_modules/.bin/tsx");
  if (!fs.existsSync(tsx)) throw new Error("server/node_modules is missing: run `npm ci` in server/ first");
  execFileSync("npx", ["prisma", "migrate", "deploy"], { cwd: SERVER_DIR, env: { ...process.env, DATABASE_URL }, stdio: "pipe" });
  const log = fs.openSync(path.join(OUTPUT, "api.log"), "a");
  const child = spawn("node", [tsx, "src/index.ts"], { cwd: SERVER_DIR, env, stdio: ["ignore", log, log], detached: true });
  children.push(child);
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`console API exited early (${child.exitCode}); see ${path.join(OUTPUT, "api.log")}`);
    try {
      if ((await fetch(`${API}/healthz`)).ok) return child;
    } catch { /* booting */ }
    await new Promise((res) => setTimeout(res, 500));
  }
  throw new Error("console API did not become healthy");
}

/* ---------------- helpers against the console API ---------------- */

const SPA_HEADERS = { Origin: API, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" };

async function me(cookie) {
  const r = await fetch(`${API}/api/v1/auth/me`, { headers: { Cookie: cookie } });
  return { status: r.status, body: r.status === 200 ? await r.json() : await json(r) };
}

async function auditEvents(cookie, wanted) {
  let entries = [];
  for (let i = 0; i < 40; i++) {
    const r = await fetch(`${API}/api/v1/audit?limit=100`, { headers: { Cookie: cookie } });
    const body = await json(r);
    entries = body.entries || body.items || [];
    const events = entries.map((e) => e.event);
    if (wanted.every((w) => events.includes(w))) break;
    await new Promise((res) => setTimeout(res, 150));
  }
  return entries;
}

// Read the whole cookie jar: Playwright's `cookies(url)` filter drops
// Secure cookies for an http:// URL even though Chromium itself sends
// them to 127.0.0.1.
async function sessionCookie(context) {
  const cookies = await context.cookies();
  const hit = cookies.find((c) => c.name === "pv_session" && (c.domain === "127.0.0.1" || c.domain === "localhost"));
  return hit ? `pv_session=${hit.value}` : null;
}

async function keycloakLogin(page, user) {
  await page.waitForSelector("#username", { timeout: 30_000 });
  await page.fill("#username", user.username);
  await page.fill("#password", user.password);
  await Promise.all([
    page.waitForURL((url) => url.href.startsWith(`${API}/app/`), { timeout: 30_000 }),
    page.click("#kc-login"),
  ]);
}

/* ---------------- main ---------------- */

async function main() {
  if (!KC_ADMIN_PASSWORD) throw new Error("KEYCLOAK_ADMIN_PASSWORD is required");
  const { chromium } = await import("playwright");
  process.env.DATABASE_URL = DATABASE_URL;
  const { PrismaClient } = await import("@prisma/client");
  const db = new PrismaClient();

  console.log(`[0] waiting for Keycloak at ${KC}`);
  await waitForKeycloak();
  const serverInfo = await (await admin("GET", "/serverinfo")).json();
  report.keycloak = { url: KC, version: serverInfo.systemInfo?.version ?? null };
  console.log(`    Keycloak ${report.keycloak.version}`);

  console.log(`[1] configuring realm ${REALM} through the admin REST API`);
  await admin("POST", "/realms", { realm: REALM, enabled: true, sslRequired: "none", registrationAllowed: false, loginWithEmailAllowed: true });
  let realmCreated = true;
  let apiProcess = null;
  let browser = null;
  const createdEmails = [OIDC_USER.email, SAML_USER.email];
  try {
    await admin("POST", `/realms/${REALM}/clients`, {
      clientId: OIDC_CLIENT_ID, name: "ProofVisor console (OIDC)", enabled: true, protocol: "openid-connect",
      publicClient: false, secret: OIDC_CLIENT_SECRET, standardFlowEnabled: true, implicitFlowEnabled: false,
      directAccessGrantsEnabled: false, serviceAccountsEnabled: false,
      redirectUris: [`${API}/api/v1/auth/oauth/oidc/callback`], webOrigins: [],
      attributes: { "pkce.code.challenge.method": "S256" },
    });
    await createUser(OIDC_USER);
    await createUser(SAML_USER);
    const discovery = await (await fetch(`${KC}/realms/${REALM}/.well-known/openid-configuration`)).json();
    check("Keycloak realm publishes OIDC discovery", discovery.issuer === `${KC}/realms/${REALM}`, discovery.issuer);

    console.log("[2] booting the console API against Keycloak");
    // SESSION_COOKIE_SECURE stays on: the SAML ceremony binds the browser
    // with a `SameSite=None` cookie, and Chromium discards such a cookie
    // unless it also carries `Secure`. Chromium treats http://127.0.0.1 as
    // a trustworthy origin, so Secure cookies are set and sent over plain
    // HTTP there (the same arrangement as ci/saml-browser-e2e.mjs).
    const env = {
      ...process.env,
      JWT_SECRET, PORT: String(PORT), HOST: "127.0.0.1", NODE_ENV: "development",
      APP_BASE_URL: API, API_PUBLIC_URL: API, ALLOWED_ORIGINS: API,
      SESSION_COOKIE_SECURE: process.env.SESSION_COOKIE_SECURE || "true",
      DATABASE_URL,
      OIDC_ISSUER_URL: `${KC}/realms/${REALM}`, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_DISPLAY_NAME: "Keycloak",
    };
    apiProcess = await bootApi(env);
    const providers = await (await fetch(`${API}/api/v1/auth/oauth/providers`)).json();
    const oidc = (providers.providers || []).find((p) => p.id === "oidc");
    check("console lists the Keycloak OIDC provider", oidc?.displayName === "Keycloak", providers);

    const before = await db.user.count({ where: { email: { in: createdEmails } } });
    check("no drill users exist before the logins", before === 0, before);

    console.log("[3] OIDC login through Keycloak in Chromium");
    browser = await chromium.launch();
    const oidcContext = await browser.newContext();
    const page = await oidcContext.newPage();
    await page.goto(`${API}/api/v1/auth/oauth/oidc/start`, { waitUntil: "domcontentloaded" });
    check("console redirects the browser to the Keycloak login page", page.url().startsWith(`${KC}/realms/${REALM}/protocol/openid-connect/auth`), page.url());
    await keycloakLogin(page, OIDC_USER);
    check("Keycloak sends the browser back into the console", page.url().startsWith(`${API}/app/`), page.url());
    const oidcCookie = await sessionCookie(oidcContext);
    check("console session cookie is set after the OIDC callback", !!oidcCookie);
    const oidcMe = await me(oidcCookie);
    check("session is valid: /me returns the Keycloak user", oidcMe.status === 200 && oidcMe.body.user?.email === OIDC_USER.email, oidcMe);
    check("JIT provisioning made the user owner of a new org", oidcMe.body.org?.role === "owner" && typeof oidcMe.body.org?.id === "string", oidcMe.body.org);
    const orgId = oidcMe.body.org.id;
    const oidcUser = await db.user.findUnique({ where: { email: OIDC_USER.email }, include: { memberships: true } });
    check("database holds the JIT user with a verified e-mail and one membership",
      !!oidcUser?.emailVerifiedAt && oidcUser.memberships.length === 1 && oidcUser.memberships[0].orgId === orgId, oidcUser);
    const tampered = oidcCookie.slice(0, -4) + (oidcCookie.endsWith("AAAA") ? "BBBB" : "AAAA");
    check("a tampered session cookie is refused", (await me(tampered)).status === 401);
    const oidcAudit = await auditEvents(oidcCookie, ["org.created", "auth.oauth_signin"]);
    const oidcEvents = oidcAudit.map((e) => e.event);
    check("audit rows record org.created and auth.oauth_signin", oidcEvents.includes("org.created") && oidcEvents.includes("auth.oauth_signin"), oidcEvents);
    const signin = oidcAudit.find((e) => e.event === "auth.oauth_signin");
    check("the sign-in audit row names the oidc provider and the user", signin?.metadata?.provider === "oidc" && signin?.actor === OIDC_USER.email, signin);

    console.log("[4] SAML: console SP config from Keycloak's IdP descriptor");
    const descriptor = await (await fetch(`${KC}/realms/${REALM}/protocol/saml/descriptor`)).text();
    const certBody = /<(?:ds:)?X509Certificate>([^<]+)<\/(?:ds:)?X509Certificate>/.exec(descriptor)?.[1]?.replace(/\s+/g, "");
    const ssoUrl = /SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"/.exec(descriptor)?.[1]
      || /SingleSignOnService[^>]*Location="([^"]+)"/.exec(descriptor)?.[1];
    const entityIdIdp = /entityID="([^"]+)"/.exec(descriptor)?.[1];
    check("Keycloak publishes a SAML IdP descriptor with a signing certificate", !!certBody && !!ssoUrl && !!entityIdIdp, { ssoUrl, entityIdIdp });
    const pem = `-----BEGIN CERTIFICATE-----\n${certBody.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
    const create = await fetch(`${API}/api/v1/auth/saml`, {
      method: "POST", headers: { ...SPA_HEADERS, Cookie: oidcCookie },
      body: JSON.stringify({
        displayName: "Keycloak SAML", ssoUrl, entityIdIdp, x509Cert: pem,
        wantAssertionsSigned: true, wantResponseSigned: true, allowEncryptedAssertions: false,
        jitEnabled: true, jitDefaultRole: "member", allowedDomains: SAML_DOMAIN,
      }),
    });
    const created = await json(create);
    check("console accepts the SAML config built from Keycloak's descriptor", create.status === 201 && created.config?.id, created);
    const samlConfig = created.config;

    await admin("POST", `/realms/${REALM}/clients`, {
      clientId: samlConfig.spEntityId, name: "ProofVisor console (SAML SP)", enabled: true, protocol: "saml",
      redirectUris: [samlConfig.spAcsUrl], frontchannelLogout: true,
      attributes: {
        "saml.assertion.signature": "true", "saml.server.signature": "true", "saml.client.signature": "false",
        "saml.encrypt": "false", "saml.authnstatement": "true", "saml_name_id_format": "email",
        "saml_force_name_id_format": "true", "saml.force.post.binding": "true",
        "saml_assertion_consumer_url_post": samlConfig.spAcsUrl,
        "saml.signature.algorithm": "RSA_SHA256",
        "saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#",
      },
      protocolMappers: [
        { name: "email", protocol: "saml", protocolMapper: "saml-user-property-mapper", consentRequired: false,
          config: { "user.attribute": "email", "attribute.name": "email", "attribute.nameformat": "Basic", "friendly.name": "email" } },
      ],
    });

    console.log("[5] SP-initiated SAML login through Keycloak in a fresh browser context");
    const samlContext = await browser.newContext();
    const samlPage = await samlContext.newPage();
    await samlPage.goto(`${API}/api/v1/auth/saml/${samlConfig.id}/login`, { waitUntil: "domcontentloaded" });
    check("console redirects the browser to Keycloak's SAML endpoint", samlPage.url().startsWith(`${KC}/realms/${REALM}/`), samlPage.url());
    await keycloakLogin(samlPage, SAML_USER);
    check("Keycloak's SAMLResponse lands the browser in the console", samlPage.url().startsWith(`${API}/app/`), samlPage.url());
    const samlCookie = await sessionCookie(samlContext);
    check("console session cookie is set after the SAML ACS", !!samlCookie);
    const samlMe = await me(samlCookie);
    check("session is valid: /me returns the SAML user", samlMe.status === 200 && samlMe.body.user?.email === SAML_USER.email, samlMe);
    check("SAML JIT provisioned the user into the SP's org as a member", samlMe.body.org?.id === orgId && samlMe.body.org?.role === "member", samlMe.body.org);
    const samlUser = await db.user.findUnique({ where: { email: SAML_USER.email }, include: { memberships: true } });
    check("database holds the SAML JIT user without a mailbox verification claim",
      !!samlUser && samlUser.emailVerifiedAt === null && samlUser.memberships.length === 1 && samlUser.memberships[0].orgId === orgId, samlUser);
    const samlAudit = await auditEvents(oidcCookie, ["saml.signin"]);
    const samlSignin = samlAudit.find((e) => e.event === "saml.signin");
    check("audit row saml.signin names the Keycloak config and the SAML user",
      samlSignin?.actor === SAML_USER.email && samlSignin?.metadata?.samlConfigId === samlConfig.id, samlSignin);
    check("audit rows record the SAML config creation", samlAudit.some((e) => /^saml\.config/.test(e.event)), samlAudit.map((e) => e.event));

    report.status = "passed";
  } finally {
    console.log("[6] cleanup");
    try { if (browser) await browser.close(); } catch { /* ignore */ }
    try {
      const users = await db.user.findMany({ where: { email: { in: createdEmails } }, include: { memberships: true } });
      const orgIds = [...new Set(users.flatMap((u) => u.memberships.map((m) => m.orgId)))];
      if (orgIds.length) await db.org.deleteMany({ where: { id: { in: orgIds } } });
      const deleted = await db.user.deleteMany({ where: { email: { in: createdEmails } } });
      report.cleanup.console = { orgs: orgIds.length, users: deleted.count };
    } catch (error) {
      report.cleanup.console = `failed: ${error.message}`;
    }
    try { await db.$disconnect(); } catch { /* ignore */ }
    if (realmCreated) {
      try { await admin("DELETE", `/realms/${REALM}`); report.cleanup.realm = "deleted"; } catch (error) { report.cleanup.realm = `failed: ${error.message}`; }
    }
    stopChildren();
    if (apiProcess) await new Promise((res) => { apiProcess.on("exit", res); setTimeout(res, 15_000); });
    report.passed = passed;
    report.failed = failed;
    fs.writeFileSync(path.join(OUTPUT, "report.json"), JSON.stringify(report, null, 2) + "\n");
    console.log(`cleanup: ${JSON.stringify(report.cleanup)}`);
  }
}

main().then(
  () => { console.log(`result: passed (${passed} checks, Keycloak ${report.keycloak?.version}); report in ${OUTPUT}`); process.exit(0); },
  (error) => {
    report.status = report.status === "passed" ? "passed" : "failed";
    console.error(`result: failed after ${passed} passing check(s): ${error.message}`);
    try { fs.writeFileSync(path.join(OUTPUT, "report.json"), JSON.stringify({ ...report, error: error.message }, null, 2) + "\n"); } catch { /* ignore */ }
    stopChildren();
    process.exit(1);
  },
);
