/*
 * Webhook "Retry" button drill: the deliveries view in the console can
 * send a finished delivery again.
 *
 * Needs a running API (API_BASE) and the console served in live mode
 * against it (SPA_ORIGIN, the /app path). A local receiver captures the
 * deliveries. Steps:
 *   1. sign up an owner, create a webhook pointing at the receiver
 *   2. fire a test event; the receiver gets it once; the row is delivered
 *   3. in the console: open the deliveries view, press Retry on the row
 *   4. the row shows "retrying" with attempt 0 at once (no reload)
 *   5. the receiver gets the same event again from the retry sweeper,
 *      and the row ends delivered
 *   6. pressing Retry again while it is retrying is refused with 409
 *      (API level, the button is gone from the row by then)
 *   7. a member does not see the Retry button, and the API refuses them
 *
 *   API_BASE=http://127.0.0.1:8995 SPA_ORIGIN=http://127.0.0.1:8797/app node scripts/webhook-redeliver-drill.mjs
 */
import { createServer } from "node:http";
import { chromium } from "playwright";

const API = process.env.API_BASE ?? "http://127.0.0.1:8995";
const SPA = (process.env.SPA_ORIGIN ?? "http://127.0.0.1:8797/app").replace(/\/$/, "");
const ORIGIN = new URL(SPA).origin;
// The public site needs ?live=1 to leave its demo mode; a console copy
// configured for a local API must NOT get it (it would switch that copy
// to the hosted API).
const LIVE_QUERY = /(^|\.)proofvisor\.com$/.test(new URL(SPA).hostname) ? "?live=1" : "";
const RECV_PORT = Number(process.env.RECV_PORT ?? 21118);
const nonce = Math.random().toString(36).slice(2, 8);
let fails = 0;
let step = 0;
const check = (label, ok, detail = "") => {
  step += 1;
  if (!ok) fails += 1;
  console.log(`${ok ? "PASS" : "FAIL"} [${step}] ${label}${ok || !detail ? "" : " — " + String(detail).slice(0, 300)}`);
};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const captured = [];
const receiver = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    captured.push({ event: req.headers["x-proofvisor-event"], body });
    res.writeHead(200);
    res.end("ok");
  });
});
await new Promise((r) => receiver.listen(RECV_PORT, "127.0.0.1", r));

function client() {
  let cookie = null;
  return {
    get cookie() { return cookie; },
    async call(method, path, body) {
      const res = await fetch(API + path, {
        method,
        headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin", ...(body ? { "Content-Type": "application/json" } : {}), ...(cookie ? { Cookie: cookie } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
      const set = res.headers.get("set-cookie");
      if (set && set.split(";")[0].split("=")[1]) cookie = set.split(";")[0];
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch {}
      return { status: res.status, json, text };
    },
  };
}

const owner = client();
const ownerEmail = `redeliver-${nonce}@test.dev`;
let r = await owner.call("POST", "/api/v1/auth/signup", { email: ownerEmail, password: "redeliver-drill-password-1", orgName: "Redeliver " + nonce });
check("owner signs up", r.status === 201, r.text);
r = await owner.call("POST", "/api/v1/webhooks", { name: "drill-receiver", url: `http://127.0.0.1:${RECV_PORT}/hook`, events: ["test"] });
check("webhook created", r.status === 201, r.text);
const endpointId = r.json?.webhook?.id ?? r.json?.endpoint?.id ?? r.json?.id;

r = await owner.call("POST", `/api/v1/webhooks/${endpointId}/test`);
check("test event fired", r.status === 200 || r.status === 202, r.text);
for (let i = 0; i < 40 && captured.length < 1; i++) await wait(250);
check("receiver got the test event once", captured.length === 1, JSON.stringify(captured.map((c) => c.event)));
let list = (await owner.call("GET", `/api/v1/webhooks/${endpointId}/deliveries`)).json?.deliveries ?? [];
const original = list[0];
check("the delivery row is delivered with attempt 1", original?.status === "delivered" && original?.attempt === 1, JSON.stringify(original));

// Console: press Retry on that row. The console copy at SPA_ORIGIN must
// point at API_BASE (CI and run-all.sh rewrite config.js for that).
const browser = await chromium.launch();
async function consolePage(c) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const [name, ...rest] = c.cookie.split("=");
  await ctx.addCookies([{ name, value: rest.join("="), url: API }]);
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(SPA + "/" + LIVE_QUERY + "#/settings/webhooks", { waitUntil: "networkidle" });
  await page.waitForSelector(`tr[data-id="${endpointId}"]`, { timeout: 15000 });
  await page.click(`tr[data-id="${endpointId}"] td:nth-child(2)`);
  await page.waitForSelector("#whdBody table", { timeout: 10000 });
  return { page, errors };
}
const { page, errors } = await consolePage(owner);
const retry = page.locator(`button[data-redeliver="${original.id}"]`);
check("owner sees a Retry button on the delivered row", (await retry.count()) === 1);
captured.length = 0;
await retry.click();
await page.waitForFunction((id) => {
  const tr = document.querySelector(`tr[data-delivery="${id}"]`);
  return tr && /retrying/.test(tr.querySelector(".whd-status").innerText);
}, original.id, { timeout: 8000 }).catch(() => {});
const rowText = await page.locator(`tr[data-delivery="${original.id}"]`).innerText();
check("the row shows retrying with attempt 0 without a reload", /retrying/.test(rowText) && /\b0\b/.test(rowText), rowText);
check("the Retry button is gone from that row", (await retry.count()) === 0);
const toastText = await page.locator("#toastStack .toast").allInnerTexts();
check("a toast explains what happens next", toastText.some((t) => /queued/i.test(t)), toastText.join(" | "));

r = await owner.call("POST", `/api/v1/webhooks/${endpointId}/redeliver/${original.id}`);
check("a second retry while it is in flight is refused with 409", r.status === 409, r.text);

// The sweeper sends it again (first tick at boot, then every 15 s).
for (let i = 0; i < 100 && captured.length < 1; i++) await wait(250);
check("the receiver gets the event a second time", captured.length === 1 && captured[0].event === "webhook.test_fired" || (captured.length === 1 && /test/.test(captured[0].event ?? "")), JSON.stringify(captured.map((c) => c.event)));
for (let i = 0; i < 20; i++) {
  list = (await owner.call("GET", `/api/v1/webhooks/${endpointId}/deliveries`)).json?.deliveries ?? [];
  if (list.find((d) => d.id === original.id)?.status === "delivered") break;
  await wait(250);
}
const after = list.find((d) => d.id === original.id);
check("the row ends delivered again", after?.status === "delivered", JSON.stringify(after));
r = await owner.call("GET", "/api/v1/audit?limit=20");
const auditEvents = (r.json?.entries ?? []).map((e) => e.event);
check("the retry is in the audit log", auditEvents.includes("webhook.delivery_redelivered"), auditEvents.join(","));
check("no script errors in the console", errors.length === 0, errors.join(" | "));

// A member: no button, and the API refuses.
const member = client();
const memberEmail = `redeliver-member-${nonce}@test.dev`;
r = await owner.call("POST", "/api/v1/members/invites", { email: memberEmail, role: "member" });
const inviteToken = (String(r.json?.invite?.acceptUrlDev ?? "").match(/token=([^&#]+)/) || [])[1];
if (inviteToken) {
  // Accepting with a password creates the member's account and signs it in.
  r = await member.call("POST", "/api/v1/members/invites/accept", { token: decodeURIComponent(inviteToken), email: memberEmail, password: "redeliver-member-password-1" });
  check("the member accepts the invite", r.status === 200 || r.status === 201, r.text);
  const me = await member.call("GET", "/api/v1/auth/me");
  const target = (me.json?.memberships ?? []).find((m) => m.role === "member");
  if (target && me.json?.org?.role !== "member") await member.call("POST", "/api/v1/auth/switch-org", { orgId: target.orgId ?? target.id });
  const meNow = await member.call("GET", "/api/v1/auth/me");
  check("the member is now acting in the owner's workspace as a member", meNow.json?.org?.role === "member", JSON.stringify(meNow.json?.org));
  // Members may not list webhooks at all (the API answers 403), so the
  // deliveries view, and with it the Retry button, is out of reach.
  r = await member.call("GET", "/api/v1/webhooks");
  check("a member cannot list webhooks, so never reaches the Retry button", r.status === 403, r.text);
  r = await member.call("POST", `/api/v1/webhooks/${endpointId}/redeliver/${original.id}`);
  check("the API refuses a member's retry", r.status === 403 || r.status === 404, r.text);
} else {
  console.log("SKIP member checks: the invite response carries no token in this mode");
}

await browser.close();
receiver.close();
console.log(fails ? `webhook-redeliver-drill: ${fails} FAILED` : `webhook-redeliver-drill: ${step} checks passed`);
process.exit(fails ? 1 : 0);
