// Shared helpers for console-injection-drill.mjs.
// Run from server/: SITE=http://127.0.0.1:<port>/ node scripts/console-injection-drill.mjs
import { chromium } from "playwright";

// The served docs/ folder (mock-mode console under /app/).
export const MOCK_ORIGIN = new URL(process.env.SITE || "http://127.0.0.1:8796/").origin;

// Marker-bearing payload. If `#htmlinj` ever appears in the DOM, raw HTML
// was interpolated (independent of whether CSP stopped the script).
export const PAYLOAD =
  '<b id="htmlinj">X</b><img src=x onerror="window.__pwned=(window.__pwned||0)+1">' +
  '<svg onload="window.__pwned=(window.__pwned||0)+1"></svg>' +
  '<a id="jsl" href="javascript:window.__pwned=1">j</a>"\' ‮evil` ${7*7}';

export const results = [];
export function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail == null ? "" : String(detail) });
  console.log((ok ? "PASS " : "FAIL ") + name + (detail != null ? "  — " + String(detail).slice(0, 300) : ""));
}
export function summary() {
  const fails = results.filter((r) => !r.ok);
  console.log("\n== " + results.length + " checks, " + fails.length + " failed ==");
  for (const f of fails) console.log("  FAIL: " + f.name + " — " + f.detail);
  return fails.length;
}

export async function launch() {
  const browser = await chromium.launch();
  return browser;
}

// New context + page with CSP-violation, console-error and pageerror capture.
export async function newPage(browser, opts = {}) {
  const context = await browser.newContext({ acceptDownloads: true, ...opts });
  const page = await context.newPage();
  const log = { csp: [], errors: [], console: [] };
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      window.__csp.push({ directive: e.violatedDirective, blocked: String(e.blockedURI).slice(0, 80), sample: String(e.sample || "").slice(0, 80) });
    });
  });
  page.on("pageerror", (e) => log.errors.push(String(e && e.message || e)));
  page.on("console", (m) => { if (m.type() === "error" || m.type() === "warning") log.console.push(m.text().slice(0, 300)); });
  page.getCsp = () => page.evaluate(() => window.__csp || []);
  page.auditLog = log;
  return { context, page };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Deep-walk a datasource result and poison display fields. Keys that drive
// routing / discriminators are kept intact so the app still navigates.
export const POISON_SRC = `
  (function () {
    var P = ${JSON.stringify(PAYLOAD)};
    var KEEP = new Set(["id","userId","orgId","deploymentId","sessionId","policyId","status","kind","severity",
      "role","format","type","enabled","isActive","jitEnabled","mfaEnrolled","hasSpKeypair","seq","nextCursor",
      "nextEventCursor","period","t","mode","cursor","requiresLogin","mfaRequired","accountDeleted","ok",
      "rawSignatureB64","publicKeyHex","webhookId","retroactive","receipt_version","key_id","public_key_b64"]);
    var NUMERIC_FUZZ = new Set(["events","toolsAllowed","toolsBlocked","blocks24h","hits24h","eventCount","attempt",
      "responseCode","sessions24h","allowed","blocked","sessions","deployments","deploymentsHealthy","credentialsRemoved",
      "receiptCount","promptTokens","blockedValueUsd","durationMs","sessionRetentionDays","auditRetentionDays"]);
    function poison(v, key, depth) {
      if (depth > 8 || v == null) return v;
      if (Array.isArray(v)) return v.map(function (x) { return poison(x, key, depth + 1); });
      if (typeof v === "object") {
        if (v instanceof Blob) return v;
        var out = {};
        Object.keys(v).forEach(function (k) {
          if (KEEP.has(k)) { out[k] = v[k]; return; }
          if (typeof v[k] === "number" && NUMERIC_FUZZ.has(k)) { out[k] = P; return; }
          out[k] = poison(v[k], k, depth + 1);
        });
        return out;
      }
      if (typeof v === "string") return P + v;
      return v;
    }
    var wrapped = null;
    Object.defineProperty(window, "dataSource", {
      configurable: true,
      get: function () { return wrapped; },
      set: function (ds) {
        wrapped = {};
        Object.keys(ds).forEach(function (k) {
          var f = ds[k];
          if (typeof f !== "function" || k === "subscribe" || k === "freshDaemonReady") { wrapped[k] = f; return; }
          wrapped[k] = async function () {
            var r = await f.apply(ds, arguments);
            if (k === "getSession" && r) {
              r = poison(r, k, 0);
              r.memberships = [
                { orgId: "org_northwind", name: P + "Northwind", role: "owner" },
                { orgId: "org_other", name: P + "Other Co", role: P + "admin" },
              ];
              return r;
            }
            return poison(r, k, 0);
          };
        });
        wrapped.mode = ds.mode;
      },
    });
  })();
`;

export async function domInjected(page) {
  return page.evaluate(() => ({
    htmlinj: !!document.getElementById("htmlinj"),
    jsl: !!document.getElementById("jsl"),
    pwned: window.__pwned || 0,
    bidi: /[‮‪-‭⁦-⁩]/.test(document.body.innerHTML),
    url: location.href,
  }));
}
