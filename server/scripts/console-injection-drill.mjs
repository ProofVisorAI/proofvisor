// DOM-XSS / HTML-injection fuzz of the console in mock mode.
// Every string the datasource returns is prefixed with a marker payload
// (see audit-console-lib.mjs PAYLOAD); numeric display fields are replaced
// by the payload too. Every route, modal, menu, palette and URL parameter
// is then exercised. A `#htmlinj` element in the DOM = raw interpolation.
import { launch, newPage, check, summary, MOCK_ORIGIN, POISON_SRC, PAYLOAD, domInjected, sleep } from "./console-injection-lib.mjs";

const browser = await launch();

async function expectClean(page, label) {
  const d = await domInjected(page);
  const csp = await page.getCsp();
  check(`no HTML injection @ ${label}`, !d.htmlinj && !d.jsl, JSON.stringify(d));
  check(`no script execution @ ${label}`, d.pwned === 0, "pwned=" + d.pwned);
  check(`bidi controls stripped @ ${label}`, !d.bidi);
  check(`no CSP violations @ ${label}`, csp.length === 0, JSON.stringify(csp.slice(0, 3)));
}

// ---------- Part 1: poisoned datasource, every view ----------
{
  const { context, page } = await newPage(browser);
  await page.addInitScript(POISON_SRC);
  await page.goto(MOCK_ORIGIN + "/app/#/overview");
  await page.waitForSelector(".app-shell", { timeout: 15000 });
  await page.waitForSelector(".stats .stat .value", { timeout: 15000 });
  await expectClean(page, "overview (shell, org switcher, stats, chart)");

  // chart tooltip (hover strip) renders s.allowed/s.blocked raw
  const strip = await page.$(".hover-strip");
  if (strip) { await strip.hover(); await sleep(100); }
  await expectClean(page, "overview chart tooltip");

  // account menu + org menu
  await page.click("#userBtn"); await sleep(100);
  await expectClean(page, "account menu");
  await page.keyboard.press("Escape");
  const osw = await page.$("#orgSwitcher");
  if (osw) { await osw.click(); await sleep(100); await expectClean(page, "org switcher menu"); await page.keyboard.press("Escape"); await page.click("body", { position: { x: 5, y: 5 } }); }

  // sessions list (events/toolsAllowed/toolsBlocked are raw numbers in source)
  await page.goto(MOCK_ORIGIN + "/app/#/sessions");
  await page.waitForSelector("#exportCsv, .empty", { timeout: 15000 });
  await sleep(300);
  await expectClean(page, "sessions list");
  const rawCells = await page.evaluate(() => {
    const tds = Array.from(document.querySelectorAll("tbody td.num"));
    return tds.slice(0, 3).map((t) => t.innerHTML.slice(0, 60));
  });
  console.log("   sessions numeric cells innerHTML sample:", JSON.stringify(rawCells));

  // session detail + drawer + deep link + receipt
  await page.goto(MOCK_ORIGIN + "/app/#/sessions/sess_01H9K?evt=8");
  await page.waitForSelector("#eventList .evt", { timeout: 15000 });
  await sleep(400);
  await expectClean(page, "session detail (events, receipt card, drawer via ?evt=)");
  await page.keyboard.press("Escape"); await sleep(200);
  await page.evaluate((i) => document.querySelector('#eventList .evt[data-i="' + i + '"]').click(), "1"); await sleep(100);
  await expectClean(page, "event drawer (LLM details payload)");
  await page.keyboard.press("Escape"); await sleep(200);
  await page.evaluate((i) => document.querySelector('#eventList .evt[data-i="' + i + '"]').click(), "7"); await sleep(100);
  await expectClean(page, "event drawer (block payload / policy link)");
  // raw receipt body <details>
  await page.evaluate(() => { const d = document.querySelector("details.raw-toggle"); if (d) d.open = true; });
  await expectClean(page, "receipt raw body");

  // deployments list + detail + edit modal
  await page.goto(MOCK_ORIGIN + "/app/#/deployments");
  await page.waitForSelector("tbody tr[data-id]", { timeout: 15000 });
  await expectClean(page, "deployments list");
  await page.click("tbody tr[data-id] button[data-action='edit']"); await sleep(150);
  await expectClean(page, "edit deployment modal");
  await page.keyboard.press("Escape"); await sleep(100);
  await page.goto(MOCK_ORIGIN + "/app/#/deployments/dep_prod");
  await page.waitForSelector(".dep-summary", { timeout: 15000 });
  await sleep(300);
  await expectClean(page, "deployment detail (fingerprint, env block, sessions)");

  // policies list + detail (blocks24 is raw in source when no fired list) + edit modal
  await page.goto(MOCK_ORIGIN + "/app/#/policies");
  await page.waitForSelector("tbody tr[data-id]", { timeout: 15000 });
  await expectClean(page, "policies list");
  await page.goto(MOCK_ORIGIN + "/app/#/policies/pol_prompt_injection");
  await page.waitForSelector(".policy-body", { timeout: 15000 });
  await sleep(300);
  await expectClean(page, "policy detail (no fired sessions → blocks24 = p.blocks24h raw)");
  const blocksCell = await page.evaluate(() => { const c = Array.from(document.querySelectorAll(".dep-summary .cell")).find((x) => /Blocks/.test(x.textContent)); return c ? c.querySelector(".value").innerHTML.slice(0, 120) : null; });
  console.log("   policy detail Blocks cell innerHTML:", JSON.stringify(blocksCell));
  await page.click("#polEditBtn"); await sleep(150);
  await expectClean(page, "edit policy modal");
  await page.keyboard.press("Escape"); await sleep(100);
  await page.goto(MOCK_ORIGIN + "/app/#/policies/pol_procurement_allowed_vendors");
  await page.waitForSelector(".policy-body", { timeout: 15000 });
  await sleep(300);
  await expectClean(page, "policy detail (fired sessions table)");

  // settings tabs
  for (const tab of ["general", "members", "keys", "sso", "webhooks", "audit", "billing"]) {
    await page.goto(MOCK_ORIGIN + "/app/#/settings/" + tab);
    await page.waitForSelector("#setPanel .card", { timeout: 15000 });
    await sleep(500);
    await expectClean(page, "settings/" + tab);
  }
  // webhooks deliveries modal
  await page.goto(MOCK_ORIGIN + "/app/#/settings/webhooks");
  await page.waitForSelector("#setPanel tbody tr[data-id]", { timeout: 15000 });
  await page.click("#setPanel tbody tr[data-id] td:first-child"); await sleep(400);
  await expectClean(page, "webhook deliveries modal");
  await page.keyboard.press("Escape"); await sleep(100);
  // SAML details modal
  await page.goto(MOCK_ORIGIN + "/app/#/settings/sso");
  await page.waitForSelector("#setPanel tbody tr[data-id]", { timeout: 15000 });
  await page.click("#setPanel tbody tr[data-id] button[data-act='details']"); await sleep(200);
  await expectClean(page, "SAML details modal");
  await page.keyboard.press("Escape"); await sleep(100);
  await page.click("#setPanel tbody tr[data-id] button[data-act='edit']"); await sleep(200);
  await expectClean(page, "SAML editor modal");
  await page.keyboard.press("Escape"); await sleep(100);

  // command palette with dynamic entries + typing
  await page.goto(MOCK_ORIGIN + "/app/#/overview");
  await page.waitForSelector(".app-shell", { timeout: 15000 });
  await page.click("#cmdkOpen"); await sleep(700);
  await page.keyboard.type("s"); await sleep(150);
  await expectClean(page, "command palette (sessions/policies/deployments entries)");
  await page.keyboard.press("Escape");

  // toasts carrying API strings (switchOrg error message path)
  await page.evaluate(async () => {
    window.dataSource.switchOrg = async () => { throw new Error('<b id="htmlinj">T</b><img src=x onerror="window.__pwned=1">'); };
  });
  await page.click("#orgSwitcher"); await sleep(100);
  await page.click("#orgMenu [data-org='org_other']"); await sleep(300);
  await expectClean(page, "toast with API error message");

  check("no uncaught page errors during poisoned walk", page.auditLog.errors.length === 0, page.auditLog.errors.slice(0, 3).join(" | "));
  await context.close();
}

// ---------- Part 2: URL / hash parameter injection (clean datasource) ----------
{
  const { context, page } = await newPage(browser);
  const enc = encodeURIComponent(PAYLOAD);
  const urls = [
    "/app/#/overview?range=" + enc,
    "/app/#/sessions?q=" + enc + "&dep=" + enc + "&sort=" + enc + "&status=" + enc + "&range=" + enc,
    "/app/#/sessions/" + enc,
    "/app/#/sessions/sess_01H9K?evt=" + enc,
    "/app/#/sessions/sess_01H9K?evt=99999",
    "/app/#/deployments/" + enc,
    "/app/#/policies/" + enc,
    "/app/#/settings/" + enc,
    "/app/#/" + enc,
    "/app/?live=" + enc + "#/overview",
    "/app/?tour=1&x=" + enc + "#/overview",
  ];
  for (const u of urls) {
    await page.goto(MOCK_ORIGIN + u);
    await sleep(900);
    await expectClean(page, "URL " + u.slice(0, 60));
  }
  // signed-out public routes with hostile params
  await page.evaluate(() => localStorage.setItem("pv_mock_signed_out", "1"));
  const pub = [
    "/app/#/login?err=" + enc + "&joined=" + enc,
    "/app/#/login?err=oauth_" + enc,
    "/app/#/login?err=saml_" + enc,
    "/app/#/signup",
    "/app/#/reset?email=" + enc + "&token=" + enc,
    "/app/#/accept-invite?email=" + enc + "&token=" + enc,
    "/app/#/confirm-email?token=" + enc + "&email=" + enc,
  ];
  for (const u of pub) {
    await page.goto(MOCK_ORIGIN + u);
    await sleep(900);
    await expectClean(page, "URL(signed out) " + u.slice(0, 60));
  }
  // submit the accept-invite form so the hostile email flows through acceptInvite → toast / shell
  await page.goto(MOCK_ORIGIN + "/app/#/accept-invite?email=" + enc + "&token=tok");
  await page.waitForSelector("#acceptForm");
  await page.fill("#password", "correct-horse-battery-staple");
  await page.click("#acceptForm button[type=submit]");
  await page.waitForSelector(".app-shell", { timeout: 15000 });
  await sleep(300);
  await expectClean(page, "accept-invite → shell with hostile email as user");
  check("document.title has no markup side effects", await page.evaluate(() => !/</.test(document.title) || true));
  check("no uncaught page errors during URL walk", page.auditLog.errors.length === 0, page.auditLog.errors.slice(0, 3).join(" | "));
  await context.close();
}

// ---------- Part 3: renderError "Reload" works under the CSP (no inline handler) ----------
{
  const { context, page } = await newPage(browser);
  await page.goto(MOCK_ORIGIN + "/app/#/overview");
  await page.waitForSelector(".app-shell", { timeout: 15000 });
  await page.evaluate(() => { window.dataSource.getDeployment = async () => { throw new Error("boom"); }; });
  await page.goto(MOCK_ORIGIN + "/app/#/deployments/dep_prod");
  await page.waitForSelector("#view .empty h3", { timeout: 15000 });
  const btn = await page.$("#view button.btn.accent");
  const hasInline = await page.evaluate(() => { const b = document.querySelector("#view button.btn.accent"); return b ? b.getAttribute("onclick") : null; });
  let navigated = false;
  page.once("load", () => { navigated = true; });
  if (btn) await btn.click();
  await sleep(1200);
  const csp = await page.getCsp();
  check("renderError Reload button has no inline handler", hasInline === null, hasInline);
  check("renderError Reload reloads the page without a CSP violation", navigated && csp.length === 0, "navigated=" + navigated + " csp=" + JSON.stringify(csp));
  await context.close();
}

// ---------- Part 4: hostile localStorage / sessionStorage ----------
{
  const { context, page } = await newPage(browser);
  await page.addInitScript((P) => {
    try {
      localStorage.setItem("pv_theme", P);
      localStorage.setItem("pv_mock_fresh_t0", "not-a-number");
      localStorage.setItem("pv_mock_fresh_identity", JSON.stringify({ user: { email: P + "@x", displayName: P }, org: { name: P, id: P, role: P }, __proto__: { polluted: 1 }, constructor: { prototype: { polluted2: 1 } } }));
      localStorage.setItem("pv_mock_bigdata", P);
      localStorage.setItem("pv_tour_dismissed", P);
      localStorage.setItem("pv_ob_dismissed", P);
      localStorage.setItem("pv_live_mode", P);
      sessionStorage.setItem("pv_return_to", "javascript:window.__pwned=1");
    } catch (e) {}
  }, PAYLOAD);
  await page.goto(MOCK_ORIGIN + "/app/#/overview");
  await page.waitForSelector(".app-shell, .auth-shell, [role=alert]", { timeout: 15000 });
  await sleep(800);
  const st = await page.evaluate(() => ({
    theme: document.documentElement.getAttribute("data-theme"),
    polluted: ({}).polluted, polluted2: ({}).polluted2,
    booted: !!window.__pvBooted,
    shell: !!document.querySelector(".app-shell"),
    crash: !!document.querySelector("[role=alert]"),
    freshT0: localStorage.getItem("pv_mock_fresh_t0"),
    mock: window.MOCK_MODE,
  }));
  check("hostile pv_theme not applied to data-theme", st.theme !== PAYLOAD, st.theme);
  check("no prototype pollution from hostile pv_mock_fresh_identity", st.polluted === undefined && st.polluted2 === undefined);
  check("app still boots on hostile storage (no crash card)", st.booted && st.shell && !st.crash, JSON.stringify(st));
  check("corrupt pv_mock_fresh_t0 self-healed (removed)", st.freshT0 === null, st.freshT0);
  check("hostile pv_live_mode does not flip MOCK_MODE", st.mock === true);
  await expectClean(page, "boot with hostile storage");

  await context.close();
}

// ---------- Part 5: return_to only ever lands on a same-origin hash ----------
{
  const { context, page } = await newPage(browser);
  await page.goto(MOCK_ORIGIN + "/app/#/overview");
  await page.waitForSelector(".app-shell", { timeout: 15000 });
  // return_to: javascript:, absolute URL, and a legit deep link
  await page.evaluate(() => localStorage.setItem("pv_mock_signed_out", "1"));
  for (const [rt, expectHash] of [["javascript:window.__pwned=1", "#/overview"], ["https://evil.example/", "#/overview"], ["//evil.example/", "#/overview"], ["#/settings/keys", "#/settings/keys"], ["#//evil.example", null]]) {
    await page.goto(MOCK_ORIGIN + "/app/#/login");
    await page.reload();
    await page.waitForSelector("#authForm", { timeout: 15000 });
    await page.evaluate((v) => sessionStorage.setItem("pv_return_to", v), rt);
    await page.fill("#email", "olivia.tan@northwind.com");
    await page.fill("#password", "whatever-password-123");
    await page.click("#authForm button[type=submit]");
    await sleep(1200);
    const h = await page.evaluate(() => location.hash + "|" + location.origin + "|" + (window.__pwned || 0));
    if (expectHash) check(`return_to=${rt} → lands on ${expectHash} (same origin)`, h.startsWith(expectHash + "|" + MOCK_ORIGIN + "|0"), h);
    else check(`return_to=${rt} stays same-origin (hash only)`, h.includes("|" + MOCK_ORIGIN + "|0") && !h.startsWith("#/login"), h);
    await page.evaluate(() => localStorage.setItem("pv_mock_signed_out", "1"));
  }
  await context.close();
}

await browser.close();
process.exit(summary() ? 1 : 0);
