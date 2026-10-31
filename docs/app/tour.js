/* ProofVisor console — guided flow tour.
 *
 * A spotlight walkthrough that carries a first-time visitor (an
 * investor, not an engineer) through the exact loop the pitch videos
 * show: money kept → the session that kept it → the moment the bad
 * payment was blocked → the signed receipt → the public verifier.
 *
 * Runs in both modes. In mock mode it narrates the Northwind fixtures
 * (six fixed steps). In live mode it builds its steps from the
 * workspace's real data through window.dataSource: the most recent
 * blocked session stands in for the fixture, and a step whose target
 * does not exist (no blocked call, no receipt yet, no sessions at all)
 * is left out, so the counter is always honest.
 *
 * Self-contained on purpose: it drives the app only through
 * location.hash and DOM selectors, so app.js stays untouched except
 * for the palette entries that call window.PVTour.start().
 */
(function () {
  "use strict";

  var DISMISS_KEY = "pv_tour_dismissed";
  var MOCK = !!window.MOCK_MODE;

  var MOCK_STEPS = [
    {
      route: "#/overview",
      waitFor: ".stat.savings",
      target: ".stat.savings",
      title: "Start with the money",
      body: "Northwind's AI agents order stock and pay invoices on their own. " +
        "This is what ProofVisor kept from leaving the building: <b>$31,840</b> " +
        "in payments that policy stopped before any money moved.",
    },
    {
      route: "#/overview",
      waitFor: ".stat.blocks",
      target: ".stat.blocks",
      title: "Every tool call is checked first",
      body: "Agents don't touch money or systems directly — every tool call " +
        "passes through ProofVisor's policy engine. Most are allowed. " +
        "The dangerous ones end up here.",
    },
    {
      route: "#/sessions",
      waitFor: 'tr[data-id="sess_01H9K"]',
      target: 'tr[data-id="sess_01H9K"]',
      title: "Every run becomes a session",
      body: "Each agent run is recorded end to end. This one is the story: " +
        "the <b>supply-planner</b> agent was tricked into paying a fake " +
        "vendor <b>$8,400</b> — and got blocked. Let's open it.",
    },
    {
      route: "#/sessions/sess_01H9K",
      waitFor: ".evt.err",
      target: ".evt.err",
      title: "The exact moment it was stopped",
      body: "Event #8: the agent tried <code>create_purchase_order</code> for a " +
        "vendor not on the approved list. Blocked in 6&nbsp;ms, before the " +
        "money moved. The safe retry with an approved vendor went through.",
    },
    {
      route: "#/sessions/sess_01H9K",
      waitFor: ".receipt-card",
      target: ".receipt-card",
      title: "Sealed into a signed receipt",
      body: "The whole session — every prompt, tool call, and block — is " +
        "sealed under a <b>tamper-evident cryptographic signature</b>. " +
        "Change one byte and the signature breaks. This is the audit " +
        "trail you hand to an auditor.",
    },
    {
      route: "#/sessions/sess_01H9K",
      waitFor: "#dlRcpt",
      target: null, // centered finale
      title: "Don't trust us — verify it",
      body: "Download this receipt and drop it into our public verifier. " +
        "It checks the real cryptography in your browser — green tick, " +
        "no account, works offline. And when you're back: hit " +
        "<b>⚡ Simulate an attack</b> on the Overview to watch a live " +
        "block happen in front of you.",
      cta: { label: "Open the verifier ↗", href: "../verify/", blank: true },
    },
  ];

  function escHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* Live mode: pick the session that tells the story (the most recent
   * one with a blocked tool call, else the most recent one) and build
   * only the steps whose targets exist. */
  async function liveSteps() {
    var ds = window.dataSource;
    var sessions = [];
    try {
      var r = ds && typeof ds.listSessions === "function" ? await ds.listSessions({ limit: 50 }) : null;
      sessions = (r && r.sessions) || [];
    } catch (e) { sessions = []; }
    var blocked = sessions.filter(function (s) { return (s.toolsBlocked || 0) > 0; });
    var pick = blocked[0] || sessions[0] || null;
    var money = pick && pick.toolsBlocked > 0
      ? "$" + Math.round((parseInt(pick.blockedPayoutUsdMicros, 10) || 0) / 1e6).toLocaleString()
      : null;
    var steps = [
      {
        route: "#/overview",
        waitFor: ".stat.savings",
        target: ".stat.savings",
        title: "Start with the money",
        body: "Your agents call tools and move money on their own. This card is " +
          "what ProofVisor kept from leaving the building: the value of payments " +
          "that policy stopped before any money moved.",
      },
      {
        route: "#/overview",
        waitFor: ".stat.blocks",
        target: ".stat.blocks",
        title: "Every tool call is checked first",
        body: "Agents don't touch money or systems directly — every tool call " +
          "passes through ProofVisor's policy engine. Most are allowed. " +
          "The dangerous ones end up here.",
      },
    ];
    if (pick) {
      var rowSel = 'tr[data-id="' + pick.id + '"]';
      steps.push({
        route: "#/sessions",
        waitFor: rowSel,
        target: rowSel,
        title: "Every run becomes a session",
        body: "Each agent run is recorded end to end. " +
          (pick.toolsBlocked > 0
            ? "This one is the story: the <b>" + escHtml(pick.agent) + "</b> agent had " +
              pick.toolsBlocked + " tool call" + (pick.toolsBlocked === 1 ? "" : "s") + " blocked" +
              (money && money !== "$0" ? " — <b>" + escHtml(money) + "</b> kept" : "") + ". Let's open it."
            : "This is the most recent run of <b>" + escHtml(pick.agent) + "</b>. Let's open it."),
      });
      if (pick.toolsBlocked > 0) {
        steps.push({
          route: "#/sessions/" + pick.id,
          waitFor: ".evt.err",
          target: ".evt.err",
          optional: true,
          title: "The exact moment it was stopped",
          body: "This is the blocked tool call: the policy that refused it and " +
            "what it would have cost are recorded right here, before the money moved.",
        });
      }
      if (pick.status === "completed") {
        steps.push({
          route: "#/sessions/" + pick.id,
          waitFor: ".receipt-card",
          target: ".receipt-card",
          optional: true,
          title: "Sealed into a signed receipt",
          body: "The whole session — every prompt, tool call, and block — is " +
            "sealed under a <b>tamper-evident cryptographic signature</b>. " +
            "Change one byte and the signature breaks. This is the audit " +
            "trail you hand to an auditor.",
        });
      }
      steps.push({
        route: "#/sessions/" + pick.id,
        waitFor: "#dlRcpt",
        target: null,
        title: "Don't trust us — verify it",
        body: (pick.status === "completed"
          ? "Download this receipt and drop it into our public verifier. "
          : "Once a session seals, download its receipt and drop it into our public verifier. ") +
          "It checks the real cryptography in your browser — green tick, " +
          "no account, works offline. A shared verify link also names the " +
          "deployment, so the verifier can confirm the key the console pinned for it. " +
          "Back on the Overview, <b>⚡ Simulate an attack</b> stages a blocked payment you can watch live.",
        cta: { label: "Open the verifier ↗", href: "../verify/", blank: true },
      });
    } else {
      steps.push({
        route: "#/overview",
        waitFor: ".stat.savings",
        target: null,
        title: "Nothing recorded yet",
        body: "No sessions have reached this workspace. Register a deployment, start " +
          "<code>pvctl console-sync --watch --pull-policies</code> on the host that runs your agent — " +
          "or press <b>⚡ Simulate an attack</b> on this page to stage a blocked payment, " +
          "signed with the public demo key, and run this tour again.",
      });
    }
    return steps;
  }

  var STEPS = MOCK_STEPS;
  var state = { i: -1, overlay: null, pollTimer: null, reposition: null };

  function el(html) {
    var t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }

  function freshMode() {
    try { return !!localStorage.getItem("pv_mock_fresh_t0"); } catch (e) { return false; }
  }
  function inShell() { return !!document.querySelector(".app-shell"); }

  /* ── Launcher pill ─────────────────────────────────────────── */

  function ensureLauncher() {
    var existing = document.getElementById("pvTourLauncher");
    var want = inShell() && state.i < 0 && !dismissed() && !freshMode();
    if (want && !existing) {
      var pill = el(
        '<div id="pvTourLauncher" role="complementary" aria-label="Guided tour">' +
          '<button type="button" id="pvTourStart">▶&nbsp; See the full flow</button>' +
          '<button type="button" id="pvTourDismiss" aria-label="Dismiss guided tour">✕</button>' +
        "</div>"
      );
      document.body.appendChild(pill);
      pill.querySelector("#pvTourStart").addEventListener("click", function () { start(); });
      pill.querySelector("#pvTourDismiss").addEventListener("click", function () {
        try { localStorage.setItem(DISMISS_KEY, "1"); } catch (e) {}
        pill.remove();
      });
    } else if (!want && existing) {
      existing.remove();
    }
  }
  function dismissed() {
    try { return localStorage.getItem(DISMISS_KEY) === "1"; } catch (e) { return false; }
  }

  /* ── Spotlight engine ──────────────────────────────────────── */

  function buildOverlay() {
    var o = el(
      '<div id="pvTour" aria-live="polite">' +
        '<div class="pv-tour-hole" aria-hidden="true"></div>' +
        '<div class="pv-tour-card" role="dialog" aria-modal="false">' +
          '<div class="pv-tour-step"></div>' +
          '<h3></h3>' +
          '<p></p>' +
          '<div class="pv-tour-actions">' +
            '<button type="button" class="pv-tour-skip">Skip tour</button>' +
            '<span class="pv-tour-spacer"></span>' +
            '<button type="button" class="pv-tour-back">Back</button>' +
            '<button type="button" class="pv-tour-next">Next</button>' +
          "</div>" +
        "</div>" +
      "</div>"
    );
    o.querySelector(".pv-tour-skip").addEventListener("click", stop);
    o.querySelector(".pv-tour-back").addEventListener("click", function () { go(state.i - 1); });
    o.querySelector(".pv-tour-next").addEventListener("click", function () {
      if (state.i >= STEPS.length - 1) stop();
      else go(state.i + 1);
    });
    document.addEventListener("keydown", onKey);
    return o;
  }

  function onKey(e) {
    if (state.i < 0) return;
    if (e.key === "Escape") { e.preventDefault(); stop(); }
    if (e.key === "ArrowRight" || e.key === "Enter") {
      if (e.target && /INPUT|TEXTAREA/.test(e.target.tagName)) return;
      e.preventDefault();
      if (state.i >= STEPS.length - 1) stop(); else go(state.i + 1);
    }
    if (e.key === "ArrowLeft") { e.preventDefault(); if (state.i > 0) go(state.i - 1); }
  }

  function positionAround(target, step) {
    var hole = state.overlay.querySelector(".pv-tour-hole");
    var card = state.overlay.querySelector(".pv-tour-card");
    if (!target) {
      hole.style.display = "none";
      card.classList.add("centered");
      card.style.left = "";
      card.style.top = "";
      return;
    }
    card.classList.remove("centered");
    var r = target.getBoundingClientRect();
    var pad = 8;
    // Clamp the spotlight to the viewport: targets inside horizontal
    // scrollers (session rows on phones) can be wider than the screen,
    // and the ring's right edge should stay visible.
    var hLeft = Math.max(4, r.left - pad);
    var hWidth = Math.min(r.width + pad * 2, window.innerWidth - hLeft - 4);
    hole.style.display = "block";
    hole.style.left = hLeft + "px";
    hole.style.top = (r.top - pad) + "px";
    hole.style.width = hWidth + "px";
    hole.style.height = (r.height + pad * 2) + "px";

    // Card below the target when there's room, above otherwise;
    // clamped to the viewport (including viewports narrower than the card).
    var cw = Math.min(380, window.innerWidth - 24), chGuess = 210, gap = 14;
    var left = Math.min(Math.max(12, r.left), Math.max(12, window.innerWidth - cw - 12));
    var top = r.bottom + gap;
    if (top + chGuess > window.innerHeight - 12) top = Math.max(12, r.top - chGuess - gap);
    card.style.width = cw + "px";
    card.style.left = left + "px";
    card.style.top = top + "px";
    // The height guess undershoots on narrow screens (more line wraps
    // → taller card: 261px real vs 210 guessed at 280px, hanging the
    // actions below the fold). Re-clamp with the REAL laid-out height.
    var ch = card.offsetHeight || chGuess;
    if (top + ch > window.innerHeight - 12) {
      top = Math.max(12, window.innerHeight - ch - 12);
      card.style.top = top + "px";
    }
  }

  function waitFor(selector, timeoutMs) {
    return new Promise(function (resolve) {
      var t0 = Date.now();
      (function poll() {
        var n = document.querySelector(selector);
        if (n) return resolve(n);
        if (Date.now() - t0 > (timeoutMs || 6000)) return resolve(null);
        state.pollTimer = setTimeout(poll, 120);
      })();
    });
  }

  async function go(i, dir) {
    if (i < 0 || i >= STEPS.length) return;
    clearTimeout(state.pollTimer);
    var from = state.i;
    state.i = i;
    var step = STEPS[i];
    ensureLauncher();

    if (location.hash !== step.route) {
      location.hash = step.route;
      // hashchange dispatches asynchronously: without this yield the
      // first waitFor() poll runs against the OUTGOING view and can
      // anchor to a same-selector element there (the overview's copy
      // of the session row), which the incoming route's skeleton then
      // destroys — leaving the spotlight on a stale rect for as long
      // as the data takes to load. Invisible on fast networks; obvious
      // on venue WiFi.
      await new Promise(function (r) { setTimeout(r, 80); });
      if (state.i !== i) return; // user moved on during the yield
    }
    var anchor = await waitFor(step.waitFor, step.optional ? 4000 : 6000);
    if (state.i !== i) return; // user skipped ahead while we were waiting
    // Live data can change under the tour (a receipt still pending, a
    // session purged): skip an optional step whose target never
    // appeared, in the direction the user was travelling.
    if (!anchor && step.optional) {
      var next = (dir || (i >= from ? 1 : -1)) > 0 ? i + 1 : i - 1;
      if (next < 0 || next >= STEPS.length) { stop(); return; }
      return go(next, dir || (i >= from ? 1 : -1));
    }

    var card = state.overlay.querySelector(".pv-tour-card");
    card.querySelector(".pv-tour-step").textContent = "Step " + (i + 1) + " of " + STEPS.length;
    card.querySelector("h3").textContent = step.title;
    card.querySelector("p").innerHTML = step.body;

    var back = card.querySelector(".pv-tour-back");
    var next = card.querySelector(".pv-tour-next");
    back.style.visibility = i === 0 ? "hidden" : "visible";
    if (step.cta) {
      next.innerHTML = step.cta.label;
      next.onclick = function () {
        window.open(step.cta.href, step.cta.blank ? "_blank" : "_self", "noopener");
        stop();
      };
    } else {
      next.textContent = i === STEPS.length - 1 ? "Finish" : "Next";
      next.onclick = null;
    }

    var target = step.target ? (document.querySelector(step.target) || anchor) : null;
    if (target && target.scrollIntoView) {
      var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      target.scrollIntoView({ block: "center", behavior: reduced ? "auto" : "smooth" });
    }

    // Wait one frame for the scroll to start, then track the target so
    // the spotlight follows smooth-scrolling and window resizes.
    positionAround(target, step);
    if (state.reposition) { window.removeEventListener("resize", state.reposition); clearInterval(state.repositionTimer); }
    state.reposition = function () { if (state.i === i) positionAround(step.target ? document.querySelector(step.target) : null, step); };
    window.addEventListener("resize", state.reposition);
    state.repositionTimer = setInterval(state.reposition, 250);
  }

  var starting = false;
  async function start() {
    if (state.i >= 0 || starting) return;
    if (!inShell()) { // signed out → the tour makes no sense; go sign in first
      location.hash = "#/overview";
    }
    if (!state.overlay) {
      state.overlay = buildOverlay();
      document.body.appendChild(state.overlay);
    }
    starting = true;
    try {
      STEPS = MOCK ? MOCK_STEPS : await liveSteps();
    } finally { starting = false; }
    state.overlay.style.display = "block";
    go(0, 1);
  }

  function stop() {
    clearTimeout(state.pollTimer);
    clearInterval(state.repositionTimer);
    if (state.reposition) window.removeEventListener("resize", state.reposition);
    state.reposition = null;
    if (state.overlay) state.overlay.style.display = "none";
    state.i = -1;
    ensureLauncher();
  }

  window.PVTour = { start: start, stop: stop };

  /* ── Boot ──────────────────────────────────────────────────── */

  window.addEventListener("hashchange", function () { setTimeout(ensureLauncher, 50); });
  var boot = setInterval(function () {
    ensureLauncher();
    if (inShell()) {
      // ?tour=1 deep link (used by the landing page CTA) auto-starts once.
      // Once per TAB (sessionStorage): the param survives reloads, and
      // re-opening a tour the user already finished/escaped on every
      // refresh was hostile. A fresh visit/tab still auto-starts.
      var autoDone = false;
      try { autoDone = sessionStorage.getItem("pv_tour_autostarted") === "1"; } catch (e) {}
      if (/[?&]tour=1/.test(location.search) && state.i < 0 && !state._autoStarted && !autoDone && !dismissed() && !freshMode()) {
        state._autoStarted = true;
        try { sessionStorage.setItem("pv_tour_autostarted", "1"); } catch (e) {}
        setTimeout(start, 600);
      }
      clearInterval(boot);
      setInterval(ensureLauncher, 1200);
    }
  }, 300);
})();
