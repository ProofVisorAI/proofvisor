# Product console (client-side simulation)

A self-contained, clickable simulation of the product's main steps: setup
wizard (the real wizard runs in the terminal as `pvctl setup`), one-line
integration, a live
session (including an $8,400 prompt-injection payout refused at the door), the
fleet overview, signed-receipt verification, and the evidence layout on disk.

It is a client-side simulation with representative data — there is no backend
and no network call; it works offline from a `file://` URL. Numbers, sessions,
and signatures shown are illustrative. The receipt fields, 403 policy
refusals, loop breaker and spool layout follow the real Rust implementation,
but the page is not a complete copy of the product.

- **Published at:** <https://proofvisor.com/app/pitch/> (deployed by
  `.github/workflows/pages.yml` together with the landing page).
- **Run locally / offline:** open `index.html` in any browser.
- **Presenter tour:** append `?tour=1` to the URL to reveal the
  **▶ Guided tour** button — a captioned, self-advancing walkthrough
  (~80 seconds). Without the parameter the page shows pure product chrome.
- **Reset:** the ↻ button in the top bar returns everything to a first-run
  state (useful between viewers).
- **Scripted recordings:** the page exposes `window.pvConsole`
  (`play(speed)`, `setSpeed(s)`, `goTo(step)`, `reset()`, `isPlaying()`),
  which is how the walkthrough video is captured with Playwright.
