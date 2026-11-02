# ProofVisor — Investor Mockup Video Storyboard
# Duration: ~29 seconds (v21 distilled cut, five scenes). Target: 30-second understanding.
# Timings below follow the published film's captions (docs/pitch/pitch.vtt).

## THE PITCH (in one line)
"AI agents make real decisions. When one costs $8,400, you need a receipt."

## Narrative arc (Kishotenketsu — set up, expand, twist, land)

┌─────────────────────────────────────────────────────────────────────────┐
│ 00:00 - 00:05  TITLE CARD — the problem                                 │
│                "One wrong decision. $8,400 gone."                        │
│                "A buying agent, tricked into paying a fake vendor.       │
│                No way to prove what happened." Red accent on $8,400.     │
├─────────────────────────────────────────────────────────────────────────┤
│ 00:05 - 00:10  CONSOLE OVERVIEW — the value                              │
│                Camera lands on the $31,840 saved figure.                 │
│                Caption: "ProofVisor watches every AI agent. $31,840      │
│                saved from blocked orders."                               │
├─────────────────────────────────────────────────────────────────────────┤
│ 00:10 - 00:18  SESSION DETAIL — the mechanism                            │
│                The blocked $8,400 order, signed.                         │
│                Caption: "Unapproved vendor: blocked, signed. The safe    │
│                retry went through."                                      │
├─────────────────────────────────────────────────────────────────────────┤
│ 00:18 - 00:24  /verify PAGE — the proof                                  │
│                The receipt verifies in the browser.                      │
│                Caption: "Verified in the browser. No account."           │
├─────────────────────────────────────────────────────────────────────────┤
│ 00:24 - 00:29  CLOSING CARD                                              │
│                "AI agents you can hand to an auditor."                   │
│                "proofvisor.com"                                          │
└─────────────────────────────────────────────────────────────────────────┘

## Design decisions

* Title cards use system-ui sans, letter-spacing -0.02em, weight 800.
* Brand navy #0a5c8b for primary, #b53a1b for the "$8,400 problem"
  accent, #1a7c3b for the verified state.
* Every scene has ONE thing to look at. No multi-panel dashboards.
* Camera moves are slow crossfades (400ms) between scenes.
* Captions overlay bottom-center, bold, 60% opacity black background.
* Two audio variants ship alongside a silent fallback: the definitive
  cut (`v21-distilled.mp4`) carries narration + subtle whoosh, the
  social cut (`v9-audio.mp4`) carries whoosh only, and the safe
  fallback (`v4.mp4`) is silent. The visual arc is designed to read
  fully without audio because investors watch muted ~90% of the time.
