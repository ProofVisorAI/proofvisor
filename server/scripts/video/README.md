# Investor mockup video pipeline

Reproducible walkthrough of the ProofVisor console for the pitch, about
29 seconds long (the five-scene v21 cut; the published copy is
`docs/pitch/pitch.mp4`). Renders against the live site at https://proofvisor.com so it
always reflects what an investor visiting the URL would see.

## Requirements

* Node 20+ with `playwright` installed (already a devDependency of the
  `server/` workspace).
* `ffmpeg` on `PATH` (Homebrew: `brew install ffmpeg`).
* macOS: uses `/System/Library/Fonts/Supplemental/Arial Bold.ttf` for
  burned-in captions. On Linux, edit `compose.sh` to point at any
  installed TTF (Fira Sans / DejaVu Sans / Inter).

## Regenerate

```sh
# From server/ so playwright resolves.
cd server
node scripts/video/record-scenes.mjs   # ~90s, writes /tmp/video-v4/scenes/*.webm
bash scripts/video/build-audio.sh       # ~5s,  writes /tmp/video-v4/audio/soundtrack-44s.aac
bash scripts/video/build-ambience.sh     # ~1s,  writes /tmp/video-v4/audio/ambience-46s.wav
bash scripts/video/build-narration.sh    # ~15s, writes /tmp/video-v4/audio/narration-44s.aac (requires macOS `say`)
bash scripts/video/compose.sh           # ~90s, writes 3 cuts (silent, whoosh, narrated)
bash scripts/video/compose-teaser.sh    # ~30s, writes /tmp/video-v4/proofvisor-mockup-teaser.mp4
```

Result:

* `proofvisor-mockup-v21-distilled.mp4` — about 29 s @ 1920×1080 H.264, narration + subtle whoosh. **Definitive pitch cut.** (The audio file names still carry the old "44s" length.)
* `proofvisor-mockup-v9-audio.mp4` — same visuals, subtle whoosh only (social autoplay).
* `proofvisor-mockup-v4.mp4` — same visuals, silent (safe fallback).
* `proofvisor-mockup-teaser.mp4` — 12s social cut.

## The full novice tour

The longer film on the pitch page (`docs/pitch/tour.mp4`, about 127 s)
comes from the scripts in `tour/`: `record-tour.mjs` records the scenes
to `/tmp/video-tour/scenes/`, the three `build-*-tour.sh` scripts write
the audio to `/tmp/video-tour/audio/`, and `compose-tour.sh` stitches
the scenes with captions into `/tmp/video-tour/proofvisor-mockup-v20-tour.mp4`.

## Uploading to GitHub for a shareable URL

```sh
FILE=/tmp/video-v4/proofvisor-mockup-v4.mp4
NAME='proofvisor-mockup-final.mp4'
REPO_ID="$(gh api repos/ProofVisorAI/proofvisor --jq .id)"
curl --fail-with-body -sS -X POST \
  "https://uploads.github.com/user-attachments/assets" \
  --url-query "name=$NAME" \
  --url-query "content_type=video/mp4" \
  --url-query "repository_id=$REPO_ID" \
  -H "Content-Type: application/octet-stream" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -H "Authorization: Bearer $(gh auth token)" \
  --data-binary "@$FILE" | jq -r .url
```

## Storyboard

See `STORYBOARD.md` for the full narrative arc and design decisions.

## When to re-record

* SPA visual changes (any change to `docs/app/styles.css` or the
  overview/session-detail rendering).
* Landing page hero copy changes (affects verify page background).
* Trust-anchor list changes (would break the green sample-verify
  scene 6).
