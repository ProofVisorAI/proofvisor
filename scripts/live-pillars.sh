#!/usr/bin/env bash
# Live identity, backend credentials, token exchange, revocation, and receipts.
# Build first: cargo build --release -p pv-harness --bin proofvisord \
#   -p pv-cli --bin pvctl --features pv-harness/redis,pv-cli/redis
# Usage: scripts/live-pillars.sh [--redis redis://127.0.0.1:6379]
# Override PROOFVISORD, PVCTL, PV_LIVE_TMPDIR, or PV_KEEP_TMP=1 as needed.
# Python owns cleanup even when startup fails or the script receives a signal.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$REPO_ROOT/scripts/live-pillars-helper.py" run "$@"
