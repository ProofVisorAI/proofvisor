// The offline receipt verifier at the path the console, the /verify/ page
// and the README name (`node tools/verify-receipt.mjs receipt.json`).
// The public tool snapshot copies server/scripts/verify-receipt.mjs here;
// in the monorepo this file forwards to that same script, so the
// documented command works from either checkout.
import "../server/scripts/verify-receipt.mjs";
