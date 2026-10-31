// A stand-in for api.stripe.com, just large enough for the official
// `stripe` SDK to complete the calls routes/billing.ts makes:
//   POST /v1/customers, POST /v1/checkout/sessions,
//   POST /v1/billing_portal/sessions, GET /v1/subscriptions/:id
// Every request is recorded (method, path, parsed form body) so a test
// can assert on the price id and metadata the API sent. Also exports
// `signStripeEvent`, which produces the `Stripe-Signature` header the
// SDK's constructEvent verifies (t=<unix>,v1=<hmac sha256 of
// "<t>.<payload>">).

import { createHmac } from "node:crypto";
import { createServer } from "node:http";

export function parseForm(text) {
  // Stripe's SDK sends application/x-www-form-urlencoded with
  // bracketed nesting (line_items[0][price]=…). Keep the flat keys.
  const out = {};
  for (const [k, v] of new URLSearchParams(text)) out[k] = v;
  return out;
}

export async function startFakeStripe({ port = 0, subscription = {} } = {}) {
  const requests = [];
  let seq = 0;
  const state = {
    subscriptions: new Map(),
  };
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const url = new URL(req.url, "http://stripe.local");
      const form = parseForm(body);
      requests.push({ method: req.method, path: url.pathname, form, headers: req.headers });
      const send = (status, obj) => {
        res.writeHead(status, { "Content-Type": "application/json", "Request-Id": "req_fake_" + ++seq });
        res.end(JSON.stringify(obj));
      };
      if (req.method === "POST" && url.pathname === "/v1/customers") {
        const id = "cus_fake_" + ++seq;
        return send(200, { id, object: "customer", email: form.email ?? null, name: form.name ?? null, metadata: { orgId: form["metadata[orgId]"] } });
      }
      if (req.method === "POST" && url.pathname === "/v1/checkout/sessions") {
        const id = "cs_fake_" + ++seq;
        return send(200, {
          id,
          object: "checkout.session",
          mode: form.mode,
          customer: form.customer,
          url: `https://checkout.stripe.test/pay/${id}`,
          metadata: { orgId: form["metadata[orgId]"], plan: form["metadata[plan]"] },
        });
      }
      if (req.method === "POST" && url.pathname === "/v1/billing_portal/sessions") {
        const id = "bps_fake_" + ++seq;
        return send(200, { id, object: "billing_portal.session", customer: form.customer, url: `https://billing.stripe.test/session/${id}` });
      }
      const subMatch = /^\/v1\/subscriptions\/([^/]+)$/.exec(url.pathname);
      if (req.method === "GET" && subMatch) {
        const id = subMatch[1];
        const sub = state.subscriptions.get(id) ?? {
          id,
          object: "subscription",
          status: "active",
          customer: "cus_fake_unknown",
          current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
          items: { object: "list", data: [{ id: "si_fake", object: "subscription_item", price: { id: "price_unknown" } }] },
          metadata: {},
          ...subscription,
        };
        return send(200, sub);
      }
      send(404, { error: { type: "invalid_request_error", message: `fake stripe: no route ${req.method} ${url.pathname}` } });
    });
  });
  await new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const actualPort = server.address().port;
  return {
    base: `http://127.0.0.1:${actualPort}`,
    port: actualPort,
    requests,
    setSubscription(id, obj) { state.subscriptions.set(id, obj); },
    async stop() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

/** Stripe-Signature header for `payload` (a string) under `secret`. */
export function signStripeEvent(payload, secret, timestamp = Math.floor(Date.now() / 1000)) {
  const v1 = createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
  return `t=${timestamp},v1=${v1}`;
}

let evtSeq = 0;
/** Build a Stripe-shaped event envelope around `object`. */
export function stripeEvent(type, object, id = `evt_fake_${Date.now().toString(36)}_${++evtSeq}`) {
  return {
    id,
    object: "event",
    api_version: "2026-01-01",
    created: Math.floor(Date.now() / 1000),
    type,
    livemode: false,
    pending_webhooks: 1,
    request: { id: null, idempotency_key: null },
    data: { object },
  };
}
