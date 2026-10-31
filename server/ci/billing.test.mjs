// Billing and plan entitlements against a running API and a local
// stand-in for Stripe (ci/helpers/fake-stripe.mjs). No Stripe account
// or network is used: STRIPE_API_BASE points the official SDK at the
// fake, and webhooks are signed with the same scheme the SDK verifies.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

import { DATABASE_URL, makeClient, provisionMember, signupOwner, startApi } from "./helpers/api-process.mjs";
import { signStripeEvent, startFakeStripe, stripeEvent } from "./helpers/fake-stripe.mjs";

const { Client } = pg;
const WEBHOOK_SECRET = "whsec_ci_fixture_secret";
const PRICE_TEAM = "price_team_ci";
const PRICE_ENTERPRISE = "price_enterprise_ci";

let stripe;
let api;
let plain;
let db;
before(async () => {
  stripe = await startFakeStripe();
  api = await startApi({
    STRIPE_SECRET_KEY: "sk_test_ci_fixture",
    STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET,
    STRIPE_PRICE_TEAM_MONTHLY: PRICE_TEAM,
    STRIPE_PRICE_ENTERPRISE_MONTHLY: PRICE_ENTERPRISE,
    STRIPE_API_BASE: stripe.base,
    PLAN_LIMITS_ENFORCED: "true",
  });
  // A second instance with no billing configuration at all: the default.
  plain = await startApi();
  db = new Client({ connectionString: DATABASE_URL });
  await db.connect();
});
after(async () => {
  await db?.end();
  await api?.stop();
  await plain?.stop();
  await stripe?.stop();
});

async function webhook(event, { secret = WEBHOOK_SECRET, signature } = {}) {
  const payload = JSON.stringify(event);
  const res = await fetch(api.base + "/api/v1/billing/webhook", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signature ?? signStripeEvent(payload, secret) },
    body: payload,
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

async function orgRow(orgId) {
  const r = await db.query('SELECT plan, "planStatus", "stripeCustomerId", "stripeSubscriptionId" FROM orgs WHERE id = $1', [orgId]);
  return r.rows[0];
}

const owners = new Map();
async function owner(tag) {
  if (!owners.has(tag)) owners.set(tag, await signupOwner(api.base, tag));
  return owners.get(tag);
}

test("without Stripe configured nothing is gated and checkout says so plainly", async () => {
  const o = await signupOwner(plain.base, "plain");
  const billing = await o.client.json("GET", "/api/v1/billing");
  assert.equal(billing.status, 200);
  assert.equal(billing.data.configured, false);
  assert.equal(billing.data.enforced, false);
  assert.equal(billing.data.plan, "free");
  const checkout = await o.client.json("POST", "/api/v1/billing/checkout", { plan: "team" });
  assert.equal(checkout.status, 503);
  assert.match(JSON.stringify(checkout.data), /billing_not_configured/);
  // Limits are off: a free workspace may create more than the free caps.
  for (let i = 0; i < 3; i++) {
    const dep = await o.client.json("POST", "/api/v1/deployments", { name: `plain-${i}`, environment: "production" });
    assert.equal(dep.status, 201, JSON.stringify(dep.data));
  }
});

test("free-plan limits answer 402 naming the limit and the plan that lifts it", async () => {
  const o = await owner("limits");
  for (let i = 0; i < 2; i++) {
    const dep = await o.client.json("POST", "/api/v1/deployments", { name: `free-${i}`, environment: "production" });
    assert.equal(dep.status, 201, JSON.stringify(dep.data));
  }
  const third = await o.client.json("POST", "/api/v1/deployments", { name: "free-2", environment: "production" });
  assert.equal(third.status, 402, JSON.stringify(third.data));
  assert.equal(third.data.errorCode, "plan_limit_reached");
  assert.equal(third.data.limit, "deployments");
  assert.equal(third.data.upgradeTo, "team");
  const billing = await o.client.json("GET", "/api/v1/billing");
  assert.equal(billing.data.enforced, true);
  assert.equal(billing.data.usage.deployments, 2);
  assert.equal(billing.data.limits.deployments, 2);
  assert.deepEqual(billing.data.purchasable, { team: true, enterprise: true });
});

test("checkout is owner-only and sends the right price and metadata", async () => {
  const o = await owner("checkout");
  const member = await provisionMember(api.base, o, "admin", "admin");
  const refused = await member.client.json("POST", "/api/v1/billing/checkout", { plan: "team" });
  assert.equal(refused.status, 403);
  const bad = await o.client.json("POST", "/api/v1/billing/checkout", { plan: "platinum" });
  assert.equal(bad.status, 400);
  const before = stripe.requests.length;
  const checkout = await o.client.json("POST", "/api/v1/billing/checkout", { plan: "team" });
  assert.equal(checkout.status, 200, JSON.stringify(checkout.data));
  assert.match(checkout.data.url, /^https:\/\/checkout\.stripe\.test\/pay\//);
  const sent = stripe.requests.slice(before);
  const customer = sent.find((r) => r.path === "/v1/customers");
  assert.equal(customer.form["metadata[orgId]"], o.org.id);
  const session = sent.find((r) => r.path === "/v1/checkout/sessions");
  assert.equal(session.form["line_items[0][price]"], PRICE_TEAM);
  assert.equal(session.form.mode, "subscription");
  assert.equal(session.form["metadata[orgId]"], o.org.id);
  assert.equal(session.form["metadata[plan]"], "team");
  assert.equal(session.form.client_reference_id, o.org.id);
  const portal = await o.client.json("POST", "/api/v1/billing/portal");
  assert.equal(portal.status, 200, JSON.stringify(portal.data));
  assert.match(portal.data.url, /^https:\/\/billing\.stripe\.test\/session\//);
});

test("webhooks: bad signatures are refused, upgrades apply once, unpaid checkouts wait", async () => {
  const o = await owner("webhook");
  // Stripe ids are unique; the database keeps rows from earlier runs.
  const run = Date.now().toString(36);
  const cus = "cus_hook_" + run;
  const sub = "sub_hook_" + run;
  const completed = stripeEvent("checkout.session.completed", {
    id: "cs_x", object: "checkout.session", mode: "subscription", payment_status: "paid",
    customer: cus, subscription: sub, client_reference_id: o.org.id,
    metadata: { orgId: o.org.id, plan: "team" },
  });
  assert.equal((await webhook(completed, { secret: "whsec_wrong" })).status, 400);
  assert.equal((await webhook(completed, { signature: "t=1,v1=00" })).status, 400);
  assert.equal((await orgRow(o.org.id)).plan, "free");

  const unpaid = stripeEvent("checkout.session.completed", {
    id: "cs_y", object: "checkout.session", mode: "subscription", payment_status: "unpaid",
    customer: cus, subscription: sub, metadata: { orgId: o.org.id, plan: "team" },
  });
  assert.equal((await webhook(unpaid)).status, 200);
  assert.equal((await orgRow(o.org.id)).plan, "free", "an unpaid checkout grants nothing yet");

  const first = await webhook(completed);
  assert.equal(first.status, 200, JSON.stringify(first.data));
  let row = await orgRow(o.org.id);
  assert.equal(row.plan, "team");
  assert.equal(row.planStatus, "active");
  assert.equal(row.stripeCustomerId, cus);
  assert.equal(row.stripeSubscriptionId, sub);
  const again = await webhook(completed);
  assert.equal(again.status, 200);
  assert.equal(again.data.duplicate, true, "a redelivered event id is ignored");

  // The team plan lifts the deployment cap.
  for (let i = 0; i < 3; i++) {
    const dep = await o.client.json("POST", "/api/v1/deployments", { name: `team-${i}`, environment: "production" });
    assert.equal(dep.status, 201, JSON.stringify(dep.data));
  }

  const failed = stripeEvent("invoice.payment_failed", {
    id: "in_1", object: "invoice", customer: cus, subscription: sub, amount_due: 9900,
  });
  assert.equal((await webhook(failed)).status, 200);
  row = await orgRow(o.org.id);
  assert.equal(row.planStatus, "past_due");

  const canceled = stripeEvent("customer.subscription.deleted", {
    id: sub, object: "subscription", customer: cus, status: "canceled", metadata: { orgId: o.org.id },
    items: { object: "list", data: [{ id: "si", object: "subscription_item", price: { id: PRICE_TEAM } }] },
  });
  assert.equal((await webhook(canceled)).status, 200);
  row = await orgRow(o.org.id);
  assert.equal(row.plan, "free");
  // Existing deployments stay; new ones are refused again.
  const over = await o.client.json("POST", "/api/v1/deployments", { name: "after-cancel", environment: "production" });
  assert.equal(over.status, 402);
  const deps = await o.client.json("GET", "/api/v1/deployments");
  assert.equal(deps.data.deployments.length, 3, "a downgrade never deletes what the workspace already has");
});

test("a member cannot read or change billing beyond the plan summary", async () => {
  const o = await owner("checkout");
  const member = await provisionMember(api.base, o, "member", "member");
  const read = await member.client.json("GET", "/api/v1/billing");
  assert.equal(read.status, 200);
  const portal = await member.client.json("POST", "/api/v1/billing/portal");
  assert.equal(portal.status, 403);
  const anonymous = makeClient(api.base);
  assert.equal((await anonymous.json("GET", "/api/v1/billing")).status, 401);
});

test("a conflicting customer id is a failure Stripe retries, not a silent duplicate", async () => {
  const a = await owner("conflict-a");
  const b = await owner("conflict-b");
  const cus = "cus_shared_" + Date.now().toString(36);
  await db.query('UPDATE orgs SET "stripeCustomerId" = $1 WHERE id = $2', [cus, a.org.id]);
  const event = stripeEvent("checkout.session.completed", {
    id: "cs_conflict", object: "checkout.session", mode: "subscription", payment_status: "paid",
    customer: cus, subscription: null, metadata: { orgId: b.org.id, plan: "team" },
  });
  const res = await webhook(event);
  assert.equal(res.status, 500, JSON.stringify(res.data));
  assert.equal((await orgRow(b.org.id)).plan, "free");
  // Nothing was recorded, so Stripe's retry is processed, not skipped.
  await db.query('UPDATE orgs SET "stripeCustomerId" = NULL WHERE id = $1', [a.org.id]);
  const retry = await webhook(event);
  assert.equal(retry.status, 200, JSON.stringify(retry.data));
  assert.notEqual(retry.data.duplicate, true);
  assert.equal((await orgRow(b.org.id)).plan, "team");
});
