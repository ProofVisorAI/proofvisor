/**
 * Billing: plan status, Stripe Checkout / Customer Portal hand-offs,
 * and the Stripe webhook that moves an organisation between plans.
 *
 *   GET  /api/v1/billing            plan, status, limits, usage, configured
 *   POST /api/v1/billing/checkout   { plan } → { url }   (owner only)
 *   POST /api/v1/billing/portal     → { url }            (owner only)
 *   POST /api/v1/billing/webhook    Stripe → us; raw body, signature
 *                                   verified with STRIPE_WEBHOOK_SECRET,
 *                                   idempotent on the Stripe event id.
 *
 * Configuration is entirely env-driven (see env.ts STRIPE_*). When no
 * secret key is set the API says so plainly — `configured: false` and
 * 503 billing_not_configured — instead of pretending a flow exists.
 *
 * Handled events:
 *   checkout.session.completed      → plan from metadata, status active,
 *                                     store customer + subscription ids
 *   customer.subscription.updated   → plan from the price id, status
 *                                     from the subscription, renewal date
 *   customer.subscription.deleted   → plan free, status canceled
 *   invoice.payment_failed          → status past_due
 * Everything else is acknowledged and recorded but not acted on.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import Stripe from "stripe";
import { z } from "zod";
import { db } from "../db.js";
import { env } from "../env.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
import { allLimits, limitsEnforced, limitsFor, normalizePlan, planUsage, type Plan } from "../lib/entitlements.js";
import { requireSession } from "../lib/session-middleware.js";

type PaidPlan = "team" | "enterprise";

// -------------------------------------------------------------------
// Stripe client (lazy; absent when STRIPE_SECRET_KEY is unset)
// -------------------------------------------------------------------

let client: Stripe | null | undefined;

export function stripeClient(): Stripe | null {
  if (client !== undefined) return client;
  if (!env.STRIPE_SECRET_KEY) {
    client = null;
    return client;
  }
  const opts: Stripe.StripeConfig = { maxNetworkRetries: 1, timeout: 20_000 };
  if (env.STRIPE_API_BASE) {
    // Test hook: point the SDK at a local stand-in server.
    const u = new URL(env.STRIPE_API_BASE);
    opts.host = u.hostname;
    opts.port = Number(u.port || (u.protocol === "https:" ? 443 : 80));
    opts.protocol = u.protocol === "https:" ? "https" : "http";
  }
  client = new Stripe(env.STRIPE_SECRET_KEY, opts);
  return client;
}

export function billingConfigured(): boolean {
  return Boolean(env.STRIPE_SECRET_KEY);
}

function priceFor(plan: PaidPlan): string | undefined {
  return plan === "team" ? env.STRIPE_PRICE_TEAM_MONTHLY : env.STRIPE_PRICE_ENTERPRISE_MONTHLY;
}

function planForPrice(priceId: string | undefined): PaidPlan | null {
  if (!priceId) return null;
  if (priceId === env.STRIPE_PRICE_TEAM_MONTHLY) return "team";
  if (priceId === env.STRIPE_PRICE_ENTERPRISE_MONTHLY) return "enterprise";
  return null;
}

function notConfigured(reply: FastifyReply) {
  return reply.code(503).send({
    error: "billing_not_configured",
    detail:
      "Billing is not enabled on this instance: the operator has not set STRIPE_SECRET_KEY. " +
      "Plans can still be assigned by the operator directly in the database.",
  });
}

function appUrl(path: string): string {
  return env.APP_BASE_URL.replace(/\/$/, "") + path;
}

// -------------------------------------------------------------------
// Subscription → org state mapping
// -------------------------------------------------------------------

function statusFor(sub: Stripe.Subscription): string {
  switch (sub.status) {
    case "trialing":
      return "trialing";
    case "active":
      return "active";
    case "canceled":
    case "incomplete_expired":
      return "canceled";
    default:
      // past_due, unpaid, incomplete, paused
      return "past_due";
  }
}

function renewsAt(sub: Stripe.Subscription): Date | null {
  // API versions before 2025-03 carry current_period_end on the
  // subscription; newer ones on each item.
  const legacy = (sub as unknown as { current_period_end?: number }).current_period_end;
  const item = sub.items?.data?.[0] as unknown as { current_period_end?: number } | undefined;
  const ts = legacy ?? item?.current_period_end;
  return typeof ts === "number" && ts > 0 ? new Date(ts * 1000) : null;
}

function idOf(v: string | { id: string } | null | undefined): string | null {
  if (!v) return null;
  return typeof v === "string" ? v : v.id;
}

async function orgForSubscription(sub: Stripe.Subscription): Promise<{ id: string } | null> {
  const metaOrg = sub.metadata?.orgId;
  if (metaOrg) {
    const o = await db.org.findUnique({ where: { id: metaOrg }, select: { id: true } });
    if (o) return o;
  }
  const bySub = await db.org.findUnique({ where: { stripeSubscriptionId: sub.id }, select: { id: true } });
  if (bySub) return bySub;
  const customer = idOf(sub.customer as string | { id: string });
  if (customer) return db.org.findUnique({ where: { stripeCustomerId: customer }, select: { id: true } });
  return null;
}

type Tx = Parameters<Parameters<typeof db.$transaction>[0]>[0];

/** Apply one verified event. Returns the org it touched (for the audit row). */
async function applyEvent(tx: Tx, event: Stripe.Event, log: FastifyRequest["log"]): Promise<string | null> {
  switch (event.type) {
    case "checkout.session.completed":
    case "checkout.session.async_payment_succeeded": {
      const session = event.data.object as Stripe.Checkout.Session;
      // A delayed payment method (bank debit) completes the checkout
      // before the money arrives: payment_status is "unpaid" and Stripe
      // confirms later with checkout.session.async_payment_succeeded.
      // Upgrading on the first event would grant a plan nobody paid for.
      if (session.payment_status === "unpaid") {
        log.info({ eventId: event.id }, "billing_checkout_awaiting_payment");
        return null;
      }
      const orgId = session.metadata?.orgId ?? session.client_reference_id ?? null;
      const plan = session.metadata?.plan;
      if (!orgId || (plan !== "team" && plan !== "enterprise")) {
        log.warn({ eventId: event.id }, "billing_checkout_missing_metadata");
        return null;
      }
      const org = await tx.org.findUnique({ where: { id: orgId }, select: { id: true, plan: true } });
      if (!org) return null;
      const customer = idOf(session.customer as string | { id: string });
      const subscription = idOf(session.subscription as string | { id: string });
      let renew: Date | null = null;
      if (subscription) {
        try {
          const s = stripeClient();
          if (s) renew = renewsAt(await s.subscriptions.retrieve(subscription));
        } catch (err) {
          log.warn({ err, subscription }, "billing_subscription_lookup_failed");
        }
      }
      await tx.org.update({
        where: { id: orgId },
        data: {
          plan,
          planStatus: "active",
          ...(customer ? { stripeCustomerId: customer } : {}),
          ...(subscription ? { stripeSubscriptionId: subscription } : {}),
          ...(renew ? { planRenewsAt: renew } : {}),
        },
      });
      writeAudit({ orgId, event: "billing.plan_changed", actorId: "stripe", target: plan, metadata: { fromPlan: org.plan, toPlan: plan, via: event.type, eventId: event.id } }, log);
      return orgId;
    }
    case "customer.subscription.updated":
    case "customer.subscription.created": {
      const sub = event.data.object as Stripe.Subscription;
      const org = await orgForSubscription(sub);
      if (!org) {
        log.warn({ eventId: event.id, subscription: sub.id }, "billing_subscription_org_unknown");
        return null;
      }
      const priceId = sub.items?.data?.[0]?.price?.id;
      const plan = planForPrice(priceId) ?? (sub.metadata?.plan === "team" || sub.metadata?.plan === "enterprise" ? sub.metadata.plan : null);
      const status = statusFor(sub);
      const before = await tx.org.findUnique({ where: { id: org.id }, select: { plan: true, planStatus: true } });
      await tx.org.update({
        where: { id: org.id },
        data: {
          ...(plan && status !== "canceled" ? { plan } : {}),
          ...(status === "canceled" ? { plan: "free" } : {}),
          planStatus: status,
          stripeSubscriptionId: sub.id,
          ...(idOf(sub.customer as string | { id: string }) ? { stripeCustomerId: idOf(sub.customer as string | { id: string }) } : {}),
          planRenewsAt: status === "canceled" ? null : renewsAt(sub),
        },
      });
      writeAudit(
        {
          orgId: org.id,
          event: "billing.subscription_updated",
          actorId: "stripe",
          target: plan ?? before?.plan ?? "free",
          metadata: { fromPlan: before?.plan, toPlan: status === "canceled" ? "free" : plan ?? before?.plan, fromStatus: before?.planStatus, toStatus: status, eventId: event.id },
        },
        log,
      );
      return org.id;
    }
    case "customer.subscription.deleted": {
      const sub = event.data.object as Stripe.Subscription;
      const org = await orgForSubscription(sub);
      if (!org) return null;
      const before = await tx.org.findUnique({ where: { id: org.id }, select: { plan: true } });
      await tx.org.update({
        where: { id: org.id },
        data: { plan: "free", planStatus: "canceled", stripeSubscriptionId: null, planRenewsAt: null },
      });
      writeAudit({ orgId: org.id, event: "billing.plan_changed", actorId: "stripe", target: "free", metadata: { fromPlan: before?.plan, toPlan: "free", via: event.type, eventId: event.id } }, log);
      return org.id;
    }
    case "invoice.payment_failed": {
      const invoice = event.data.object as Stripe.Invoice;
      const customer = idOf(invoice.customer as string | { id: string });
      const legacySub = (invoice as unknown as { subscription?: string | { id: string } | null }).subscription;
      const parentSub = (invoice as unknown as { parent?: { subscription_details?: { subscription?: string | { id: string } } } }).parent
        ?.subscription_details?.subscription;
      const subscription = idOf(legacySub) ?? idOf(parentSub);
      const org =
        (customer ? await db.org.findUnique({ where: { stripeCustomerId: customer }, select: { id: true } }) : null) ??
        (subscription ? await db.org.findUnique({ where: { stripeSubscriptionId: subscription }, select: { id: true } }) : null);
      if (!org) {
        log.warn({ eventId: event.id, customer }, "billing_invoice_org_unknown");
        return null;
      }
      await tx.org.update({ where: { id: org.id }, data: { planStatus: "past_due" } });
      writeAudit({ orgId: org.id, event: "billing.payment_failed", actorId: "stripe", target: invoice.id ?? null, metadata: { eventId: event.id, amountDue: invoice.amount_due } }, log);
      return org.id;
    }
    default:
      return null;
  }
}

// -------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------

export async function billingRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const org = await db.org.findUnique({
      where: { id: claims.orgId },
      select: { plan: true, planStatus: true, planRenewsAt: true, stripeCustomerId: true, stripeSubscriptionId: true },
    });
    if (!org) return reply.code(404).send({ error: "not_found" });
    const plan = normalizePlan(org.plan);
    const usage = await planUsage(claims.orgId);
    return reply.send({
      configured: billingConfigured(),
      enforced: limitsEnforced(),
      plan,
      planStatus: org.planStatus,
      planRenewsAt: org.planRenewsAt,
      hasStripeCustomer: Boolean(org.stripeCustomerId),
      hasSubscription: Boolean(org.stripeSubscriptionId),
      limits: limitsFor(plan),
      usage,
      plans: allLimits(),
      // Which paid plans this instance can actually sell.
      purchasable: {
        team: billingConfigured() && Boolean(env.STRIPE_PRICE_TEAM_MONTHLY),
        enterprise: billingConfigured() && Boolean(env.STRIPE_PRICE_ENTERPRISE_MONTHLY),
      },
    });
  });

  app.post("/checkout", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") return reply.code(403).send({ error: "forbidden" });
    const body = z.object({ plan: z.enum(["team", "enterprise"]) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const stripe = stripeClient();
    if (!stripe) return notConfigured(reply);
    const price = priceFor(body.data.plan);
    if (!price) {
      return reply.code(503).send({
        error: "billing_not_configured",
        detail: `The ${body.data.plan} plan has no Stripe price configured on this instance (STRIPE_PRICE_${body.data.plan.toUpperCase()}_MONTHLY).`,
      });
    }
    const org = await db.org.findUnique({ where: { id: claims.orgId }, select: { id: true, name: true, plan: true, stripeCustomerId: true } });
    if (!org) return reply.code(404).send({ error: "not_found" });
    if (normalizePlan(org.plan) === body.data.plan) return reply.code(409).send({ error: "already_on_plan" });
    const actor = await resolveActor(claims.sub);

    let customerId = org.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({
        ...(actor.actorEmail ? { email: actor.actorEmail } : {}),
        name: org.name,
        metadata: { orgId: org.id },
      });
      customerId = customer.id;
      await db.org.update({ where: { id: org.id }, data: { stripeCustomerId: customerId } });
    }
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      client_reference_id: org.id,
      line_items: [{ price, quantity: 1 }],
      success_url: appUrl("/app/#/settings/billing?checkout=success"),
      cancel_url: appUrl("/app/#/settings/billing?checkout=cancel"),
      metadata: { orgId: org.id, plan: body.data.plan },
      subscription_data: { metadata: { orgId: org.id, plan: body.data.plan } },
      allow_promotion_codes: true,
    });
    writeAudit(
      { orgId: org.id, event: "billing.checkout_started", ...actor, target: body.data.plan, metadata: { checkoutSessionId: session.id, price }, req },
      req.log,
    );
    if (!session.url) return reply.code(502).send({ error: "checkout_url_missing" });
    return reply.send({ url: session.url, sessionId: session.id });
  });

  app.post("/portal", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") return reply.code(403).send({ error: "forbidden" });
    const stripe = stripeClient();
    if (!stripe) return notConfigured(reply);
    const org = await db.org.findUnique({ where: { id: claims.orgId }, select: { id: true, stripeCustomerId: true } });
    if (!org) return reply.code(404).send({ error: "not_found" });
    if (!org.stripeCustomerId) {
      return reply.code(409).send({
        error: "no_billing_customer",
        detail: "This workspace has never checked out, so there is no billing account to manage yet.",
      });
    }
    const session = await stripe.billingPortal.sessions.create({
      customer: org.stripeCustomerId,
      return_url: appUrl("/app/#/settings/billing"),
    });
    writeAudit(
      { orgId: org.id, event: "billing.portal_opened", ...(await resolveActor(claims.sub)), target: org.stripeCustomerId, req },
      req.log,
    );
    return reply.send({ url: session.url });
  });

  // Webhook lives in its own encapsulated scope so the JSON body
  // parser can be swapped for a raw-string parser: Stripe's signature
  // covers the exact bytes, and a re-serialised object would not match.
  await app.register(async (sub) => {
    sub.removeContentTypeParser("application/json");
    sub.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => done(null, body));
    sub.addContentTypeParser("*", { parseAs: "string" }, (_req, body, done) => done(null, body));

    sub.post("/webhook", async (req, reply) => {
      if (!env.STRIPE_WEBHOOK_SECRET) return notConfigured(reply);
      const stripe = stripeClient() ?? new Stripe("sk_unused_signature_verification_only");
      const sig = req.headers["stripe-signature"];
      const raw = typeof req.body === "string" ? req.body : "";
      if (typeof sig !== "string" || !raw) {
        return reply.code(400).send({ error: "missing_stripe_signature" });
      }
      let event: Stripe.Event;
      try {
        event = stripe.webhooks.constructEvent(raw, sig, env.STRIPE_WEBHOOK_SECRET);
      } catch (err) {
        req.log.warn({ err }, "billing_webhook_bad_signature");
        return reply.code(400).send({ error: "invalid_stripe_signature" });
      }
      try {
        await db.$transaction(async (tx) => {
          // The insert is the idempotency lock: a redelivered event id
          // violates the primary key and the whole transaction rolls
          // back before any plan change is applied.
          await tx.billingEvent.create({ data: { id: event.id, type: event.type } });
          const orgId = await applyEvent(tx, event, req.log);
          if (orgId) await tx.billingEvent.update({ where: { id: event.id }, data: { orgId } });
        });
      } catch (err) {
        // Only a repeated event id is a duplicate delivery. Any other
        // uniqueness conflict (say, a Stripe customer already linked to
        // another workspace) is a real failure: answering 200 would make
        // Stripe stop retrying and silently drop the plan change.
        const e = err as { code?: string; meta?: { modelName?: string; target?: unknown } };
        const target = Array.isArray(e.meta?.target) ? e.meta.target.join(",") : String(e.meta?.target ?? "");
        const duplicateEvent =
          e.code === "P2002" && (e.meta?.modelName === "BillingEvent" || /billing_events/.test(target));
        if (duplicateEvent) {
          return reply.send({ received: true, duplicate: true });
        }
        req.log.error({ err, eventId: event.id, type: event.type }, "billing_webhook_apply_failed");
        return reply.code(500).send({ error: "webhook_apply_failed" });
      }
      return reply.send({ received: true });
    });
  });
}

export type { Plan };
