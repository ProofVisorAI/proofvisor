/**
 * Unauthenticated, read-only lookups the public /verify page uses.
 *
 *   GET /api/v1/public/receipt-keys/:deploymentId
 *     → { deploymentId, deploymentName, publicKeyHex, publicKeyB64,
 *         keyId, pinnedAt, orgName }   or 404 not_found
 *
 * This is the receipt trust anchor: the console pins a deployment's
 * Ed25519 public key the first time its daemon checks in
 * (deployment.pubkey_first_set) and refuses silent rotation afterwards.
 * A shared verify link carries `&deployment=<id>&api=<origin>`, and the
 * verifier compares the receipt's embedded key with the pinned one, so
 * "signature verifies" becomes "signed by the key the console pinned
 * for deployment X". Nothing else about the deployment or org is
 * exposed; deployment ids are unguessable cuids; the route is rate
 * limited and answers CORS GETs from any origin (the verifier page is a
 * static site on another host).
 */

import type { FastifyInstance } from "fastify";
import { createHash } from "node:crypto";
import { z } from "zod";
import { db } from "../db.js";

export async function publicRoutes(app: FastifyInstance): Promise<void> {
  app.get(
    "/receipt-keys/:deploymentId",
    {
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
    },
    async (req, reply) => {
      // CORS for any origin: a read of public key material. The global
      // @fastify/cors plugin only reflects allow-listed console origins
      // and adds Allow-Credentials; override both for this response.
      // Also relax helmet's same-site CORP so a cross-origin fetch may
      // read the body.
      reply.header("Access-Control-Allow-Origin", "*");
      reply.removeHeader("Access-Control-Allow-Credentials");
      reply.header("Vary", "Origin");
      reply.header("Cross-Origin-Resource-Policy", "cross-origin");
      // Public and cacheable for a short while: the pinned key never
      // changes silently, and the verifier tolerates a stale answer.
      reply.header("Cache-Control", "public, max-age=300");

      const params = z
        .object({ deploymentId: z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/) })
        .safeParse(req.params);
      if (!params.success) return reply.code(404).send({ error: "not_found" });
      const dep = await db.deployment.findUnique({
        where: { id: params.data.deploymentId },
        select: {
          id: true,
          name: true,
          publicKeyHex: true,
          createdAt: true,
          org: { select: { name: true } },
        },
      });
      if (!dep || !dep.publicKeyHex) return reply.code(404).send({ error: "not_found" });
      const keyBytes = Buffer.from(dep.publicKeyHex, "hex");
      // derive_key_id(pubkey): first 32 hex chars of SHA-256(pubkey),
      // matching crates/pv-receipts and the ingest receipt check.
      const keyId = createHash("sha256").update(keyBytes).digest("hex").slice(0, 32);
      // When the key was pinned: the first-set audit entry for this
      // deployment; the deployment's creation time when the trail was
      // trimmed by audit retention.
      const pinned = await db.auditEntry.findFirst({
        where: {
          event: "deployment.pubkey_first_set",
          metadata: { path: ["deploymentId"], equals: dep.id },
        },
        orderBy: { at: "asc" },
        select: { at: true },
      });
      return reply.send({
        deploymentId: dep.id,
        deploymentName: dep.name,
        publicKeyHex: dep.publicKeyHex,
        publicKeyB64: keyBytes.toString("base64"),
        keyId,
        pinnedAt: (pinned?.at ?? dep.createdAt).toISOString(),
        orgName: dep.org.name,
      });
    },
  );
}
