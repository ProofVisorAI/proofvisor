import type { SessionClaims } from "./lib/auth.js";

declare module "fastify" {
  interface FastifyRequest {
    session?: SessionClaims;
    orgIpAllowlist?: string[];
    /** Tenant resolved from a `pv_scim_` bearer token on /scim/v2 (routes/scim.ts). */
    scim?: {
      orgId: string;
      tokenId: string;
      defaultRole: "member" | "admin";
      deprovisionAction: "deactivate" | "remove";
      plan: string;
    };
  }
}
