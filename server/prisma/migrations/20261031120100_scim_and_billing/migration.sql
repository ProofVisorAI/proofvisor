-- SCIM 2.0 provisioning + plan billing.

ALTER TABLE "users" ADD COLUMN "scimExternalId" TEXT;

ALTER TABLE "memberships" ADD COLUMN "active" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "memberships" ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "orgs" ADD COLUMN "plan" TEXT NOT NULL DEFAULT 'free';
ALTER TABLE "orgs" ADD COLUMN "planStatus" TEXT NOT NULL DEFAULT 'active';
ALTER TABLE "orgs" ADD COLUMN "stripeCustomerId" TEXT;
ALTER TABLE "orgs" ADD COLUMN "stripeSubscriptionId" TEXT;
ALTER TABLE "orgs" ADD COLUMN "planRenewsAt" TIMESTAMP(3);
ALTER TABLE "orgs" ADD COLUMN "scimEnabled" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "orgs" ADD COLUMN "scimDefaultRole" TEXT NOT NULL DEFAULT 'member';
ALTER TABLE "orgs" ADD COLUMN "scimDeprovisionAction" TEXT NOT NULL DEFAULT 'deactivate';

CREATE UNIQUE INDEX "orgs_stripeCustomerId_key" ON "orgs"("stripeCustomerId");
CREATE UNIQUE INDEX "orgs_stripeSubscriptionId_key" ON "orgs"("stripeSubscriptionId");

CREATE TABLE "scim_tokens" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "tokenHint" TEXT NOT NULL,
    "createdById" TEXT,
    "createdByEmail" TEXT,
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    CONSTRAINT "scim_tokens_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "scim_tokens_orgId_idx" ON "scim_tokens"("orgId");
CREATE INDEX "scim_tokens_tokenHint_idx" ON "scim_tokens"("tokenHint");
ALTER TABLE "scim_tokens" ADD CONSTRAINT "scim_tokens_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "scim_groups" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "externalId" TEXT,
    "role" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "scim_groups_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "scim_groups_orgId_displayName_key" ON "scim_groups"("orgId", "displayName");
CREATE INDEX "scim_groups_orgId_idx" ON "scim_groups"("orgId");
ALTER TABLE "scim_groups" ADD CONSTRAINT "scim_groups_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "scim_group_members" (
    "groupId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "scim_group_members_pkey" PRIMARY KEY ("groupId", "userId")
);
CREATE INDEX "scim_group_members_userId_idx" ON "scim_group_members"("userId");
ALTER TABLE "scim_group_members" ADD CONSTRAINT "scim_group_members_groupId_fkey"
    FOREIGN KEY ("groupId") REFERENCES "scim_groups"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "scim_group_members" ADD CONSTRAINT "scim_group_members_userId_fkey"
    FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "billing_events" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "orgId" TEXT,
    "processedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "billing_events_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "billing_events_orgId_processedAt_idx" ON "billing_events"("orgId", "processedAt");
ALTER TABLE "billing_events" ADD CONSTRAINT "billing_events_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE SET NULL ON UPDATE CASCADE;
