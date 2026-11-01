-- Verified email domains. Anonymous SAML discovery only consults
-- domains an organisation has proven with a DNS TXT record.
CREATE TABLE "org_domains" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "org_domains_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "org_domains_domain_key" ON "org_domains"("domain");
CREATE INDEX "org_domains_orgId_idx" ON "org_domains"("orgId");
ALTER TABLE "org_domains" ADD CONSTRAINT "org_domains_orgId_fkey"
    FOREIGN KEY ("orgId") REFERENCES "orgs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
