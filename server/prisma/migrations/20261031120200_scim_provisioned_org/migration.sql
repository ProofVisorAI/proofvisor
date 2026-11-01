-- Which organisation's SCIM endpoint created an account (null for every
-- other way an account is made). Gates SCIM email changes and re-attach.
ALTER TABLE "users" ADD COLUMN "scimProvisionedOrgId" TEXT;
