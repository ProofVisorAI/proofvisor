// Identity hardening contracts, against a real API process and Postgres:
//
//  * SAML discovery trusts only domains an organisation has PROVEN with a
//    DNS TXT record. A workspace owner typing another company's domain
//    into a SAML config must not be able to turn the login page into a
//    redirect to their own "identity provider".
//  * Accepting an invitation for an address that someone pre-registered
//    (unverified) resets that account instead of handing the attacker a
//    membership: new password, sessions fenced, API keys revoked.
//
// DNS is answered by a fixture file (PV_TEST_DNS_TXT_FILE), which the
// API only honours outside production.
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import { makeClient, signupOwner, startApi, uniqueEmail } from "./helpers/api-process.mjs";

let api;
let dnsFile;
before(async () => {
  dnsFile = path.join(await mkdtemp(path.join(tmpdir(), "pv-dns-")), "txt.json");
  await writeFile(dnsFile, "{}");
  api = await startApi({ PV_TEST_DNS_TXT_FILE: dnsFile, PLAN_LIMITS_ENFORCED: "false" });
});
after(async () => {
  await api?.stop();
});

const samlBody = (displayName, domains) => ({
  displayName,
  ssoUrl: "https://idp.example.test/sso",
  entityIdIdp: "https://idp.example.test/" + displayName,
  x509Cert:
    "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ8m3m4f3q4iK7g1bq4G1J5x9c2EwCgYIKoZIzj0EAwIw\nFTETMBEGA1UEAwwKZmFrZS1zYW1sMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAw\nMDAwMFowFTETMBEGA1UEAwwKZmFrZS1zYW1sMFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAE6mBd3Wn4N0kPZB8g7c1Hqz5n9Zf0S2jLw3L1kq3XqRxkFhQe1uQxW4wU\n6WbNqgqS6N9W3PYyJ1XGXQy5MxVUU6NTMFEwHQYDVR0OBBYEFO1l0Kk8s2c3H7n6\nL6m2YQ4dYd8IMB8GA1UdIwQYMBaAFO1l0Kk8s2c3H7n6L6m2YQ4dYd8IMA8GA1Ud\nEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKq7kq0b9V4f7cZl8mG2XWwE\nW9v7Qv8Vb1G0x0dZr2mFAiAx0p4uY2Zc3p1pQ9r5k3f1q4u8e9Y6hY2Zl0bQ6r1n\nvw==\n-----END CERTIFICATE-----\n",
  jitEnabled: true,
  jitDefaultRole: "member",
  allowedDomains: domains,
});

test("SAML discovery ignores a domain nobody has verified, even when a config claims it", async () => {
  const attacker = await signupOwner(api.base, "attacker");
  const victimDomain = `victim-${Date.now().toString(36)}.example`;
  const cfg = await attacker.client.json("POST", "/api/v1/auth/saml", samlBody("Phishing IdP", victimDomain));
  assert.equal(cfg.status, 201, JSON.stringify(cfg.data));

  const anon = makeClient(api.base);
  const found = await anon.json("GET", `/api/v1/auth/saml/discover?email=${encodeURIComponent("pat@" + victimDomain)}`);
  assert.equal(found.status, 200);
  assert.equal(found.data.ssoConfig, null, "an unverified domain claim must not steer sign-in");
});

test("a verified domain unlocks discovery for its organisation only, and cannot be claimed twice", async () => {
  const owner = await signupOwner(api.base, "domain-owner");
  const other = await signupOwner(api.base, "domain-other");
  const domain = `corp-${Date.now().toString(36)}.example`;

  // Members cannot read or write; admins read; owners write.
  const anon = makeClient(api.base);
  assert.equal((await anon.json("GET", "/api/v1/org/domains")).status, 401);

  const bad = await owner.client.json("POST", "/api/v1/org/domains", { domain: "not a domain" });
  assert.equal(bad.status, 400);
  assert.equal(bad.data.errorCode ?? bad.data.error, "invalid_domain");

  const added = await owner.client.json("POST", "/api/v1/org/domains", { domain: domain.toUpperCase() + "." });
  assert.equal(added.status, 201, JSON.stringify(added.data));
  assert.equal(added.data.domain.domain, domain, "domains are stored lowercase without a trailing dot");
  assert.equal(added.data.domain.verifiedAt, null);
  const record = added.data.domain.txtRecord;
  assert.equal(record.name, `_proofvisor-challenge.${domain}`);
  assert.match(record.value, /^proofvisor-domain-verification=[A-Za-z0-9_-]{20,}$/);

  // Another organisation cannot claim the same domain, verified or not.
  const dup = await other.client.json("POST", "/api/v1/org/domains", { domain });
  assert.equal(dup.status, 409);
  assert.equal(dup.data.errorCode ?? dup.data.error, "domain_claimed");

  // The config exists but the domain is only claimed: no discovery yet.
  const cfg = await owner.client.json("POST", "/api/v1/auth/saml", samlBody("Corp Okta", domain));
  assert.equal(cfg.status, 201, JSON.stringify(cfg.data));
  const email = encodeURIComponent("sam@" + domain);
  assert.equal((await anon.json("GET", `/api/v1/auth/saml/discover?email=${email}`)).data.ssoConfig, null);

  // Verification fails until the record is published...
  const notYet = await owner.client.json("POST", `/api/v1/org/domains/${added.data.domain.id}/verify`, {});
  assert.equal(notYet.status, 409);
  assert.equal(notYet.data.errorCode ?? notYet.data.error, "txt_record_not_found");

  // ...and a wrong value does not count.
  await writeFile(dnsFile, JSON.stringify({ [record.name]: ["proofvisor-domain-verification=wrong", "v=spf1 -all"] }));
  assert.equal((await owner.client.json("POST", `/api/v1/org/domains/${added.data.domain.id}/verify`, {})).status, 409);

  // The right record verifies it; the check is owner-only.
  await writeFile(dnsFile, JSON.stringify({ [record.name]: ["v=spf1 -all", record.value] }));
  assert.equal((await other.client.json("POST", `/api/v1/org/domains/${added.data.domain.id}/verify`, {})).status, 404, "another org cannot see or verify it");
  const ok = await owner.client.json("POST", `/api/v1/org/domains/${added.data.domain.id}/verify`, {});
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal(ok.data.verified, true);
  assert.ok(ok.data.domain.verifiedAt);

  // Now discovery sends that domain to this org's config, and only this domain.
  const found = await anon.json("GET", `/api/v1/auth/saml/discover?email=${email}`);
  assert.equal(found.data.ssoConfig?.id, cfg.data.config?.id ?? cfg.data.id, JSON.stringify(found.data));
  assert.equal(found.data.ssoConfig.displayName, "Corp Okta");
  const sibling = await anon.json("GET", `/api/v1/auth/saml/discover?email=${encodeURIComponent("sam@sub." + domain)}`);
  assert.equal(sibling.data.ssoConfig, null, "subdomains are separate claims");

  const listed = await owner.client.json("GET", "/api/v1/org/domains");
  assert.equal(listed.status, 200);
  assert.equal(listed.data.domains.length, 1);

  // Removing the domain switches discovery off again.
  assert.equal((await owner.client.json("DELETE", `/api/v1/org/domains/${added.data.domain.id}`)).status, 204);
  assert.equal((await anon.json("GET", `/api/v1/auth/saml/discover?email=${email}`)).data.ssoConfig, null);
});

test("accepting an invite for a pre-registered, unverified address resets that account", async () => {
  // The attacker registers the victim's address first.
  const victimEmail = uniqueEmail("victim");
  const attackerPassword = "attacker-chosen-password-1!";
  const attacker = makeClient(api.base);
  const reg = await attacker.json("POST", "/api/v1/auth/signup", { email: victimEmail, password: attackerPassword, orgName: "Squatter Org" });
  assert.equal(reg.status, 201, JSON.stringify(reg.data));
  const key = await attacker.json("POST", "/api/v1/keys", { name: "squat" });
  assert.equal(key.status, 201, JSON.stringify(key.data));

  // The real employer invites the victim.
  const employer = await signupOwner(api.base, "employer");
  const inv = await employer.client.json("POST", "/api/v1/members/invites", { email: victimEmail, role: "admin" });
  assert.equal(inv.status, 201, JSON.stringify(inv.data));
  const token = new URLSearchParams((inv.data.invite.acceptUrlDev.split("#/")[1] ?? "").split("?")[1] ?? "").get("token");
  assert.ok(token);

  // Accepting without a password is refused: the account is unverified.
  const victim = makeClient(api.base);
  const noPassword = await victim.json("POST", "/api/v1/members/invites/accept", { token, email: victimEmail });
  assert.equal(noPassword.status, 400);
  assert.equal(noPassword.data.errorCode ?? noPassword.data.error, "password_required_for_unverified_user");

  const victimPassword = "victim-new-password-2026!";
  const accepted = await victim.json("POST", "/api/v1/members/invites/accept", { token, email: victimEmail, password: victimPassword });
  assert.equal(accepted.status, 200, JSON.stringify(accepted.data));
  assert.equal(accepted.data.requiresLogin, true);
  assert.equal(accepted.data.passwordReset, true);
  assert.equal(accepted.data.org.role, "admin");

  // The attacker's password, session and API key are all dead.
  // Login answers wrong credentials with the uniform `{mfaRequired:true}`
  // shape and no session cookie (no account enumeration), so "no longer
  // works" means: no session was minted.
  const squatterAgain = makeClient(api.base);
  const oldLogin = await squatterAgain.json("POST", "/api/v1/auth/login", { email: victimEmail, password: attackerPassword });
  assert.equal(oldLogin.status, 200);
  assert.equal(oldLogin.data.mfaRequired, true, JSON.stringify(oldLogin.data));
  assert.equal(squatterAgain.cookie, null, "the squatter's password no longer mints a session");
  assert.equal((await squatterAgain.json("GET", "/api/v1/auth/me")).status, 401);
  assert.equal((await attacker.json("GET", "/api/v1/auth/me")).status, 401, "the squatter's session is fenced");
  const bearer = makeClient(api.base);
  bearer.bearer = key.data.plaintextToken;
  assert.ok(typeof bearer.bearer === "string" && bearer.bearer.startsWith("pv_srv_"), JSON.stringify(key.data));
  assert.equal((await bearer.json("GET", "/api/v1/auth/me")).status, 401, "the squatter's API key is revoked");

  // The invitee signs in with the password they just set and is a member.
  const login = await victim.json("POST", "/api/v1/auth/login", { email: victimEmail, password: victimPassword });
  assert.equal(login.status, 200, JSON.stringify(login.data));
  assert.ok(victim.cookie, "the invitee's new password mints a session");
  const me = await victim.json("GET", "/api/v1/auth/me");
  assert.equal(me.status, 200, JSON.stringify(me.data));
});
