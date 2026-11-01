// SCIM 2.0 provisioning contract, against a real API process + Postgres.
//
//   DATABASE_URL=postgresql://pv:pv@localhost:5433/pvdb node --test ci/scim.test.mjs
//
// Covers: discovery endpoints, bearer auth, plan gating of the owner
// controls, filter + pagination, create/update/patch/delete, deactivate
// blocking login, last-owner protection, group → role mapping, token
// revocation, cross-tenant isolation, malformed PATCH → invalidSyntax.

import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { Client } from "pg";
import { DATABASE_URL, makeClient, provisionMember, signupOwner, startApi } from "./helpers/api-process.mjs";

const SCIM_CT = "application/scim+json";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

let api;
let pg;
before(async () => {
  // Plan gating is opt-in (PLAN_LIMITS_ENFORCED) and needs Stripe configured;
  // the key is a placeholder, no Stripe call is made by these tests.
  api = await startApi({ PLAN_LIMITS_ENFORCED: "true", STRIPE_SECRET_KEY: "sk_test_scim_fixture" });
  pg = new Client({ connectionString: DATABASE_URL });
  await pg.connect();
});
after(async () => {
  await pg?.end();
  await api?.stop();
});

async function setPlan(orgId, plan) {
  await pg.query('UPDATE "orgs" SET "plan" = $1 WHERE "id" = $2', [plan, orgId]);
}

/**
 * Owner upgrades to team, enables SCIM, mints a token; returns an IdP
 * client. Memoised per tag: /signup is capped at 5 per minute per IP,
 * so the file provisions five organisations in total and the tests
 * share them where isolation is not the point.
 */
const tenants = new Map();
async function tenant(tag = "tenant") {
  if (tenants.has(tag)) return tenants.get(tag);
  const t = await freshTenant(tag);
  tenants.set(tag, t);
  return t;
}
async function freshTenant(tag) {
  const owner = await signupOwner(api.base, tag);
  await setPlan(owner.org.id, "team");
  const enabled = await owner.client.json("PATCH", "/api/v1/scim/settings", { enabled: true });
  assert.equal(enabled.status, 200, JSON.stringify(enabled.data));
  const tok = await owner.client.json("POST", "/api/v1/scim/tokens", { name: "Okta" });
  assert.equal(tok.status, 201, JSON.stringify(tok.data));
  const idp = makeClient(api.base);
  idp.bearer = tok.data.plaintextToken;
  return { owner, idp, tokenId: tok.data.token.id, plaintext: tok.data.plaintextToken };
}

const scimHeaders = { "Content-Type": SCIM_CT };
const patch = (ops) => ({ schemas: [PATCH_SCHEMA], Operations: ops });

test("discovery endpoints answer without a token and describe Users + Groups", async () => {
  const anon = makeClient(api.base);
  const spc = await anon.json("GET", "/scim/v2/ServiceProviderConfig");
  assert.equal(spc.status, 200);
  assert.match(spc.headers.get("content-type"), /application\/scim\+json/);
  assert.equal(spc.data.patch.supported, true);
  assert.equal(spc.data.filter.supported, true);
  assert.equal(spc.data.authenticationSchemes[0].type, "oauthbearertoken");

  const rt = await anon.json("GET", "/scim/v2/ResourceTypes");
  assert.deepEqual(rt.data.Resources.map((r) => r.id).sort(), ["Group", "User"]);
  assert.equal(rt.data.Resources.find((r) => r.id === "User").endpoint, "/Users");

  const schemas = await anon.json("GET", "/scim/v2/Schemas");
  assert.equal(schemas.data.totalResults, 2);
  const userSchema = await anon.json("GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User");
  assert.equal(userSchema.status, 200);
  assert.ok(userSchema.data.attributes.some((a) => a.name === "userName" && a.required));

  const users = await anon.json("GET", "/scim/v2/Users");
  assert.equal(users.status, 401);
  assert.equal(users.data.status, "401");
  assert.deepEqual(users.data.schemas, ["urn:ietf:params:scim:api:messages:2.0:Error"]);
  assert.match(users.headers.get("www-authenticate"), /Bearer/);
});

let gateTenant = null; // reused by the revocation test below
test("owner controls are plan-gated and owner-only; a minted token has the documented shape", async () => {
  const owner = await signupOwner(api.base, "gate");
  const settings = await owner.client.json("GET", "/api/v1/scim/settings");
  assert.equal(settings.status, 200);
  assert.equal(settings.data.settings.enabled, false);
  assert.equal(settings.data.settings.planAllows, false);
  assert.equal(settings.data.settings.baseUrl, api.base + "/scim/v2");

  const enableFree = await owner.client.json("PATCH", "/api/v1/scim/settings", { enabled: true });
  assert.equal(enableFree.status, 402);
  assert.equal(enableFree.data.errorCode, "plan_limit_reached");
  assert.equal(enableFree.data.limit, "scim");
  assert.equal(enableFree.data.upgradeTo, "team");
  assert.match(enableFree.data.detail, /team plan/);
  const tokenFree = await owner.client.json("POST", "/api/v1/scim/tokens", { name: "x" });
  assert.equal(tokenFree.status, 402);

  // Non-owner never sees the controls.
  const admin = await provisionMember(api.base, owner, "admin", "gateadmin");
  const adminList = await admin.client.json("GET", "/api/v1/scim/tokens");
  assert.equal(adminList.status, 403);
  const adminSettings = await admin.client.json("PATCH", "/api/v1/scim/settings", { defaultRole: "admin" });
  assert.equal(adminSettings.status, 403);

  await setPlan(owner.org.id, "team");
  const enabled = await owner.client.json("PATCH", "/api/v1/scim/settings", { enabled: true, defaultRole: "admin", deprovisionAction: "remove" });
  assert.equal(enabled.status, 200);
  assert.deepEqual(
    [enabled.data.settings.enabled, enabled.data.settings.defaultRole, enabled.data.settings.deprovisionAction],
    [true, "admin", "remove"],
  );
  const bad = await owner.client.json("PATCH", "/api/v1/scim/settings", { deprovisionAction: "obliterate" });
  assert.equal(bad.status, 400);

  const tok = await owner.client.json("POST", "/api/v1/scim/tokens", { name: "Okta prod" });
  assert.equal(tok.status, 201);
  assert.match(tok.data.plaintextToken, /^pv_scim_[A-Za-z0-9_-]{32}$/);
  assert.equal(tok.data.token.hint, tok.data.plaintextToken.slice(0, "pv_scim_".length + 8) + "…");
  const list = await owner.client.json("GET", "/api/v1/scim/tokens");
  assert.equal(list.data.tokens.length, 1);
  assert.equal(list.data.tokens[0].id, tok.data.token.id);
  assert.equal(JSON.stringify(list.data).includes(tok.data.plaintextToken), false, "list must never echo the plaintext");

  // Audit trail for the settings + token writes.
  let events = [];
  for (let i = 0; i < 20 && !(events.includes("scim.token_created") && events.includes("scim.settings_updated")); i++) {
    const audit = await owner.client.json("GET", "/api/v1/audit?limit=20");
    events = audit.data.entries.map((e) => e.event);
    if (!(events.includes("scim.token_created") && events.includes("scim.settings_updated"))) await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(events.includes("scim.settings_updated"), events.join(","));
  assert.ok(events.includes("scim.token_created"), events.join(","));
  // Put the defaults back so the revocation test sees a plain tenant.
  await owner.client.json("PATCH", "/api/v1/scim/settings", { defaultRole: "member", deprovisionAction: "deactivate" });
  const idp = makeClient(api.base);
  idp.bearer = tok.data.plaintextToken;
  gateTenant = { owner, idp, tokenId: tok.data.token.id, plaintext: tok.data.plaintextToken };
});

test("Users: create, filter, paginate, read, replace, patch, conflict", async () => {
  const { owner, idp } = await tenant("shared");
  const email = `ada.${Date.now().toString(36)}@example.test`;
  const created = await idp.json("POST", "/scim/v2/Users", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: email.toUpperCase(),
    externalId: "okta-001",
    name: { givenName: "Ada", familyName: "Lovelace" },
    emails: [{ value: email, primary: true, type: "work" }],
    active: true,
  }, { headers: scimHeaders });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  assert.match(created.headers.get("content-type"), /scim\+json/);
  assert.equal(created.headers.get("location"), `${api.base}/scim/v2/Users/${created.data.id}`);
  assert.equal(created.data.userName, email);
  assert.equal(created.data.externalId, "okta-001");
  assert.equal(created.data.displayName, "Ada Lovelace");
  assert.equal(created.data.name.givenName, "Ada");
  assert.equal(created.data.active, true);
  assert.equal(created.data.roles[0].value, "member", "default role applies");
  const adaId = created.data.id;

  const dup = await idp.json("POST", "/scim/v2/Users", { userName: email }, { headers: scimHeaders });
  assert.equal(dup.status, 409);
  assert.equal(dup.data.scimType, "uniqueness");

  // The member appears in the console's members list with the default role.
  const members = await owner.client.json("GET", "/api/v1/members");
  assert.ok(members.data.members.some((m) => m.email === email && m.role === "member"));

  const byName = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${email}"`)}`);
  assert.equal(byName.data.totalResults, 1);
  assert.equal(byName.data.Resources[0].id, adaId);
  const byExt = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent('externalId eq "okta-001"')}`);
  assert.equal(byExt.data.totalResults, 1);
  const byEmailPath = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent(`emails[type eq "work"].value eq "${email}"`)}`);
  assert.equal(byEmailPath.data.totalResults, 1);
  const miss = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent('userName eq "nobody@example.test"')}`);
  assert.equal(miss.data.totalResults, 0);
  assert.deepEqual(miss.data.Resources, []);
  const badFilter = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent('userName co "ada"')}`);
  assert.equal(badFilter.status, 400);
  assert.equal(badFilter.data.scimType, "invalidFilter");
  const badAttr = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent('title eq "x"')}`);
  assert.equal(badAttr.status, 400);

  // Two more members → owner + 3 = 4 resources; page by 2.
  for (const n of ["bob", "cy"]) {
    const r = await idp.json("POST", "/scim/v2/Users", { userName: `${n}.${Date.now().toString(36)}@example.test` }, { headers: scimHeaders });
    assert.equal(r.status, 201);
  }
  const page1 = await idp.json("GET", "/scim/v2/Users?startIndex=1&count=2");
  assert.equal(page1.data.totalResults, 4);
  assert.equal(page1.data.itemsPerPage, 2);
  assert.equal(page1.data.startIndex, 1);
  const page2 = await idp.json("GET", "/scim/v2/Users?startIndex=3&count=2");
  assert.equal(page2.data.itemsPerPage, 2);
  assert.equal(page2.data.startIndex, 3);
  const ids = [...page1.data.Resources, ...page2.data.Resources].map((u) => u.id);
  assert.equal(new Set(ids).size, 4, "pages do not overlap");
  const page3 = await idp.json("GET", "/scim/v2/Users?startIndex=5&count=2");
  assert.equal(page3.data.itemsPerPage, 0);
  assert.equal(page3.data.totalResults, 4);
  const badPage = await idp.json("GET", "/scim/v2/Users?startIndex=abc");
  assert.equal(badPage.status, 400);

  const one = await idp.json("GET", `/scim/v2/Users/${adaId}`);
  assert.equal(one.status, 200);
  assert.equal(one.data.userName, email);
  const none = await idp.json("GET", "/scim/v2/Users/does-not-exist");
  assert.equal(none.status, 404);
  assert.equal(none.data.status, "404");

  const put = await idp.json("PUT", `/scim/v2/Users/${adaId}`, {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: email,
    externalId: "okta-001-renamed",
    displayName: "Ada L.",
    active: true,
  }, { headers: scimHeaders });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  assert.equal(put.data.displayName, "Ada L.");
  assert.equal(put.data.externalId, "okta-001-renamed");

  const patched = await idp.json("PATCH", `/scim/v2/Users/${adaId}`, patch([
    { op: "Replace", path: "name.givenName", value: "Augusta" },
    { op: "replace", path: "name.familyName", value: "King" },
    { op: "add", value: { externalId: "okta-002" } },
  ]), { headers: scimHeaders });
  assert.equal(patched.status, 200, JSON.stringify(patched.data));
  assert.equal(patched.data.displayName, "Augusta King");
  assert.equal(patched.data.externalId, "okta-002");

  // A renamed userName for a single-org user is allowed and unique-checked.
  const newEmail = `augusta.${Date.now().toString(36)}@example.test`;
  const renamed = await idp.json("PATCH", `/scim/v2/Users/${adaId}`, patch([{ op: "replace", path: "userName", value: newEmail }]), { headers: scimHeaders });
  assert.equal(renamed.status, 200, JSON.stringify(renamed.data));
  assert.equal(renamed.data.userName, newEmail);
  const clash = await idp.json("PATCH", `/scim/v2/Users/${adaId}`, patch([{ op: "replace", path: "userName", value: owner.email }]), { headers: scimHeaders });
  assert.equal(clash.status, 409);
  assert.equal(clash.data.scimType, "uniqueness");
});

test("malformed PATCH bodies are 400 invalidSyntax / invalidPath, malformed JSON too", async () => {
  const { idp } = await tenant("shared");
  const u = await idp.json("POST", "/scim/v2/Users", { userName: `m.${Date.now().toString(36)}@example.test` }, { headers: scimHeaders });
  assert.equal(u.status, 201);
  const cases = [
    { body: { schemas: [PATCH_SCHEMA] }, type: "invalidSyntax" },
    { body: { schemas: [PATCH_SCHEMA], Operations: [] }, type: "invalidSyntax" },
    { body: { schemas: [PATCH_SCHEMA], Operations: [{ path: "active", value: false }] }, type: "invalidSyntax" },
    { body: { schemas: [PATCH_SCHEMA], Operations: [{ op: "explode", path: "active", value: false }] }, type: "invalidSyntax" },
    { body: { schemas: ["urn:wrong"], Operations: [{ op: "replace", path: "active", value: false }] }, type: "invalidSyntax" },
    { body: { schemas: [PATCH_SCHEMA], Operations: [{ op: "replace", path: "shoeSize", value: 44 }] }, type: "invalidPath" },
    { body: { schemas: [PATCH_SCHEMA], Operations: [{ op: "replace", path: "active", value: "maybe" }] }, type: "invalidValue" },
    { body: { schemas: [PATCH_SCHEMA], Operations: [{ op: "remove" }] }, type: "noTarget" },
  ];
  for (const c of cases) {
    const r = await idp.json("PATCH", `/scim/v2/Users/${u.data.id}`, c.body, { headers: scimHeaders });
    assert.equal(r.status, 400, JSON.stringify(c.body));
    assert.equal(r.data.scimType, c.type, JSON.stringify(c.body) + " → " + JSON.stringify(r.data));
    assert.equal(r.data.status, "400");
  }
  const notJson = await idp.json("PATCH", `/scim/v2/Users/${u.data.id}`, "{not json", { headers: scimHeaders });
  assert.equal(notJson.status, 400);
  assert.equal(notJson.data.scimType, "invalidSyntax");
  const notJsonPlain = await idp.json("POST", "/scim/v2/Users", "{not json", { headers: { "Content-Type": "application/json" } });
  assert.equal(notJsonPlain.status, 400);
  assert.equal(notJsonPlain.data.scimType, "invalidSyntax");
  // Unchanged after all that.
  const still = await idp.json("GET", `/scim/v2/Users/${u.data.id}`);
  assert.equal(still.data.active, true);
});

test("deactivate blocks login, kills the live session, and re-activation restores access", async () => {
  const { owner, idp } = await tenant("deact");
  const carol = await provisionMember(api.base, owner, "member", "carol");
  const me = await carol.client.json("GET", "/api/v1/auth/me");
  assert.equal(me.status, 200);

  const found = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${carol.email}"`)}`);
  assert.equal(found.data.totalResults, 1);
  const carolId = found.data.Resources[0].id;

  // Azure-style string boolean is accepted.
  const off = await idp.json("PATCH", `/scim/v2/Users/${carolId}`, patch([{ op: "Replace", path: "active", value: "False" }]), { headers: scimHeaders });
  assert.equal(off.status, 200, JSON.stringify(off.data));
  assert.equal(off.data.active, false);

  // The live cookie no longer resolves to a session …
  const dead = await carol.client.json("GET", "/api/v1/auth/me");
  assert.equal(dead.status, 401, JSON.stringify(dead.data));
  // … and a fresh password login does not mint one (uniform MFA shape,
  // no cookie), because the only membership is inactive.
  const fresh = makeClient(api.base);
  const login = await fresh.json("POST", "/api/v1/auth/login", { email: carol.email, password: carol.password });
  assert.equal(login.status, 200);
  assert.equal(login.data.mfaRequired, true);
  assert.equal(fresh.cookie, null, "no session cookie for a deactivated member");
  // The console still lists the row (inactive) — nothing was deleted.
  const members = await owner.client.json("GET", "/api/v1/members");
  assert.ok(members.data.members.some((m) => m.email === carol.email));
  // Still readable over SCIM, with active=false.
  const read = await idp.json("GET", `/scim/v2/Users/${carolId}`);
  assert.equal(read.data.active, false);

  const on = await idp.json("PATCH", `/scim/v2/Users/${carolId}`, patch([{ op: "replace", value: { active: true } }]), { headers: scimHeaders });
  assert.equal(on.status, 200);
  assert.equal(on.data.active, true);
  const again = makeClient(api.base);
  const login2 = await again.json("POST", "/api/v1/auth/login", { email: carol.email, password: carol.password });
  assert.equal(login2.status, 200, JSON.stringify(login2.data));
  assert.ok(again.cookie, "re-activated member can sign in");
  assert.equal((await again.json("GET", "/api/v1/auth/me")).status, 200);

  // DELETE with deprovisionAction=remove deletes the membership.
  const rm = await owner.client.json("PATCH", "/api/v1/scim/settings", { deprovisionAction: "remove" });
  assert.equal(rm.status, 200);
  const del = await idp.json("DELETE", `/scim/v2/Users/${carolId}`);
  assert.equal(del.status, 204);
  const gone = await idp.json("GET", `/scim/v2/Users/${carolId}`);
  assert.equal(gone.status, 404);
  const membersAfter = await owner.client.json("GET", "/api/v1/members");
  assert.equal(membersAfter.data.members.some((m) => m.email === carol.email), false);
  assert.equal((await again.json("GET", "/api/v1/auth/me")).status, 401);

  // Audit slugs landed.
  let events = [];
  for (let i = 0; i < 20; i++) {
    const audit = await owner.client.json("GET", "/api/v1/audit?limit=50");
    events = audit.data.entries.map((e) => e.event);
    if (events.includes("scim.user.removed") && events.includes("scim.user.deactivated")) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  for (const slug of ["scim.user.deactivated", "scim.user.updated", "scim.user.removed"]) {
    assert.ok(events.includes(slug), `${slug} missing from ${events.join(",")}`);
  }
});

test("the last active owner can be neither deactivated, removed nor demoted", async () => {
  // Same tenant as the deactivation test: its owner is still the only
  // owner, and deprovisionAction is now "remove", so DELETE exercises
  // the guard on the remove path too.
  const { owner, idp } = await tenant("deact");
  const found = await idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${owner.email}"`)}`);
  const ownerId = found.data.Resources[0].id;
  assert.equal(found.data.Resources[0].roles[0].value, "owner");

  const deact = await idp.json("PATCH", `/scim/v2/Users/${ownerId}`, patch([{ op: "replace", path: "active", value: false }]), { headers: scimHeaders });
  assert.equal(deact.status, 400);
  assert.equal(deact.data.scimType, "mutability");
  const del = await idp.json("DELETE", `/scim/v2/Users/${ownerId}`);
  assert.equal(del.status, 400);
  assert.equal(del.data.scimType, "mutability");
  const put = await idp.json("PUT", `/scim/v2/Users/${ownerId}`, { userName: owner.email, active: false }, { headers: scimHeaders });
  assert.equal(put.status, 400);

  // Demotion through a mapped group is refused too.
  const grp = await idp.json("POST", "/scim/v2/Groups", { displayName: "member", members: [{ value: ownerId }] }, { headers: scimHeaders });
  assert.equal(grp.status, 400, JSON.stringify(grp.data));
  assert.equal(grp.data.scimType, "mutability");

  // Owner still signed in and still owner.
  const me = await owner.client.json("GET", "/api/v1/auth/me");
  assert.equal(me.status, 200);
  assert.equal(me.data.org.role, "owner");
  const still = await idp.json("GET", `/scim/v2/Users/${ownerId}`);
  assert.equal(still.data.active, true);
});

test("groups map to roles: admin group promotes, removal falls back to the default role, unmapped groups are inert", async () => {
  const { owner, idp } = await tenant("shared");
  const dan = await idp.json("POST", "/scim/v2/Users", { userName: `dan.${Date.now().toString(36)}@example.test` }, { headers: scimHeaders });
  const eve = await idp.json("POST", "/scim/v2/Users", { userName: `eve.${Date.now().toString(36)}@example.test` }, { headers: scimHeaders });
  assert.equal(dan.data.roles[0].value, "member");

  const admins = await idp.json("POST", "/scim/v2/Groups", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    displayName: "Admin",
    externalId: "grp-admins",
    members: [{ value: dan.data.id }],
  }, { headers: scimHeaders });
  assert.equal(admins.status, 201, JSON.stringify(admins.data));
  assert.equal(admins.headers.get("location"), `${api.base}/scim/v2/Groups/${admins.data.id}`);
  assert.equal(admins.data.members.length, 1);
  assert.equal(admins.data.members[0].value, dan.data.id);
  assert.equal((await idp.json("GET", `/scim/v2/Users/${dan.data.id}`)).data.roles[0].value, "admin");
  assert.deepEqual((await idp.json("GET", `/scim/v2/Users/${dan.data.id}`)).data.groups.map((g) => g.display), ["Admin"]);

  const dupGroup = await idp.json("POST", "/scim/v2/Groups", { displayName: "Admin" }, { headers: scimHeaders });
  assert.equal(dupGroup.status, 409);

  // Console agrees.
  const members = await owner.client.json("GET", "/api/v1/members");
  assert.equal(members.data.members.find((m) => m.email === dan.data.userName).role, "admin");

  // PATCH add eve, remove dan via the filter path.
  const p = await idp.json("PATCH", `/scim/v2/Groups/${admins.data.id}`, patch([
    { op: "add", path: "members", value: [{ value: eve.data.id }] },
    { op: "remove", path: `members[value eq "${dan.data.id}"]` },
  ]), { headers: scimHeaders });
  assert.equal(p.status, 200, JSON.stringify(p.data));
  assert.deepEqual(p.data.members.map((m) => m.value), [eve.data.id]);
  assert.equal((await idp.json("GET", `/scim/v2/Users/${dan.data.id}`)).data.roles[0].value, "member", "removed from admin group → default role");
  assert.equal((await idp.json("GET", `/scim/v2/Users/${eve.data.id}`)).data.roles[0].value, "admin");

  // Filter + list.
  const byName = await idp.json("GET", `/scim/v2/Groups?filter=${encodeURIComponent('displayName eq "admin"')}`);
  assert.equal(byName.data.totalResults, 1);
  const byExt = await idp.json("GET", `/scim/v2/Groups?filter=${encodeURIComponent('externalId eq "grp-admins"')}`);
  assert.equal(byExt.data.totalResults, 1);

  // Unmapped group changes nothing.
  const eng = await idp.json("POST", "/scim/v2/Groups", { displayName: "Engineering", members: [{ value: dan.data.id }, { value: eve.data.id }] }, { headers: scimHeaders });
  assert.equal(eng.status, 201);
  assert.equal((await idp.json("GET", `/scim/v2/Users/${dan.data.id}`)).data.roles[0].value, "member");
  assert.equal((await idp.json("GET", `/scim/v2/Users/${eve.data.id}`)).data.roles[0].value, "admin");

  // Rename an unmapped group to a mapped name → mapping applies to its members.
  const put = await idp.json("PUT", `/scim/v2/Groups/${eng.data.id}`, { displayName: "owner", members: [{ value: dan.data.id }] }, { headers: scimHeaders });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  assert.equal((await idp.json("GET", `/scim/v2/Users/${dan.data.id}`)).data.roles[0].value, "owner");

  // Deleting the mapped group drops dan back to member (not the last owner: the real owner remains).
  const del = await idp.json("DELETE", `/scim/v2/Groups/${eng.data.id}`);
  assert.equal(del.status, 204);
  assert.equal((await idp.json("GET", `/scim/v2/Users/${dan.data.id}`)).data.roles[0].value, "member");
  assert.equal((await idp.json("GET", `/scim/v2/Groups/${eng.data.id}`)).status, 404);

  const badMember = await idp.json("POST", "/scim/v2/Groups", { displayName: "Ops", members: [{ value: "nope" }] }, { headers: scimHeaders });
  assert.equal(badMember.status, 404);

  let events = [];
  for (let i = 0; i < 20 && !events.includes("scim.group.deleted"); i++) {
    const audit = await owner.client.json("GET", "/api/v1/audit?limit=50");
    events = audit.data.entries.map((e) => e.event);
    if (!events.includes("scim.group.deleted")) await new Promise((r) => setTimeout(r, 100));
  }
  for (const slug of ["scim.group.created", "scim.group.updated", "scim.group.deleted"]) {
    assert.ok(events.includes(slug), `${slug} missing from ${events.join(",")}`);
  }
});

test("token revocation and disabling SCIM shut the door; a wrong token is 401", async () => {
  assert.ok(gateTenant, "the plan-gate test provisions this tenant");
  const { owner, idp, tokenId, plaintext } = gateTenant;
  assert.equal((await idp.json("GET", "/scim/v2/Users")).status, 200);

  const wrong = makeClient(api.base);
  wrong.bearer = plaintext.slice(0, -4) + "AAAA";
  assert.equal((await wrong.json("GET", "/scim/v2/Users")).status, 401);
  const notScim = makeClient(api.base);
  notScim.bearer = "pv_srv_" + plaintext.slice("pv_scim_".length);
  assert.equal((await notScim.json("GET", "/scim/v2/Users")).status, 401);

  const disabled = await owner.client.json("PATCH", "/api/v1/scim/settings", { enabled: false });
  assert.equal(disabled.status, 200);
  const whileDisabled = await idp.json("GET", "/scim/v2/Users");
  assert.equal(whileDisabled.status, 403);
  assert.match(whileDisabled.data.detail, /disabled/);
  await owner.client.json("PATCH", "/api/v1/scim/settings", { enabled: true });
  assert.equal((await idp.json("GET", "/scim/v2/Users")).status, 200);

  const revoke = await owner.client.json("DELETE", `/api/v1/scim/tokens/${tokenId}`);
  assert.equal(revoke.status, 204);
  const after = await idp.json("GET", "/scim/v2/Users");
  assert.equal(after.status, 401);
  assert.equal((await owner.client.json("GET", "/api/v1/scim/tokens")).data.tokens.length, 0);
  assert.equal((await owner.client.json("DELETE", `/api/v1/scim/tokens/${tokenId}`)).status, 404);

  // Plan downgrade after the fact: the IdP gets a clear 402.
  const tok2 = await owner.client.json("POST", "/api/v1/scim/tokens", { name: "second" });
  const idp2 = makeClient(api.base);
  idp2.bearer = tok2.data.plaintextToken;
  await setPlan(owner.org.id, "free");
  const downgraded = await idp2.json("GET", "/scim/v2/Users");
  assert.equal(downgraded.status, 402);
  assert.equal(downgraded.data.status, "402");
});

test("tenants are isolated: ids, filters and groups of one org are invisible to another's token", async () => {
  const a = await tenant("iso-a");
  const b = await tenant("iso-b");
  const userA = await a.idp.json("POST", "/scim/v2/Users", { userName: `isoa.${Date.now().toString(36)}@example.test`, externalId: "shared-ext" }, { headers: scimHeaders });
  assert.equal(userA.status, 201);
  const groupA = await a.idp.json("POST", "/scim/v2/Groups", { displayName: "Admin", members: [{ value: userA.data.id }] }, { headers: scimHeaders });
  assert.equal(groupA.status, 201);

  assert.equal((await b.idp.json("GET", `/scim/v2/Users/${userA.data.id}`)).status, 404);
  assert.equal((await b.idp.json("PATCH", `/scim/v2/Users/${userA.data.id}`, patch([{ op: "replace", path: "active", value: false }]), { headers: scimHeaders })).status, 404);
  assert.equal((await b.idp.json("DELETE", `/scim/v2/Users/${userA.data.id}`)).status, 404);
  assert.equal((await b.idp.json("GET", `/scim/v2/Groups/${groupA.data.id}`)).status, 404);
  // Adding A's user to a B group is refused (member must be a User of B).
  const cross = await b.idp.json("POST", "/scim/v2/Groups", { displayName: "Admin", members: [{ value: userA.data.id }] }, { headers: scimHeaders });
  assert.equal(cross.status, 404);

  const listB = await b.idp.json("GET", "/scim/v2/Users");
  assert.equal(listB.data.totalResults, 1, "only B's owner");
  assert.equal(listB.data.Resources[0].userName, b.owner.email);
  const extB = await b.idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent('externalId eq "shared-ext"')}`);
  assert.equal(extB.data.totalResults, 0);
  const nameB = await b.idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${userA.data.userName}"`)}`);
  assert.equal(nameB.data.totalResults, 0);

  // B's IdP may not attach the account A provisioned: it belongs to
  // another workspace, and only an invite (which the person accepts)
  // may add it here. A's resource is untouched.
  const sameInB = await b.idp.json("POST", "/scim/v2/Users", { userName: userA.data.userName, externalId: "b-ext" }, { headers: scimHeaders });
  assert.equal(sameInB.status, 409, JSON.stringify(sameInB.data));
  assert.equal(sameInB.data.scimType, "uniqueness");
  assert.equal((await a.idp.json("GET", `/scim/v2/Users/${userA.data.id}`)).data.active, true);
});

test("a SCIM-created account never carries mailbox verification (OAuth pre-hijack gate)", async () => {
  const t = await tenant("verify-gate");
  const email = `prehijack-${Date.now()}@victim.example`;
  const created = await t.idp.json("POST", "/scim/v2/Users",
    { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: email, active: true }, { headers: scimHeaders });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const row = await pg.query('SELECT "emailVerifiedAt" FROM users WHERE email = $1', [email]);
  assert.equal(row.rows[0].emailVerifiedAt, null);
});

test("one workspace's IdP cannot attach, rename or sign out an account of another workspace", async () => {
  const t = await tenant("cross-a");
  const other = await signupOwner(api.base, "cross-b");
  const me = async () => (await other.client.json("GET", "/api/v1/auth/me"));
  const before = await me();
  assert.equal(before.status, 200);
  // Attaching an account that lives in another workspace is refused.
  const attach = await t.idp.json("POST", "/scim/v2/Users",
    { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: other.email, active: true }, { headers: scimHeaders });
  assert.equal(attach.status, 409, JSON.stringify(attach.data));
  assert.equal(attach.data.scimType, "uniqueness");
  // A shared account (joined through an invite, simulated here) can only
  // have its membership in this org changed.
  const role = await pg.query("SELECT gen_random_uuid()::text AS id");
  await pg.query('INSERT INTO memberships (id, "userId", "orgId", role, active, "createdAt") VALUES ($1, $2, $3, $4, true, NOW())',
    [role.rows[0].id, other.user.id, t.owner.org.id, "member"]);
  const listed = await t.idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${other.email}"`)}`);
  const id = listed.data.Resources[0].id;
  const renamed = await t.idp.json("PATCH", `/scim/v2/Users/${id}`,
    patch([{ op: "replace", path: "displayName", value: "Renamed By Another Tenant" }, { op: "replace", path: "emails", value: [{ value: "hijack@attacker.example", primary: true }] }]),
    { headers: scimHeaders });
  assert.ok(renamed.status === 200 || renamed.status === 400, JSON.stringify(renamed.data));
  const deactivated = await t.idp.json("PATCH", `/scim/v2/Users/${id}`, patch([{ op: "replace", path: "active", value: false }]), { headers: scimHeaders });
  assert.equal(deactivated.status, 200, JSON.stringify(deactivated.data));
  const after = await me();
  assert.equal(after.status, 200, "the other workspace's session still works");
  assert.equal(after.data.user.email, other.email, "the login email is unchanged");
  assert.equal(after.data.user.displayName ?? null, before.data.user.displayName ?? null, "the name is unchanged");
  const row = await pg.query('SELECT active FROM memberships WHERE id = $1', [role.rows[0].id]);
  assert.equal(row.rows[0].active, false, "only this org's membership was deactivated");
});

test("SCIM creates count against the same seat usage the billing endpoint reports", async () => {
  // The free-plan 402 on the SCIM path is exercised by
  // ci/billing.test.mjs (where the plan is driven by Stripe events);
  // here we check both paths read one counter.
  const { owner, idp } = await tenant("shared");
  const before = await owner.client.json("GET", "/api/v1/billing");
  const seats = before.data.usage.members;
  const r = await idp.json("POST", "/scim/v2/Users", { userName: `seat.${Date.now().toString(36)}@example.test` }, { headers: scimHeaders });
  assert.equal(r.status, 201);
  const after = await owner.client.json("GET", "/api/v1/billing");
  assert.equal(after.data.usage.members, seats + 1);
});

test("SCIM re-addresses only accounts its own workspace's SCIM created, and drops their verification", async () => {
  const t = await tenant("shared");
  const first = `readdress.${Date.now().toString(36)}@example.test`;
  const u = await t.idp.json("POST", "/scim/v2/Users", { userName: first }, { headers: scimHeaders });
  assert.equal(u.status, 201, JSON.stringify(u.data));
  // Pretend the person proved the mailbox and has a reset link pending.
  await pg.query('UPDATE users SET "emailVerifiedAt" = NOW(), "resetTokenHash" = $1, "resetTokenAt" = NOW() WHERE email = $2', ["pending-reset", first]);
  const second = `readdressed.${Date.now().toString(36)}@example.test`;
  const moved = await t.idp.json("PATCH", `/scim/v2/Users/${u.data.id}`, patch([{ op: "replace", path: "userName", value: second }]), { headers: scimHeaders });
  assert.equal(moved.status, 200, JSON.stringify(moved.data));
  const row = await pg.query('SELECT "emailVerifiedAt", "resetTokenHash" FROM users WHERE email = $1', [second]);
  assert.equal(row.rows[0].emailVerifiedAt, null, "the new address is not verified by the IdP's word");
  assert.equal(row.rows[0].resetTokenHash, null, "a reset link mailed to the old address is void");

  // An invited member owns their login email, even in a one-workspace account.
  const invited = await provisionMember(api.base, t.owner, "member", "readdress-invited");
  const listed = await t.idp.json("GET", `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${invited.email}"`)}`);
  const refused = await t.idp.json("PATCH", `/scim/v2/Users/${listed.data.Resources[0].id}`,
    patch([{ op: "replace", path: "userName", value: `taken-over.${Date.now().toString(36)}@attacker.example` }]), { headers: scimHeaders });
  assert.equal(refused.status, 400, JSON.stringify(refused.data));
  assert.equal(refused.data.scimType, "mutability");
  const still = await pg.query("SELECT email FROM users WHERE id = $1", [invited.userId]);
  assert.equal(still.rows[0].email, invited.email);
});

test("an account with no workspace left is re-attached only by the workspace whose SCIM created it", async () => {
  const t = await tenant("shared");
  const other = await tenant("verify-gate");
  // A person who joined by invite and was later removed everywhere.
  const leaver = await provisionMember(api.base, t.owner, "member", "leaver");
  await pg.query('DELETE FROM memberships WHERE "userId" = $1', [leaver.userId]);
  for (const idp of [t.idp, other.idp]) {
    const r = await idp.json("POST", "/scim/v2/Users", { userName: leaver.email }, { headers: scimHeaders });
    assert.equal(r.status, 409, JSON.stringify(r.data));
    assert.equal(r.data.scimType, "uniqueness");
  }
  // An account this workspace's SCIM created comes back after removal …
  const email = `cycle.${Date.now().toString(36)}@example.test`;
  const made = await t.idp.json("POST", "/scim/v2/Users", { userName: email }, { headers: scimHeaders });
  assert.equal(made.status, 201);
  await pg.query('DELETE FROM memberships WHERE id = $1', [made.data.id]);
  // … but never into another workspace.
  const stolen = await other.idp.json("POST", "/scim/v2/Users", { userName: email }, { headers: scimHeaders });
  assert.equal(stolen.status, 409, JSON.stringify(stolen.data));
  const back = await t.idp.json("POST", "/scim/v2/Users", { userName: email }, { headers: scimHeaders });
  assert.equal(back.status, 201, JSON.stringify(back.data));
});

test("SCIM display names lose control and bidi characters and are capped at 80", async () => {
  const { idp } = await tenant("shared");
  const r = await idp.json("POST", "/scim/v2/Users", {
    userName: `names.${Date.now().toString(36)}@example.test`,
    displayName: "Mallory‮evil\u0000\r\nAdmin",
  }, { headers: scimHeaders });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal(r.data.displayName, "Mallory evil Admin");
  const long = await idp.json("PATCH", `/scim/v2/Users/${r.data.id}`, patch([{ op: "replace", path: "displayName", value: "x".repeat(150) }]), { headers: scimHeaders });
  assert.equal(long.status, 200, JSON.stringify(long.data));
  assert.equal(long.data.displayName, "x".repeat(80));
});
