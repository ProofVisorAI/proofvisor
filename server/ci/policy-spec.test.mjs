/**
 * Schema policies may only reference their own contents. Daemons refuse to
 * fetch external references in a pushed schema (crates/pv-sandbox/src/pushed.rs),
 * so the console refuses them when the policy is saved, with the reason.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { validatePolicySpec } from "../src/lib/policy-bundle.ts";

const schemaPolicy = (json_schema) =>
  validatePolicySpec("schema", "tool.create_payment", JSON.stringify({ tool: "create_payment", json_schema }));

test("external references are refused at write time", () => {
  for (const bad of [
    { $ref: "http://169.254.169.254/latest/meta-data" },
    { $ref: "file:///etc/passwd" },
    { $ref: "other.json#/$defs/x" },
    { properties: { n: { $dynamicRef: "https://example.com/s" } } },
    { allOf: [{ $recursiveRef: "https://example.com/s" }] },
    { $schema: "https://example.com/meta.json" },
  ]) {
    const result = schemaPolicy(bad);
    assert.equal(result.ok, false, JSON.stringify(bad));
    assert.match(result.detail, /points outside the schema/);
  }
});

test("references inside the schema and the standard drafts are accepted", () => {
  for (const good of [
    { $defs: { amount: { type: "integer" } }, properties: { n: { $ref: "#/$defs/amount" } } },
    { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object" },
    { $schema: "http://json-schema.org/draft-07/schema#", type: "object" },
  ]) {
    const result = schemaPolicy(good);
    assert.equal(result.ok, true, `${JSON.stringify(good)}: ${result.detail}`);
  }
});
