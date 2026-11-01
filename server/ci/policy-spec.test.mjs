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

/**
 * Guardrails are enforceable per policy: a body that is the JSON spec
 * (docs/reference/OPERATIONS.md, "Guardrail policies") is pushed to
 * daemons, a free-text body stays documentation only, and a JSON object
 * that is not a valid spec is refused with the reason.
 */
const guardrail = (scope, body) => validatePolicySpec("guardrail", scope, typeof body === "string" ? body : JSON.stringify(body));

test("a free-text guardrail is accepted as documentation only", () => {
  for (const text of ["", "documentation only", 'policy "x" { effect = block }', "[1, 2]"]) {
    assert.deepEqual(guardrail("llm.egress", text), { ok: true, spec: null }, JSON.stringify(text));
  }
});

test("a guardrail JSON spec is accepted and parsed", () => {
  const spec = { applies_to: "tool.args", deny_patterns: ["\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b"], effect: "block" };
  assert.deepEqual(guardrail("tool.*", spec), { ok: true, spec });
  assert.deepEqual(guardrail("tool.create_ticket", spec), { ok: true, spec });
  const ingress = { applies_to: "llm.ingress", deny_patterns: ["(?i)password"] };
  for (const scope of ["llm.request", "llm", "llm.*", "llm.ingress"]) {
    assert.deepEqual(guardrail(scope, ingress), { ok: true, spec: ingress }, scope);
  }
  // Pretty-printed bodies, as the console writes them, parse the same.
  assert.equal(guardrail("tool.*", JSON.stringify(spec, null, 2)).spec.deny_patterns.length, 1);
});

test("a guardrail JSON object that is not a valid spec is refused with the reason", () => {
  const cases = [
    [{}, /applies_to/],
    [{ applies_to: "llm.egress", deny_patterns: ["x"] }, /llm\.egress is not enforced by daemons yet/],
    [{ applies_to: "tool.result", deny_patterns: ["x"] }, /applies_to must be tool\.args or llm\.ingress/],
    [{ applies_to: "tool.args", deny_patterns: [] }, /at least one pattern/],
    [{ applies_to: "tool.args", deny_patterns: [""] }, /must not be empty/],
    [{ applies_to: "tool.args", deny_patterns: ["x".repeat(513)] }, /at most 512 bytes/],
    [{ applies_to: "tool.args", deny_patterns: Array.from({ length: 65 }, () => "x") }, /deny_patterns/],
    [{ applies_to: "tool.args", deny_patterns: ["(?=secret)"] }, /lookaround and backreferences/],
    [{ applies_to: "tool.args", deny_patterns: ["(a)\\1"] }, /lookaround and backreferences/],
    [{ applies_to: "tool.args", deny_patterns: ["x"], effect: "warn" }, /effect/],
    [{ applies_to: "tool.args", deny_patterns: ["x"], extra: 1 }, /extra/],
    ["{ not json }", /not valid JSON/],
  ];
  for (const [body, reason] of cases) {
    const result = guardrail("tool.*", body);
    assert.equal(result.ok, false, JSON.stringify(body));
    assert.match(result.detail, reason);
  }
});

test("a guardrail's scope must match where it applies", () => {
  const toolArgs = { applies_to: "tool.args", deny_patterns: ["x"] };
  const ingress = { applies_to: "llm.ingress", deny_patterns: ["x"] };
  assert.match(guardrail("llm.request", toolArgs).detail, /not a tool scope/);
  assert.match(guardrail("tool.*", ingress).detail, /not a model scope/);
  assert.match(guardrail("llm.egress", ingress).detail, /not a model scope/);
});
