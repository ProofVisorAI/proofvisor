/**
 * Schema policies may only reference their own contents. Daemons refuse to
 * fetch external references in a pushed schema (crates/pv-sandbox/src/pushed.rs),
 * so the console refuses them when the policy is saved, with the reason.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { isEnforceablePolicy, validatePolicySpec } from "../src/lib/policy-bundle.ts";

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
    [{ applies_to: "llm.egress", deny_patterns: ["x"] }, /not a response scope/],
    [{ applies_to: "tool.result", deny_patterns: ["x"] }, /applies_to must be tool\.args, llm\.ingress or llm\.egress/],
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

const transform = (scope, body) => validatePolicySpec("transform", scope, typeof body === "string" ? body : JSON.stringify(body));

test("a guardrail may apply to model responses with a response scope", () => {
  const egress = { applies_to: "llm.egress", deny_patterns: ["(?i)project nightjar"], effect: "block" };
  for (const scope of ["llm", "llm.*", "llm.response", "llm.egress"]) {
    assert.deepEqual(guardrail(scope, egress), { ok: true, spec: egress }, scope);
  }
  assert.match(guardrail("llm.request", egress).detail, /not a response scope/);
  assert.match(guardrail("tool.*", egress).detail, /not a response scope/);
});

test("a free-text transform is accepted as documentation only", () => {
  for (const text of ["", "redact everything", 'policy "x" { transform = redact([\"ssn\"]) }']) {
    assert.deepEqual(transform("llm.request", text), { ok: true, spec: null }, JSON.stringify(text));
  }
});

test("a transform JSON spec is accepted and parsed", () => {
  const tool = { applies_to: "tool.args", redact_patterns: ["TCK-[0-9]{4}"], replacement: "[ticket]" };
  assert.deepEqual(transform("tool.*", tool), { ok: true, spec: tool });
  assert.deepEqual(transform("tool.create_ticket", tool), { ok: true, spec: tool });
  const chat = { applies_to: "llm.ingress", redact_patterns: ["[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"] };
  for (const scope of ["llm", "llm.*", "llm.request", "llm.ingress"]) {
    assert.deepEqual(transform(scope, chat), { ok: true, spec: chat }, scope);
  }
  const egress = { applies_to: "llm.egress", redact_patterns: ["TCK-[0-9]{4}"], replacement: "[ticket]" };
  for (const scope of ["llm", "llm.*", "llm.response", "llm.egress"]) {
    assert.deepEqual(transform(scope, egress), { ok: true, spec: egress }, scope);
  }
  assert.match(transform("llm.request", egress).detail, /not a response scope/);
  assert.equal(isEnforceablePolicy("transform", "tool.*", JSON.stringify(tool)), true);
  assert.equal(isEnforceablePolicy("transform", "tool.*", "free text"), false);
});

test("a transform JSON object that is not a valid spec is refused with the reason", () => {
  for (const [body, reason] of [
    [{ applies_to: "tool.result", redact_patterns: ["x"] }, /tool\.args, llm\.ingress or llm\.egress/],
    [{ applies_to: "tool.args", redact_patterns: [] }, /at least one/],
    [{ applies_to: "tool.args", redact_patterns: ["(?<=a)b"] }, /lookaround/],
    [{ applies_to: "tool.args", redact_patterns: ["x"], replacement: "" }, /replacement/],
    [{ applies_to: "tool.args", redact_patterns: ["x"], replacement: "a\nb" }, /control characters/],
    [{ applies_to: "tool.args", redact_patterns: ["x"], replacement: "r".repeat(65) }, /at most 64 bytes/],
    [{ applies_to: "tool.args", redact_patterns: ["x"], effect: "block" }, /unrecognized|Unrecognized|unknown/i],
    ["{ not json }", /not valid JSON/],
  ]) {
    const result = transform("tool.*", body);
    assert.equal(result.ok, false, JSON.stringify(body));
    assert.match(result.detail, reason, result.detail);
  }
  assert.match(transform("llm.request", { applies_to: "tool.args", redact_patterns: ["x"] }).detail, /not a tool scope/);
  assert.match(transform("tool.*", { applies_to: "llm.ingress", redact_patterns: ["x"] }).detail, /not a model scope/);
});
