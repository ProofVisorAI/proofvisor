// /metrics must not be public in production unless an operator says so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { startApi } from "./helpers/api-process.mjs";

const production = {
  NODE_ENV: "production",
  APP_BASE_URL: "https://proofvisor.example",
  API_PUBLIC_URL: "https://api.proofvisor.example",
  ALLOWED_ORIGINS: "https://proofvisor.example",
  SMTP_URL: "smtp://127.0.0.1:2525",
};

test("production without ALLOW_METRICS_IPS hides /metrics", async () => {
  const api = await startApi(production);
  try {
    const res = await fetch(api.base + "/metrics");
    assert.equal(res.status, 404);
  } finally {
    await api.stop();
  }
});

test("an explicit allow-list still serves the scraper", async () => {
  const api = await startApi({ ...production, ALLOW_METRICS_IPS: "127.0.0.1" });
  try {
    const res = await fetch(api.base + "/metrics");
    assert.equal(res.status, 200);
    assert.match(await res.text(), /^# HELP /m);
  } finally {
    await api.stop();
  }
});

test("development keeps /metrics open for local tooling", async () => {
  const api = await startApi();
  try {
    assert.equal((await fetch(api.base + "/metrics")).status, 200);
  } finally {
    await api.stop();
  }
});
