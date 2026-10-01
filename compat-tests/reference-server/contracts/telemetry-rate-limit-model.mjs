import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const events = [];
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://telemetry-rate-limit-model.test/capture");
  events.push(JSON.parse(init.body));
  return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
};
const { betterAuth } = await import("better-auth");
const { memoryAdapter } = await import("better-auth/adapters/memory");
const cases = {
  omitted: {},
  empty: { rateLimit: { fields: {} } },
  explicitDefaults: { rateLimit: { modelName: "rateLimit" } },
  renamed: { rateLimit: { modelName: "app_request_limits", fields: { key: "request_bucket", count: "request_total", lastRequest: "requested_at_ms" } } },
};
const results = {};
for (const [name, options] of Object.entries(cases)) {
  const count = events.length;
  const auth = betterAuth({
    secret: "telemetry-rate-limit-model-secret-0123456789",
    baseURL: "https://example.test",
    logger: { disabled: true },
    telemetry: { enabled: true },
    database: memoryAdapter({}),
    rateLimit: { ...options.rateLimit, storage: "database" },
  });
  await auth.$context;
  assert.equal(events.length, count + 1);
  results[name] = { options, expected: events[count].payload.config.rateLimit };
}
const fixture = new URL("../../../tests/fixtures/telemetry-rate-limit-model-1.7.6.json", import.meta.url);
if (process.env.TELEMETRY_RATE_LIMIT_MODEL_OUTPUT) {
  writeFileSync(process.env.TELEMETRY_RATE_LIMIT_MODEL_OUTPUT, JSON.stringify(results, null, 2) + "\n");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} real initialization rate-limit model cases match the Rust fixture`);
}
