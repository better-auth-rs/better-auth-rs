import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
const events = [];
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://telemetry-cache-init.test/capture");
  events.push(JSON.parse(init.body));
  return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
};
const { betterAuth } = await import("better-auth");
const { memoryAdapter } = await import("better-auth/adapters/memory");
const results = {};
for (const storage of ["stateless", "database", "secondary"]) {
  for (const cache of ["omitted", "empty", "disabled", "zeroLifetime", "customLifetime", "fractionalDurations"]) {
    const options = {};
    if (storage === "database") options.database = memoryAdapter({});
    if (storage === "secondary") options.secondaryStorage = { get: async () => null, set: async () => {}, delete: async () => {} };
    if (cache === "empty") options.session = { cookieCache: {} };
    if (cache === "disabled") options.session = { cookieCache: { enabled: false } };
    if (cache === "zeroLifetime") options.session = { expiresIn: 0 };
    if (cache === "customLifetime") options.session = { expiresIn: 90 };
    if (cache === "fractionalDurations") options.session = { expiresIn: 12.25, updateAge: 0.5, freshAge: -0.125, cookieCache: { maxAge: 0.000000001 } };
    const count = events.length;
    const auth = betterAuth({ secret: "telemetry-cache-init-normal-secret-0123456789", baseURL: "https://example.test", logger: { disabled: true }, telemetry: { enabled: true }, ...options });
    const context = await auth.$context;
    assert.equal(events.length, count + 1);
    results[`${storage}-${cache}`] = JSON.parse(JSON.stringify({ session: events[count].payload.config.session, expiresIn: context.sessionConfig.expiresIn, cache: context.options.session?.cookieCache }));
    if (cache === "zeroLifetime") {
      assert.equal(context.sessionConfig.expiresIn, 604800);
      assert.equal(events[count].payload.config.session.expiresIn, 0);
    }
  }
}
const fixture = new URL("../../../tests/fixtures/telemetry-cache-init-1.7.6.json", import.meta.url);
if (process.env.TELEMETRY_CACHE_INIT_OUTPUT) {
  writeFileSync(process.env.TELEMETRY_CACHE_INIT_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log(`Wrote ${Object.keys(results).length} real initialization cache cases`);
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} real initialization cache cases match the Rust fixture`);
}
