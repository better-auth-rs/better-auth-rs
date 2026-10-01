import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const events = [];
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://telemetry-storage-init.test/capture");
  events.push(JSON.parse(init.body));
  return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
};
const { betterAuth } = await import("better-auth");
const { memoryAdapter } = await import("better-auth/adapters/memory");
const results = {};
for (const database of [false, true]) {
  for (const secondary of [false, true]) {
    const count = events.length;
    const auth = betterAuth({
      secret: "telemetry-storage-init-secret-0123456789",
      baseURL: "https://example.test",
      logger: { disabled: true },
      telemetry: { enabled: true },
      database: database ? memoryAdapter({}) : undefined,
      secondaryStorage: secondary ? { get: async () => null, set: async () => {}, delete: async () => {} } : undefined,
    });
    await auth.$context;
    assert.equal(events.length, count + 1);
    const config = events[count].payload.config;
    results[`${database ? "database" : "stateless"}-${secondary ? "secondary" : "primary"}`] = {
      database: config.database,
      adapter: config.adapter,
      secondaryStorage: config.secondaryStorage,
    };
  }
}
const fixture = new URL("../../../tests/fixtures/telemetry-storage-init-1.7.6.json", import.meta.url);
if (process.env.TELEMETRY_STORAGE_INIT_OUTPUT) {
  writeFileSync(process.env.TELEMETRY_STORAGE_INIT_OUTPUT, JSON.stringify(results, null, 2) + "\n");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} real initialization storage cases match the Rust fixture`);
}
