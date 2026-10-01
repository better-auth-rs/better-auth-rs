import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const events = [];
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://telemetry-model-declarations.test/capture");
  events.push(JSON.parse(init.body));
  return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
};
const { betterAuth } = await import("better-auth");
const models = { user: "email", session: "ipAddress", account: "providerId", verification: "identifier" };
const cases = {
  omitted: {},
  empty: Object.fromEntries(Object.keys(models).map((model) => [model, { fields: {} }])),
  explicitDefaults: Object.fromEntries(Object.entries(models).map(([model, field]) => [model, { modelName: model, fields: { [field]: field } }])),
  renamed: Object.fromEntries(Object.entries(models).map(([model, field]) => [model, { modelName: `app_${model}`, fields: { [field]: `configured_${field}` } }])),
};
const results = {};
for (const [name, options] of Object.entries(cases)) {
  const count = events.length;
  const auth = betterAuth({
    secret: "telemetry-model-declarations-secret-0123456789",
    baseURL: "https://example.test",
    logger: { disabled: true },
    telemetry: { enabled: true },
    ...options,
  });
  await auth.$context;
  assert.equal(events.length, count + 1);
  const config = events[count].payload.config;
  results[name] = {
    options,
    expected: Object.fromEntries(Object.keys(models).map((model) => [model,
      Object.fromEntries(["modelName", "fields"].filter((key) => Object.hasOwn(config[model], key)).map((key) => [key, config[model][key]])),
    ])),
  };
}
const fixture = new URL("../../../tests/fixtures/telemetry-model-declarations-1.7.6.json", import.meta.url);
if (process.env.TELEMETRY_MODEL_DECLARATIONS_OUTPUT) {
  writeFileSync(process.env.TELEMETRY_MODEL_DECLARATIONS_OUTPUT, JSON.stringify(results, null, 2) + "\n");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} real initialization model declaration cases match the Rust fixture`);
}
