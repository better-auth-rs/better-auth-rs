import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const events = [];
let callbacks = 0;
const callback = (value) => { callbacks++; return value; };
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://telemetry-fields-init.test/capture");
  events.push(JSON.parse(init.body));
  return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
};
const { betterAuth } = await import("better-auth");
const { lastLoginMethod } = await import("better-auth/plugins");
const fields = {
  types: Object.fromEntries(["string", "number", "boolean", "date", "json", "string[]", "number[]", ["bronze", "silver"]].map((type, index) => [`field${index}`, { type }])),
  flags: {
    omitted: { type: "string" },
    enabled: { type: "string", required: true, input: true, returned: true },
    disabled: { type: "string", required: false, input: false, returned: false },
  },
  declaration: {
    label: { type: "string", fieldName: "display_label", defaultValue: "hello" },
    count: { type: "number", defaultValue: 7 },
    settings: { type: "json", defaultValue: { theme: "light", tags: ["ordinary"] } },
    reference: { type: "string", references: { model: "user", field: "id" } },
    nothing: { type: "json", defaultValue: null },
  },
  transforms: {
    omitted: { type: "string" },
    empty: { type: "string", transform: {} },
    input: { type: "string", transform: { input: callback } },
    output: { type: "string", transform: { output: callback } },
    both: { type: "string", transform: { input: callback, output: callback } },
    asynchronous: { type: "string", transform: { input: async (value) => callback(value), output: async (value) => callback(value) } },
  },
  factories: { label: { type: "string", defaultValue: () => callback("hello"), onUpdate: () => callback("updated") } },
};
const results = {};
for (const name of ["omitted", "empty", ...Object.keys(fields), "plugin"]) {
  const additionalFields = name === "empty" ? {} : fields[name];
  const count = events.length;
  const auth = betterAuth({
    secret: "telemetry-fields-init-secret-0123456789",
    baseURL: "https://example.test",
    logger: { disabled: true },
    telemetry: { enabled: true },
    user: { additionalFields },
    session: { additionalFields },
    plugins: name === "plugin" ? [lastLoginMethod({ storeInDatabase: true })] : [],
  });
  await auth.$context;
  assert.equal(events.length, count + 1);
  const config = events[count].payload.config;
  results[name] = Object.fromEntries(["user", "session"].map((model) => [model,
    Object.hasOwn(config[model], "additionalFields") ? { additionalFields: config[model].additionalFields } : {},
  ]));
}
assert.equal(callbacks, 0, "initialization must not invoke field callbacks");
const fixture = new URL("../../../tests/fixtures/telemetry-fields-init-1.7.6.json", import.meta.url);
if (process.env.TELEMETRY_FIELDS_INIT_OUTPUT) {
  writeFileSync(process.env.TELEMETRY_FIELDS_INIT_OUTPUT, JSON.stringify(results, null, 2) + "\n");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} real initialization field cases match the Rust fixture`);
}
