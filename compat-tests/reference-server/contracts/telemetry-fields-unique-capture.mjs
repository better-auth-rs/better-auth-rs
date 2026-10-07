import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const version = "1.7.6";
const endpoint = "https://telemetry-fields-unique.test/capture";
const json = value => JSON.parse(JSON.stringify(value));

export async function captureTelemetryFieldUnique() {
  for (const name of ["better-auth", "@better-auth/core", "@better-auth/telemetry"]) {
    const metadata = JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8"));
    assert.equal(metadata.version, version);
  }
  assert.equal(process.env.NODE_ENV, "production");
  assert.equal(process.env.TEST, "");
  assert.equal(process.env.BETTER_AUTH_TELEMETRY_ENDPOINT, endpoint);

  const events = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    assert.equal(String(input), endpoint);
    events.push(JSON.parse(init.body));
    return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
  };
  try {
    const { betterAuth } = await import("better-auth");
    const { getTelemetryAuthConfig } = await import("@better-auth/telemetry");
    const cases = [];
    for (const [name, attributes] of [["omitted", {}], ["false", { unique: false }], ["true", { unique: true }]]) {
      const callbacks = [];
      const fields = model => {
        const callback = kind => value => {
          callbacks.push({ model, kind });
          return value;
        };
        return { label: {
          type: "string", ...attributes,
          defaultValue: () => callback("defaultValue")("ordinary-label"),
          onUpdate: () => callback("onUpdate")("updated-label"),
          transform: { input: callback("input"), output: callback("output") },
        } };
      };
      const options = {
        secret: "telemetry-fields-unique-secret-0123456789",
        baseURL: "https://example.test",
        logger: { disabled: true },
        telemetry: { enabled: true },
        user: { additionalFields: fields("user") },
        session: { additionalFields: fields("session") },
        plugins: [],
      };
      const start = events.length;
      const auth = betterAuth(options);
      const context = await auth.$context;
      assert.equal(events.length, start + 1, "Each initialization must emit exactly one event");
      assert.equal(events[start].type, "init");
      const config = events[start].payload.config;
      const projected = json(await getTelemetryAuthConfig(context.options));
      const observed = {};
      for (const model of ["user", "session"]) {
        assert.deepEqual(config[model], projected[model], "Initialization must retain the complete helper projection");
        assert.deepEqual(config[model].additionalFields, json(options[model].additionalFields));
        const label = config[model].additionalFields.label;
        assert.equal(Object.hasOwn(label, "unique"), name !== "omitted");
        if (name !== "omitted") assert.equal(label.unique, attributes.unique);
        observed[model] = config[model];
      }
      assert.deepEqual(callbacks, [], "Initialization and telemetry projection must not invoke field callbacks");
      cases.push({ name, config: observed, callbacks });
    }
    return { version, cases };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureTelemetryFieldUnique(), null, 2)}\n`);
}
