import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const events = [];
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://telemetry-plugin-ids.test/capture");
  events.push(JSON.parse(init.body));
  return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
};
const { betterAuth } = await import("better-auth");
const { genericOAuth } = await import("better-auth/plugins");
const generic = (providerId) => ({
  providerId,
  clientId: "telemetry-client",
  clientSecret: "telemetry-client-secret",
  authorizationUrl: "https://provider.test/authorize",
  tokenUrl: "https://provider.test/token",
  userInfoUrl: "https://provider.test/userinfo",
});
const cases = {
  omitted: {},
  empty: { plugins: [] },
  core: { emailAndPassword: { enabled: true }, emailVerification: {}, user: { changeEmail: {} } },
  social: { socialProviders: { github: { clientId: "client", clientSecret: "secret" } } },
  generic: { plugins: [genericOAuth({ config: [generic("provider")] })] },
  multipleGeneric: { plugins: [genericOAuth({ config: [generic("first"), generic("second")] })] },
  mixed: { emailAndPassword: { enabled: true }, plugins: [{ id: "first" }, genericOAuth({ config: [generic("provider")] }), { id: "last" }] },
  customCoreName: { plugins: [{ id: "email-password" }] },
};
const results = {};
for (const [name, options] of Object.entries(cases)) {
  const count = events.length;
  const auth = betterAuth({
    secret: "telemetry-plugin-ids-normal-config-secret-0123456789",
    baseURL: "https://example.test",
    logger: { disabled: true },
    telemetry: { enabled: true },
    ...options,
  });
  const context = await auth.$context;
  assert.equal(events.length, count + 1);
  const plugins = events[count].payload.config.plugins;
  const initializedPlugins = context.options.plugins.map(plugin => plugin.id);
  assert.deepEqual(plugins, initializedPlugins);
  results[name] = { plugins, initializedPlugins };
}
const fixture = new URL("../../../tests/fixtures/telemetry-plugin-ids-1.7.6.json", import.meta.url);
if (process.env.TELEMETRY_PLUGIN_IDS_OUTPUT) {
  writeFileSync(process.env.TELEMETRY_PLUGIN_IDS_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log(`Wrote ${Object.keys(results).length} real initialization plugin array cases`);
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} real initialization plugin arrays match the Rust fixture`);
}
