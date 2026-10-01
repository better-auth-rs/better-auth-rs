import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ciKeys = ["BUILD_ID", "BUILD_NUMBER", "CI", "CI_APP_ID", "CI_BUILD_ID", "CI_BUILD_NUMBER", "CI_NAME", "CONTINUOUS_INTEGRATION", "RUN_ID"];
const vendors = [
  ["cloudflare", ["CF_PAGES", "CF_PAGES_URL", "CF_ACCOUNT_ID"]],
  ["vercel", ["VERCEL", "VERCEL_URL", "VERCEL_ENV"]],
  ["netlify", ["NETLIFY", "NETLIFY_URL"]],
  ["render", ["RENDER", "RENDER_URL", "RENDER_INTERNAL_HOSTNAME", "RENDER_SERVICE_ID"]],
  ["aws", ["AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "LAMBDA_TASK_ROOT"]],
  ["gcp", ["GOOGLE_CLOUD_FUNCTION_NAME", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "K_SERVICE"]],
  ["azure", ["AZURE_FUNCTION_NAME", "FUNCTIONS_WORKER_RUNTIME", "WEBSITE_INSTANCE_ID", "WEBSITE_SITE_NAME"]],
  ["deno-deploy", ["DENO_DEPLOYMENT_ID", "DENO_REGION"]],
  ["fly-io", ["FLY_APP_NAME", "FLY_REGION", "FLY_ALLOC_ID"]],
  ["railway", ["RAILWAY_STATIC_URL", "RAILWAY_ENVIRONMENT_NAME"]],
  ["heroku", ["DYNO", "HEROKU_APP_NAME"]],
  ["digitalocean", ["DO_DEPLOYMENT_ID", "DO_APP_NAME", "DIGITALOCEAN"]],
  ["koyeb", ["KOYEB", "KOYEB_DEPLOYMENT_ID", "KOYEB_APP_NAME"]],
];
const clearedKeys = [...new Set(["NODE_ENV", "TEST", "npm_config_user_agent", "BETTER_AUTH_TELEMETRY", "BETTER_AUTH_TELEMETRY_DEBUG", "BETTER_AUTH_TELEMETRY_ENDPOINT", ...ciKeys, ...vendors.flatMap(([, keys]) => keys)])];

function publicMetadata(payload) {
  return JSON.parse(JSON.stringify({ environment: payload.environment, systemInfo: { deploymentVendor: payload.systemInfo.deploymentVendor }, packageManager: payload.packageManager }));
}

if (process.argv[2] === "--observe") {
  const direct = [];
  const http = [];
  const fetches = [];
  const endpoint = "https://telemetry-environment.test/capture";
  globalThis.fetch = async (input, init) => {
    fetches.push(String(input));
    assert.equal(String(input), endpoint);
    http.push(JSON.parse(init.body));
    return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const { createTelemetry } = await import("@better-auth/telemetry");
  const { isTest } = await import("@better-auth/core/env");
  const { betterAuth } = await import("better-auth");
  const options = { secret: "telemetry-environment-normal-secret-0123456789", baseURL: "https://example.test", logger: { disabled: true }, telemetry: { enabled: true } };
  await createTelemetry(options, { customTrack: async event => { direct.push(event); }, skipTestCheck: true });
  assert.equal(direct.length, 1);
  const metadata = publicMetadata(direct[0].payload);
  assert.equal(direct[0].payload.runtime.name, typeof Bun === "undefined" ? "node" : "bun");
  const auth = betterAuth(options);
  await auth.$context;
  const emits = !isTest();
  assert.deepEqual(fetches, emits ? [endpoint] : []);
  assert.equal(http.length, emits ? 1 : 0);
  if (emits) assert.deepEqual(publicMetadata(http[0].payload), metadata);
  process.stdout.write(JSON.stringify({ metadata, authEvents: http.length, nativeSystemInfo: direct[0].payload.systemInfo, nativeRuntime: direct[0].payload.runtime }));
} else {
  const cases = {
    omitted: {},
    development: { NODE_ENV: "development" },
    staging: { NODE_ENV: "staging" },
    production: { NODE_ENV: "production" },
    ciFalseOverridesMarkers: { CI: "false", BUILD_ID: "1" },
    ciCapitalFalse: { CI: "False" },
    productionOverCiAndTest: { NODE_ENV: "production", CI: "", TEST: "1" },
    nodeTest: { NODE_ENV: "test" },
    emptyTest: { TEST: "" },
    falseTest: { TEST: "false" },
    zeroTest: { TEST: "0" },
    capitalFalseTest: { TEST: "FALSE" },
    ciOverTest: { CI: "", TEST: "1" },
    emptyVendor: { CF_PAGES: "", VERCEL: "" },
    falseVendorIsPresent: { CF_PAGES: "false", VERCEL: "1" },
    zeroVendorIsPresent: { VERCEL: "0" },
  };
  for (const key of ciKeys) cases[`ciPresence-${key}`] = { [key]: "" };
  for (const [vendor, keys] of vendors) {
    for (const key of keys) cases[`vendor-${vendor}-${key}`] = { [key]: "1" };
  }
  for (let index = 0; index < vendors.length - 1; index++) {
    cases[`vendorPriority-${vendors[index][0]}`] = Object.fromEntries(vendors.slice(index).map(([, keys]) => [keys[0], "1"]));
  }
  for (const [name, agent] of Object.entries({ empty: "", npm: "npm/10.8.2 node/v22.1.0", pnpm: "pnpm/10.4.1 npm/? node/v22.1.0", yarn: "yarn/4.0.0", bun: "bun/1.4.2", cnpm: "npminstall/7.12.0", scoped: "@scope/pnpm/10.4.1 node/v22.1.0", noSlash: "npm", leadingSpace: " npm/10.8.2" })) {
    cases[`package-${name}`] = { npm_config_user_agent: agent };
  }
  const results = { clearedKeys, cases: {} };
  let nativeObservation;
  for (const [name, overrides] of Object.entries(cases)) {
    const env = { ...process.env };
    for (const key of clearedKeys) delete env[key];
    Object.assign(env, overrides, { BETTER_AUTH_TELEMETRY_ENDPOINT: "https://telemetry-environment.test/capture" });
    const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--observe"], { env, encoding: "utf8" });
    assert.equal(result.status, 0, `${name}: ${result.stderr}`);
    const observed = JSON.parse(result.stdout);
    nativeObservation ??= { runtime: observed.nativeRuntime, systemInfo: observed.nativeSystemInfo };
    results.cases[name] = { env: overrides, metadata: observed.metadata, authEvents: observed.authEvents };
  }
  const fixture = new URL("../../../tests/fixtures/telemetry-environment-1.7.6.json", import.meta.url);
  if (process.env.TELEMETRY_ENVIRONMENT_OUTPUT) {
    writeFileSync(process.env.TELEMETRY_ENVIRONMENT_OUTPUT, JSON.stringify(results, null, 2) + "\n");
    writeFileSync(process.env.TELEMETRY_ENVIRONMENT_OUTPUT + ".system-observation.json", JSON.stringify(nativeObservation, null, 2) + "\n");
    console.log(`Wrote ${Object.keys(cases).length} telemetry environment cases`);
  } else {
    assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
    console.log(`${Object.keys(cases).length} telemetry environment cases match the Rust fixture`);
  }
}
