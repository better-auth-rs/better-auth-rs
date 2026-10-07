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
  const observation = {
    runtime: { name: typeof Bun === "undefined" ? "node" : "bun", version: typeof Bun === "undefined" ? process.versions.node : Bun.version, versions: process.versions },
    packages: {},
    stdout: { mode: "pipe", isTTY: process.stdout.isTTY ?? null },
    direct: [],
    auth: [],
    fetches: [],
  };
  globalThis.fetch = async (input, init) => {
    observation.fetches.push(String(input));
    observation.auth.push(JSON.parse(init.body));
    return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
  };
  try {
    for (const name of ["better-auth", "@better-auth/telemetry"]) {
      const entrypoint = import.meta.resolve(name);
      const { version } = JSON.parse(readFileSync(new URL("../package.json", entrypoint), "utf8"));
      observation.packages[name] = { version, entrypoint };
    }
    const { createTelemetry } = await import("@better-auth/telemetry");
    const { isTest } = await import("@better-auth/core/env");
    const { betterAuth } = await import("better-auth");
    const options = { secret: "telemetry-environment-normal-secret-0123456789", baseURL: "https://example.test", logger: { disabled: true }, telemetry: { enabled: true } };
    await createTelemetry(options, { customTrack: async event => { observation.direct.push(event); }, skipTestCheck: true });
    const auth = betterAuth(options);
    await auth.$context;
    observation.emits = !isTest();
  } finally {
    process.stdout.write(JSON.stringify(observation));
  }
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
  const nativeObservations = { clearedKeys, cases: {} };
  const saveObservations = () => {
    if (process.env.TELEMETRY_ENVIRONMENT_OUTPUT) {
      writeFileSync(process.env.TELEMETRY_ENVIRONMENT_OUTPUT + ".system-observation.json", JSON.stringify(nativeObservations, null, 2) + "\n");
    }
  };
  for (const [name, overrides] of Object.entries(cases)) {
    const env = { ...process.env };
    for (const key of clearedKeys) delete env[key];
    Object.assign(env, overrides, { BETTER_AUTH_TELEMETRY_ENDPOINT: "https://telemetry-environment.test/capture" });
    const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--observe"], { env, encoding: "utf8" });
    const captured = { env: overrides, status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr, error: result.error?.message };
    nativeObservations.cases[name] = captured;
    saveObservations();
    assert.equal(result.status, 0, `${name}: ${result.stderr}`);
    const observed = JSON.parse(result.stdout);
    captured.observation = observed;
    saveObservations();
    assert.equal(observed.direct.length, 1);
    const metadata = publicMetadata(observed.direct[0].payload);
    assert.equal(observed.direct[0].payload.runtime.name, typeof Bun === "undefined" ? "node" : "bun");
    for (const endpoint of observed.fetches) assert.equal(endpoint, "https://telemetry-environment.test/capture");
    assert.deepEqual(observed.fetches, observed.emits ? ["https://telemetry-environment.test/capture"] : []);
    assert.equal(observed.auth.length, observed.emits ? 1 : 0);
    if (observed.emits) assert.deepEqual(publicMetadata(observed.auth[0].payload), metadata);
    results.cases[name] = { env: overrides, metadata, authEvents: observed.auth.length };
  }
  const fixture = new URL("../../../tests/fixtures/telemetry-environment-1.7.6.json", import.meta.url);
  if (process.env.TELEMETRY_ENVIRONMENT_OUTPUT) {
    writeFileSync(process.env.TELEMETRY_ENVIRONMENT_OUTPUT, JSON.stringify(results, null, 2) + "\n");
    console.log(`Wrote ${Object.keys(cases).length} telemetry environment cases`);
  } else {
    assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
    console.log(`${Object.keys(cases).length} telemetry environment cases match the Rust fixture`);
  }
}
