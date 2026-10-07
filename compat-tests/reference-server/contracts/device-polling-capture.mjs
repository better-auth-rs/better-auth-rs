import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization, redeemDeviceCode } from "better-auth/plugins/device-authorization";
import { observeValue } from "./device-where-capture.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";

const version = "1.7.6";
const origin = "http://device-polling.test";
const timestampMillis = 2_000_000_000_000;
const tables = ["user", "session", "account", "verification", "deviceCode"];
const authorizationContext = { issuer: "polling-issuer" };
const redemptionContext = { prepared: true };
const scenarios = [
  { name: "zero-future", interval: 0, offset: 1000, blocked: false },
  { name: "zero-past", interval: 0, offset: -1000, blocked: false },
  { name: "negative-zero-future", interval: -0, offset: 1000, blocked: false },
  { name: "negative-zero-past", interval: -0, offset: -1000, blocked: false },
  { name: "positive-future", interval: 5000, offset: 1000, blocked: true },
  { name: "positive-recent", interval: 5000, offset: -4999, blocked: true },
  { name: "positive-boundary", interval: 5000, offset: -5000, blocked: false },
  { name: "positive-past", interval: 5000, offset: -5001, blocked: false },
  { name: "fractional-recent", interval: 1.5, offset: -1, blocked: true },
  { name: "fractional-past", interval: 1.5, offset: -2, blocked: false },
  { name: "nan-future", interval: NaN, offset: 1000, blocked: false, backend: "memory" },
  { name: "nan-past", interval: NaN, offset: -1000, blocked: false, backend: "memory" },
];

function observe(value) {
  if (Object.is(value, -0)) return { type: "number", value: "-0" };
  if (Array.isArray(value)) return value.map(observe);
  if (value !== null && typeof value === "object" && !(value instanceof Date)) {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, observe(child)]));
  }
  return observeValue(value);
}

function errorObservation(error) {
  return {
    name: error?.name, message: error?.message,
    status: observe(error?.status), statusCode: observe(error?.statusCode),
    body: observe(error?.body),
    headers: error?.headers instanceof Headers ? [...error.headers] : observe(error?.headers),
  };
}

async function captureCase(backend, surface, scenario, diagnostics) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const options = {
    database: sqlite ?? memoryAdapter(memory), baseURL: origin,
    secret: "device-polling-contract-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    plugins: [deviceAuthorization({ validateClient(clientId) {
      events.push({ kind: "validate-client", clientId });
      return true;
    } })],
  };
  const snapshot = () => observe(Object.fromEntries(tables.map(model => [model,
    sqlite ? sqlite.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model],
  ])));
  const label = { backend, surface, scenario: scenario.name };
  try {
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const context = await auth.$context;
    const { adapter } = context;
    const owner = await adapter.create({ model: "user", forceAllowId: true, data: {
      id: "polling-owner", name: "Polling owner", email: "owner@device-polling.test",
      emailVerified: false, image: null,
      createdAt: new Date(timestampMillis), updatedAt: new Date(timestampMillis),
    } });
    const input = {
      id: "polling-device", deviceCode: "polling-device-code", userCode: "ABCD2345", userId: owner.id,
      expiresAt: new Date(timestampMillis + 60_000), status: surface === "helper" ? "approved" : "pending",
      lastPolledAt: new Date(timestampMillis + scenario.offset), pollingInterval: scenario.interval,
      clientId: "polling-client", scope: "read",
    };
    const seeded = observe(await adapter.create({ model: "deviceCode", forceAllowId: true, data: input }));
    const before = snapshot();
    const seedEvents = events.splice(0);
    diagnostics.push({ ...label, stage: "seed", input: observe(input), seeded, events: seedEvents, before });
    let outcome;
    let request = null;
    try {
      if (surface === "helper") {
        const result = await redeemDeviceCode({
          ctx: { context }, deviceCode: input.deviceCode,
          async authorizeRedemption(row) {
            events.push({ kind: "authorize", row: observe(row) });
            return { ownershipWhere: { field: "clientId", value: "polling-client" }, context: authorizationContext };
          },
          async prepareRedemption(row, authorization) {
            events.push({ kind: "prepare", row: observe(row), authorizationContext: observe(authorization) });
            return redemptionContext;
          },
        });
        outcome = { kind: "returned", value: observe(result) };
      } else {
        request = {
          method: "POST", url: `${origin}/api/auth/device/token`,
          headers: { origin, "content-type": "application/json" },
          body: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: input.deviceCode, client_id: "polling-client" },
        };
        const response = await auth.handler(new Request(request.url, {
          method: request.method, headers: request.headers, body: JSON.stringify(request.body),
        }));
        outcome = { kind: "response", value: {
          status: response.status, statusText: response.statusText,
          headers: [...response.headers], cookies: response.headers.getSetCookie(), body: await response.text(),
        } };
      }
    } catch (error) {
      outcome = { kind: "thrown", apiError: error instanceof APIError, error: errorObservation(error) };
      diagnostics.push({ ...label, stage: "operation-error", error: errorObservation(error), stack: error?.stack });
    }
    const after = snapshot();
    const observed = {
      ...label, scenario: observe(scenario), owner: observe(owner),
      input: observe(input), seeded, seedEvents, before, request, outcome, events, after,
    };
    diagnostics.push({ ...label, stage: "complete", observation: observed });
    return observed;
  } catch (error) {
    diagnostics.push({ ...label, stage: "capture-error", events: observe(events), error: errorObservation(error), stack: error?.stack });
    throw error;
  } finally { sqlite?.close(); }
}

export async function captureDevicePolling({ diagnostics = [] } = {}) {
  const versions = Object.fromEntries(["better-auth", "@better-auth/core", "@better-auth/memory-adapter"].map(name => [
    name, JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version,
  ]));
  return withClock(async setClock => {
    setClock(timestampMillis);
    const cases = [];
    for (const backend of ["memory", "sqlite"]) {
      for (const scenario of scenarios.filter(scenario => !scenario.backend || scenario.backend === backend)) {
        for (const surface of ["helper", "http"]) cases.push(await captureCase(backend, surface, scenario, diagnostics));
      }
    }
    return { version, versions, timestampMillis, scenarios: observe(scenarios), cases };
  });
}

export function assertDevicePolling(observed) {
  assert.equal(observed.version, version);
  for (const capturedVersion of Object.values(observed.versions)) assert.equal(capturedVersion, version);
  assert.equal(observed.cases.length, 44);
  for (const entry of observed.cases) {
    const { backend, surface, scenario, seeded, outcome, events, before, after } = entry;
    if (scenario.name.startsWith("nan-")) {
      assert.equal(backend, "memory");
      assert.deepEqual(seeded.pollingInterval, { type: "number", value: "NaN" });
      assert.deepEqual(before.deviceCode[0].pollingInterval, seeded.pollingInterval);
    }
    for (const model of tables.filter(model => model !== "deviceCode")) assert.deepEqual(after[model], before[model]);
    assert.deepEqual(entry.seedEvents, []);
    const body = { error: scenario.blocked ? "slow_down" : "authorization_pending", error_description: scenario.blocked
      ? "Polling too frequently" : "Authorization pending" };
    if (surface === "http") {
      assert.equal(outcome.kind, "response");
      assert.equal(outcome.value.status, 400);
      assert.deepEqual(outcome.value.cookies, []);
      assert.deepEqual(JSON.parse(outcome.value.body), body);
      assert.deepEqual(events, [{ kind: "validate-client", clientId: "polling-client" }]);
    } else {
      assert.deepEqual(events, scenario.blocked
        ? [{ kind: "authorize", row: seeded }]
        : [{ kind: "authorize", row: seeded }, { kind: "prepare", row: seeded, authorizationContext }]);
      if (scenario.blocked) {
        assert.equal(outcome.kind, "thrown");
        assert.equal(outcome.apiError, true);
        assert.equal(outcome.error.status, "BAD_REQUEST");
        assert.equal(outcome.error.statusCode, 400);
        assert.deepEqual(outcome.error.body, body);
      } else {
        assert.equal(outcome.kind, "returned");
        assert.deepEqual(outcome.value, {
          claimedDeviceCode: { ...seeded, lastPolledAt: { type: "date", value: new Date(timestampMillis).toISOString() } },
          authorizationContext, redemptionContext, user: entry.owner,
        });
      }
    }
    if (scenario.blocked) assert.deepEqual(after, before);
    else if (surface === "helper") assert.deepEqual(after.deviceCode, []);
    else assert.deepEqual(after.deviceCode, [{ ...before.deviceCode[0], lastPolledAt: backend === "memory"
      ? { type: "date", value: new Date(timestampMillis).toISOString() } : new Date(timestampMillis).toISOString() }]);
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the Device polling fixture output path");
  const diagnostics = [];
  try {
    const observed = await captureDevicePolling({ diagnostics });
    writeFileSync(`${output}.raw.json`, `${JSON.stringify(observed, null, 2)}\n`);
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
    assertDevicePolling(observed);
    writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
