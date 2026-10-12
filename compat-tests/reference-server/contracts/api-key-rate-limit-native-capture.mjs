import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import {
  assertSecondaryNativeVersions, createSecondaryNativeObserver,
  secondaryNativeNow as now, secondaryNativeVersion as version, withSecondarySourceExports,
} from "./secondary-native-shared.mjs";

export const apiKeyRateLimitScenarios = [
  "skip-global", "skip-key", "skip-null-window", "skip-null-maximum", "start-null", "absent-last",
  "reset", "deny", "increment", "first-window-failure", "count-failure", "maximum-failure",
  "second-window-failure", "reset-second-window-failure", "deny-second-window-failure",
];

function seed() {
  return {
    id: "usage-key", name: "Usage key", start: null, prefix: null,
    key: "usage-secret", referenceId: "owner", configId: "default",
    refillInterval: null, refillAmount: null, lastRefillAt: null,
    enabled: true, rateLimitEnabled: true, rateLimitTimeWindow: 2_000,
    rateLimitMax: 3, requestCount: 2, remaining: 3, lastRequest: new Date(now - 1_000),
    expiresAt: null, createdAt: new Date(now - 60_000), updatedAt: new Date(now - 60_000),
    permissions: null, metadata: null,
  };
}

function setup(name) {
  const state = createSecondaryNativeObserver();
  const original = { cause: name };
  function primitive(label, values, failure) {
    let calls = 0;
    const object = {
      valueOf(...args) {
        state.call(label, this, object, args);
        const index = calls++;
        if (index === failure) throw original;
        assert.ok(index < values.length, `Unexpected ${label} conversion`);
        return values[index];
      },
    };
    return object;
  }
  const reset = name.startsWith("reset");
  const denied = name.startsWith("deny");
  const windowFailure = name === "first-window-failure" || name === "start-null" ? 0
    : name.includes("second-window-failure") ? 1 : undefined;
  const key = {
    ...seed(),
    rateLimitTimeWindow: primitive("window", [reset ? 100 : 2_000, 3_500], windowFailure),
    requestCount: primitive("count", [2, 4], name === "count-failure" ? 0 : undefined),
    rateLimitMax: primitive("maximum", [denied ? 2 : 3], name === "maximum-failure" ? 0 : undefined),
  };
  const opts = { rateLimit: { enabled: name !== "skip-global" } };
  if (name === "skip-key") key.rateLimitEnabled = false;
  if (name === "skip-null-window") key.rateLimitTimeWindow = null;
  if (name === "skip-null-maximum") key.rateLimitMax = null;
  if (name === "start-null") key.lastRequest = null;
  if (name === "absent-last") delete key.lastRequest;
  return { state, original, key, opts };
}

async function decisionCase(source, boundary, name) {
  const { state, original, key, opts } = setup(name);
  const before = state.snapshot(key);
  let result;
  const outcome = await state.outcome(() => {
    result = source[boundary](key, opts);
    return result;
  }, original);
  return {
    name, boundary, before, outcome, after: state.snapshot(key), events: state.events,
    maximumIdentity: result?.type === "increment" ? result.max === key.rateLimitMax : null,
  };
}

async function databaseCase(source) {
  const name = "second-window-failure";
  const { state, original, key, opts } = setup(name);
  const memory = { user: [], session: [], account: [], verification: [], apikey: [seed()] };
  const auth = betterAuth({
    database: memoryAdapter(memory), baseURL: "http://api-key-rate-limit-native.test",
    secret: "api-key-rate-limit-native-contract-at-least-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    plugins: [apiKey(), {
      id: "rate-limit-native-observer",
      schema: { apikey: { fields: {
        rateLimitTimeWindow: { type: "number", transform: { output(value) {
          state.record("output-window", { value: state.snapshot(value) });
          return key.rateLimitTimeWindow;
        } } },
        rateLimitMax: { type: "number", transform: { output() { return key.rateLimitMax; } } },
        requestCount: { type: "number", transform: { output() { return key.requestCount; } } },
      } } },
    }],
  });
  const context = await auth.$context;
  const before = state.snapshot(memory);
  const row = await context.adapter.findOne({ model: "apikey", where: [{ field: "id", value: key.id }] });
  assert.ok(row);
  const outcome = await state.outcome(() => source.claimUsageInDatabase({
    ctx: { context }, apiKey: row, opts: { ...opts, storage: "database" }, hashedKey: key.key,
  }), original);
  assert.equal(outcome.returned, false);
  assert.equal(outcome.sameOriginal, true);
  assert.equal(memory.apikey.length, 1);
  assert.equal(memory.apikey[0].remaining, 2);
  assert.equal(memory.apikey[0].requestCount, 2);
  assert.deepEqual(memory.apikey[0], { ...seed(), remaining: 2 });
  return { name, boundary: "database", before, outcome, after: state.snapshot(memory), events: state.events };
}

async function secondaryCase(source, name) {
  const { state, original, key, opts } = setup(name);
  const values = new Map([
    ["api-key:usage-secret", JSON.stringify(seed())],
    ["api-key:by-id:usage-key", JSON.stringify(seed())],
    ["api-key:by-ref:owner", '["usage-key"]'],
  ]);
  const before = state.snapshot([...values]);
  const storageEvents = [];
  const customStorage = {
    async get(key) { storageEvents.push(["get", key]); return values.get(key) ?? null; },
    async set(key, value, ttl) { storageEvents.push(["set", key, value, ttl]); values.set(key, value); },
    async delete(key) { storageEvents.push(["delete", key]); values.delete(key); },
  };
  const outcome = await state.outcome(() => source.claimUsageInSecondaryStorage({
    ctx: { context: {} }, apiKey: key,
    opts: { ...opts, storage: "secondary-storage", customStorage, deferUpdates: false }, hashedKey: key.key,
  }), original);
  if (name === "second-window-failure") {
    assert.equal(outcome.returned, false);
    assert.equal(outcome.sameOriginal, true);
    assert.deepEqual(storageEvents, []);
    assert.deepEqual(state.snapshot([...values]), before);
  } else {
    assert.equal(outcome.returned, true);
    assert.deepEqual(state.events, []);
    const updated = JSON.parse(values.get("api-key:usage-secret"));
    assert.equal(updated.remaining, 2);
    assert.equal(updated.requestCount, 1);
    assert.equal(updated.lastRequest, new Date(now).toISOString());
    assert.equal(values.get("api-key:by-id:usage-key"), values.get("api-key:usage-secret"));
  }
  return {
    name, boundary: "secondary", before, outcome, after: state.snapshot([...values]),
    events: state.events, storageEvents: state.snapshot(storageEvents),
  };
}

export async function captureApiKeyRateLimitNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key"]);
  return await withClock(async setClock => {
    setClock(now);
    return await withSecondarySourceExports("@better-auth/api-key", [
      "evaluateRateLimit", "applyRateLimitToSnapshot", "claimUsageInDatabase", "claimUsageInSecondaryStorage",
    ], async (source, provenance) => {
      const cases = [];
      for (const boundary of ["evaluateRateLimit", "applyRateLimitToSnapshot"]) {
        for (const name of apiKeyRateLimitScenarios) cases.push(await decisionCase(source, boundary, name));
      }
      cases.push(await databaseCase(source));
      for (const name of ["start-null", "second-window-failure"]) cases.push(await secondaryCase(source, name));
      assert.equal(cases.length, 33);
      return { version, contract: "api-key-rate-limit-native", provenance, scenarios: apiKeyRateLimitScenarios, cases };
    });
  });
}

if (import.meta.main) {
  const output = `${JSON.stringify(await captureApiKeyRateLimitNative(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], output);
  else process.stdout.write(output);
}
