import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createSecondaryNativeObserver, secondaryNativeNow as now } from "./secondary-native-shared.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";

export const consumerOrigin = "http://verification-consumer-native.test";
export const consumerSecret = "verification-consumer-native-secret-at-least-thirty-two-characters";
export const consumerEmail = "owner@verification-consumer-native.test";
export const consumerPhone = "+12025550123";
export const consumerUser = () => ({ id: "owner", name: "Verification consumer", email: consumerEmail,
  emailVerified: true, image: null, createdAt: new Date(now), updatedAt: new Date(now), twoFactorEnabled: true });

export function createConsumerHarness(scenario, identifier) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver();
  const events = [];
  const original = { code: "CONSUMER_ORIGINAL_FAILURE", mutation: 0, ownUndefined: undefined };
  const counts = { expiry: 0, value: 0, split: 0, slice: 0, generated: 0 };
  let active = false;
  const cache = new Map();
  const targetKey = `verification:${identifier}`;
  const retained = { value: "unchanged", ownUndefined: undefined };
  const database = { user: [consumerUser()], session: [], account: [], verification: [] };
  const event = (phase, fields = {}, audit = fields) => {
    if (!active) return;
    events.push({ phase, ...fields });
    native.record(phase, audit);
  };
  const fail = phase => { original.mutation += 1; event(phase, { mutation: original.mutation }); throw original; };
  const method = (object, name, body) => Object.defineProperty(object, name, {
    configurable: true, get() {
      event(`get:${name}`, { sameReceiver: this === object });
      if (scenario.fail === `${name}:get`) fail(`throw:${name}:get`);
      return function (...args) {
        event(`call:${name}`, { sameReceiver: this === object, arguments: runtime.value(args) },
          { sameReceiver: this === object, arguments: native.snapshot(args) });
        if (scenario.fail === `${name}:call`) fail(`throw:${name}:call`);
        return body(args);
      };
    },
  });
  const expiry = () => {
    switch (scenario.expiry) {
      case "missing": case "undefined": return undefined;
      case "null": return null;
      case "nan": return NaN;
      case "invalid-date": return new Date(NaN);
      case "expired": return new Date(now - 1);
      case "equal": return new Date(now);
      case "object": case "conversion-error": {
        const value = {};
        method(value, "valueOf", () => scenario.expiry === "conversion-error" ? fail("throw:expiry-conversion") : now + 60_000);
        return value;
      }
      default: return new Date(now + 60_000);
    }
  };
  const attempts = () => {
    if (scenario.attempts === "string-object" || scenario.attempts === "string-error") {
      const value = { marker: "attempts" };
      method(value, "toString", () => scenario.attempts === "string-error" ? fail("throw:attempt-conversion") : "  +2tail");
      return value;
    }
    if (scenario.attempts === "object" || scenario.attempts === "conversion-error") {
      const value = { marker: "attempts" };
      method(value, "valueOf", () => scenario.attempts === "conversion-error" ? fail("throw:attempt-conversion") : 1);
      return value;
    }
    if (scenario.attempts === "false") return false;
    if (scenario.attempts === "nan") return NaN;
    return scenario.exhausted ? "3" : "0";
  };
  const otp = () => scenario.otpShape === "array" ? [49, 50, 51, 52, 53, 54]
    : scenario.otpShape === "array-like" ? { 0: 49, 1: 50, 2: 51, 3: 52, 4: 53, 5: 54, length: 6 }
    : "123456";
  let value;
  if (scenario.value === "methods") {
    value = { marker: "native-otp" };
    method(value, "lastIndexOf", () => {
      if (scenario.index === "string") return "6";
      if (scenario.index === "object") {
        const index = { marker: "index" };
        method(index, "valueOf", () => 6);
        return index;
      }
      return scenario.noColon ? -1 : 6;
    });
    method(value, "slice", () => {
      counts.slice += 1;
      return counts.slice % 2 ? otp() : scenario.exhausted ? "3" : "0";
    });
    method(value, "split", () => {
      counts.split += 1;
      if (scenario.fail === "split:second" && counts.split === 2) fail("throw:split:second");
      const raw = attempts();
      if (scenario.splitShape === "null") return null;
      if (scenario.splitShape === "undefined") return undefined;
      if (scenario.splitShape === "string") return "12";
      if (scenario.splitShape === "array-like") return { 0: "123456", 1: raw, length: 2 };
      return ["123456", raw];
    });
  } else if (scenario.value === "undefined") value = undefined;
  else if (scenario.value === "null") value = null;
  else if (scenario.value === "false") value = false;
  else if (scenario.value === "zero") value = 0;
  else if (scenario.value === "nan") value = NaN;
  else if (scenario.value === "empty") value = "";
  else if (scenario.value === "owner") value = "owner";
  else if (scenario.value === "other-user") value = "other-user";
  else if (scenario.value === "object") value = { ownUndefined: undefined, marker: "native-value" };
  else value = `123456:${scenario.exhausted ? 3 : 0}`;
  const root = scenario.root === "function" ? function verificationRoot() {} : new Date(now);
  Object.assign(root, { id: "verification-row", identifier, createdAt: new Date(now), updatedAt: new Date(now) });
  if (scenario.expiry !== "missing") Object.defineProperty(root, "expiresAt", {
    configurable: true, enumerable: true, get() {
      counts.expiry += 1;
      event("get:expiresAt", { sameReceiver: this === root, read: counts.expiry });
      if (scenario.fail === "expiry:get" || scenario.fail === "expiry:second" && counts.expiry === 2) fail("throw:expiry:get");
      return expiry();
    },
  });
  Object.defineProperty(root, "value", { configurable: true, enumerable: true, get() {
    counts.value += 1;
    event("get:value", { sameReceiver: this === root, read: counts.value, sameValue: true });
    if (scenario.fail === "value:get" || scenario.fail === "value:second" && counts.value === 2) fail("throw:value:get");
    return value;
  } });
  cache.set(targetKey, scenario.root === "missing" ? undefined : root);
  cache.set("verification:retained", retained);
  const storage = {
    async get(key) {
      const present = cache.has(key);
      const result = present ? cache.get(key) : null;
      event("storage.get", { key, present, sameRoot: result === root, value: runtime.value(result) },
        { key, present, sameRoot: result === root, value: native.snapshot(result) });
      return result;
    },
    async set(key, next, ttl) {
      event("storage.set", { key, value: runtime.value(next), ttl: runtime.value(ttl) });
      cache.set(key, next);
      if (scenario.fail === "set:after") fail("throw:storage.set:after");
    },
    async delete(key) {
      event("storage.delete", { key, present: cache.has(key) });
      cache.delete(key);
      if (scenario.fail === "delete:after" || scenario.fail === "session-delete:after" && key === "new-session") fail("throw:storage.delete:after");
    },
    async getAndDelete(key) {
      const present = cache.has(key);
      const result = present ? cache.get(key) : null;
      cache.delete(key);
      event("storage.getAndDelete", { key, present, sameRoot: result === root, remainingKeys: [...cache.keys()] },
        { key, present, value: native.snapshot(result), remainingKeys: [...cache.keys()] });
      return result;
    },
  };
  const logger = { level: "debug", log(level, message, ...args) {
    event(`logger:${level}`, { message, arguments: args.map(errorValue) }, { message, arguments: native.snapshot(args) });
  } };
  function errorValue(error) {
    if (!(error instanceof Error)) return runtime.value(error);
    return { name: error.name, message: error.message, ownEnumerable: runtime.ownValues(error),
      ...(error.status === undefined ? {} : { status: error.status, statusCode: error.statusCode,
        body: runtime.value(error.body), headers: error.headers ? [...new Headers(error.headers)] : [] }) };
  }
  const state = () => ({ database, cache: [...cache], targetPresent: cache.has(targetKey),
    targetSameRoot: cache.get(targetKey) === root, retainedSameObject: cache.get("verification:retained") === retained,
    counts: { ...counts }, original: { ...original } });
  const options = {
    baseURL: consumerOrigin, secret: consumerSecret, database: memoryAdapter(database),
    telemetry: { enabled: false }, rateLimit: { enabled: false }, logger,
    verification: { storeInDatabase: false, storeIdentifier: "plain" }, secondaryStorage: storage,
    advanced: { database: { generateId({ model }) {
      const id = `${model}-generated-${++counts.generated}`;
      event("generate-id", { model, id });
      return id;
    } } },
  };
  return { native, runtime, original, counts, root, value, cache, targetKey, database, event, fail, options,
    async capture(plugins, operation, extraOptions = {}) {
      const auth = betterAuth({ ...options, ...extraOptions, plugins });
      const context = await auth.$context;
      const input = native.snapshot(root);
      const before = native.snapshot(state());
      const runtimeBefore = runtime.value(state());
      active = true;
      let runtimeOutcome;
      let result;
      let caught;
      const outcome = await native.outcome(async () => {
        try {
          result = await operation(auth, context);
          runtimeOutcome = { returned: true, result: runtime.value(result) };
          return result;
        } catch (error) {
          if (error instanceof assert.AssertionError) throw error;
          caught = error;
          runtimeOutcome = { returned: false, sameOriginal: error === original, error: errorValue(error) };
          throw error;
        }
      }, original);
      assert.equal(cache.get("verification:retained"), retained);
      assert.deepEqual(database.user, [consumerUser()]);
      assert.deepEqual(database.verification, []);
      assert.deepEqual(database.account, []);
      assert.deepEqual(database.session, []);
      const after = native.snapshot(state());
      return { observation: { name: scenario.name, scenario, input, before, outcome, events: native.events, after,
        inputAfter: native.snapshot(root), functions: native.functions,
        runtime: { before: runtimeBefore, outcome: runtimeOutcome, events, after: runtime.value(state()), functionIds: runtime.functionIds } }, result, caught };
    },
  };
}
