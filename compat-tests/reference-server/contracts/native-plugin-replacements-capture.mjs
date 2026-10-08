import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { getAuthTables } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization, jwt, twoFactor } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";
import { address, walletPlugin } from "./wallet-additional-fields.ts";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key", "@better-auth/passkey"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const fixedDate = "2030-01-02T03:04:05.000Z";
const ownerId = "native-replacement-owner";
const rowId = "native-replacement-row";
const column = "stored_native_value";

export const nativeReplacementTargets = [
  { name: "api-key-remaining-number", model: "apikey", field: "remaining", type: "number" },
  { name: "api-key-remaining-string", model: "apikey", field: "remaining", type: "string" },
  { name: "api-key-enabled-boolean", model: "apikey", field: "enabled", type: "boolean" },
  { name: "api-key-enabled-number", model: "apikey", field: "enabled", type: "number" },
  { name: "api-key-expiry-date", model: "apikey", field: "expiresAt", type: "date" },
  { name: "passkey-counter-string", model: "passkey", field: "counter", type: "string" },
  { name: "passkey-backup-boolean", model: "passkey", field: "backedUp", type: "boolean" },
  { name: "device-polling-number", model: "deviceCode", field: "pollingInterval", type: "number" },
  { name: "two-factor-verified-boolean", model: "twoFactor", field: "verified", type: "boolean" },
  { name: "jwk-algorithm-array", model: "jwks", field: "alg", type: "string[]" },
  { name: "wallet-owner-number", model: "walletAddress", field: "userId", type: "number" },
  { name: "wallet-chain-number", model: "walletAddress", field: "chainId", type: "number" },
];
export const nativeReplacementInputs = ["provided", "omitted", "undefined", "null"];
export const nativeReplacementOperations = ["create", "read-created", "update", "read-updated"];
export const nativeReplacementProjections = ["object", "null", "undefined"];
export const nativeReplacementFailures = [
  { operation: "create", phase: "default" },
  { operation: "create", phase: "input" },
  { operation: "create", phase: "output" },
  { operation: "update", phase: "onUpdate" },
  { operation: "update", phase: "input" },
  { operation: "update", phase: "output" },
  { operation: "read", phase: "output" },
];

function nativePlugin(model) {
  return {
    apikey: apiKey, passkey, deviceCode: deviceAuthorization,
    twoFactor, jwks: jwt, walletAddress: walletPlugin,
  }[model]();
}

function nativeInput(model) {
  return {
    apikey: {
      name: "Desk", start: null, prefix: null, key: "ordinary-native-replacement-key", referenceId: ownerId,
      configId: "default", refillInterval: 60000, refillAmount: 10, lastRefillAt: null, enabled: true,
      rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3, requestCount: 0, remaining: 10,
      lastRequest: null, expiresAt: null, createdAt: new Date(fixedDate), updatedAt: new Date(fixedDate),
      permissions: null, metadata: null,
    },
    passkey: {
      name: "Desk", userId: ownerId, credentialID: "ordinary-native-credential", publicKey: "ordinary-public-key",
      counter: 0, deviceType: "singleDevice", backedUp: false, transports: null,
      createdAt: new Date(fixedDate), aaguid: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
    },
    deviceCode: {
      deviceCode: "ordinary-native-device", userCode: "ordinary-native-user", userId: ownerId,
      expiresAt: new Date("2032-01-02T03:04:05.000Z"), status: "pending", lastPolledAt: null,
      pollingInterval: 5000, clientId: "ordinary-native-client", scope: "read",
    },
    twoFactor: {
      userId: ownerId, secret: "ordinary-encrypted-secret", backupCodes: "ordinary-encrypted-codes",
      verified: false, failedVerificationCount: 0, lockedUntil: null,
    },
    jwks: {
      publicKey: "ordinary-public-key", privateKey: "ordinary-private-key", createdAt: new Date(fixedDate),
      expiresAt: null, alg: "EdDSA", crv: null,
    },
    walletAddress: { userId: ownerId, address, chainId: 1, isPrimary: false, createdAt: new Date(fixedDate) },
  }[model];
}

function valueFor(type, phase) {
  const index = ["create", "update", "default", "onUpdate", "transformed"].indexOf(phase);
  assert.notEqual(index, -1);
  if (type === "number") return 5.25 + index;
  if (type === "boolean") return index % 2 === 0;
  if (type === "string") return `replacement-${phase}`;
  if (type === "string[]") return ["replacement", phase];
  assert.equal(type, "date");
  return new Date(Date.parse(fixedDate) + (index + 1) * 86400000);
}

function observeDeclaration(value) {
  if (typeof value === "function") return { type: "function" };
  if (Array.isArray(value)) return value.map(observeDeclaration);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, observeDeclaration(item)]));
  }
  return observeValue(value);
}

function configuration(target, state, defaults = false) {
  const event = (phase, field, value) => {
    state.events.push({ phase, field, value: observeValue(value) });
    if (field === target.field && state.failure === phase) throw state.errors[phase];
  };
  const replacement = {
    type: target.type, required: false, fieldName: column,
    ...(defaults ? {
      defaultValue() { const value = valueFor(target.type, "default"); event("default", target.field, value); return value; },
      onUpdate() { const value = valueFor(target.type, "onUpdate"); event("onUpdate", target.field, value); return value; },
    } : {}),
    transform: {
      input(value) {
        event("input", target.field, value);
        return state.replaceInput ? valueFor(target.type, "transformed") : value;
      },
      output(value) {
        event("output", target.field, value);
        if (state.projection === "object") return { source: "output", field: target.field };
        if (state.projection === "null") return null;
        if (state.projection === "undefined") return undefined;
        return value;
      },
    },
  };
  return {
    baseURL: "http://native-replacements.test",
    secret: "ordinary-native-replacements-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [nativePlugin(target.model), {
      id: "native-field-replacement",
      schema: { [target.model]: { modelName: `native_${target.name.replaceAll("-", "_")}`, fields: {
        [target.field]: replacement,
        marker: { type: "string", required: false, fieldName: "stored_marker", transform: {
          input(value) { event("input", "marker", value); return value; },
          output(value) { event("output", "marker", value); return value; },
        } },
      } } },
    }],
  };
}

async function captureTarget(backend, target, diagnostics) {
  const state = { events: [], errors: Object.fromEntries(["default", "onUpdate", "input", "output"].map(phase => [phase, new Error(`ordinary native ${phase} error`)])) };
  let scenario = "setup";
  const base = configuration(target, state);
  const table = getAuthTables(base)[target.model];
  const tableName = table.modelName;
  const original = getAuthTables({ ...base, plugins: [nativePlugin(target.model)] })[target.model].fields[target.field];
  assert.ok(original, "The replacement must target an existing native field");
  const declaration = {
    original: observeDeclaration(original), replacement: observeDeclaration(table.fields[target.field]),
    defaulted: observeDeclaration(getAuthTables(configuration(target, state, true))[target.model].fields[target.field]),
    fields: Object.keys(table.fields),
  };
  const memory = { user: [], session: [], account: [], verification: [], [tableName]: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const database = sqlite ?? memoryAdapter(memory);
  try {
    if (sqlite) await (await getMigrations({ ...base, database })).runMigrations();
    const catalog = sqlite ? observeSqliteCatalog(sqlite, tableName, "The replacement table must exist") : null;
    const adapter = (await betterAuth({ ...base, database }).$context).adapter;
    const defaults = (await betterAuth({ ...configuration(target, state, true), database }).$context).adapter;
    const owner = await adapter.create({ model: "user", forceAllowId: true, data: {
      id: ownerId, name: "Native replacement owner", email: "owner@native-replacements.test", emailVerified: false,
      createdAt: new Date(fixedDate), updatedAt: new Date(fixedDate),
    } });
    assert.equal(owner.id, ownerId);
    const raw = () => (sqlite ? sqlite.query(`SELECT * FROM "${tableName}" ORDER BY "id"`).all() : memory[tableName])
      .map(row => ({ row: observeValue(row), keys: Object.keys(row) }));
    const where = [{ field: "id", value: rowId }];
    const parameters = (method, supplied) => {
      if (method === "findOne") return { model: target.model, where };
      if (method === "update") return { model: target.model, where, update: { marker: "updated", ...supplied } };
      const data = nativeInput(target.model);
      delete data[target.field];
      return { model: target.model, forceAllowId: true, data: { ...data, id: rowId, marker: "created", ...supplied } };
    };
    const observe = async (name, selected, method, supplied = {}) => {
      const input = parameters(method, supplied);
      diagnostics.push({ target: target.name, scenario, operation: name, phase: "start", method, input: observeValue(input) });
      let outcome;
      try {
        const result = await selected[method](input);
        outcome = { returned: true, result: observeValue(result), keys: result === null ? [] : Object.keys(result) };
      } catch (error) {
        if (error instanceof assert.AssertionError) throw error;
        assert.ok(error instanceof Error);
        outcome = { returned: false, error: {
          name: error.name, message: error.message, sameCallbackError: Object.values(state.errors).includes(error),
          properties: observeValue(Object.fromEntries(Object.entries(error))),
        } };
      }
      const stored = raw();
      const observation = { name, method, input: observeValue(input), ...outcome, events: state.events.splice(0), stored };
      diagnostics.push({ target: target.name, scenario, operation: name, phase: "complete", observation });
      return observation;
    };
    const reset = async () => {
      state.failure = undefined;
      state.replaceInput = false;
      state.projection = undefined;
      assert.deepEqual(state.events.splice(0), []);
      await adapter.deleteMany({ model: target.model, where: [] });
      assert.deepEqual(raw(), []);
    };
    const field = (scenario, phase) => scenario === "omitted" ? {} : {
      [target.field]: scenario === "undefined" ? undefined : scenario === "null" ? null : valueFor(target.type, phase),
    };
    const cases = [];
    for (const name of nativeReplacementInputs) {
      scenario = name;
      await reset();
      const operations = [
        await observe("create", adapter, "create", field(name, "create")),
        await observe("read-created", adapter, "findOne"),
        await observe("update", adapter, "update", field(name, "update")),
        await observe("read-updated", adapter, "findOne"),
      ];
      for (const operation of operations) assert.equal(operation.returned, true, `${target.name}: ${name}: ${operation.name}`);
      cases.push({ name, operations });
    }
    scenario = "defaults";
    await reset();
    const defaultOperations = [
      await observe("create-default", defaults, "create"),
      await observe("update-default", defaults, "update"),
      await observe("read-default", defaults, "findOne"),
    ];
    for (const operation of defaultOperations) assert.equal(operation.returned, true);
    scenario = "input-transform";
    await reset();
    state.replaceInput = true;
    const transformed = await observe("input-transform", adapter, "create", field("provided", "create"));
    assert.equal(transformed.returned, true);
    state.replaceInput = false;
    const projections = [];
    for (const name of nativeReplacementProjections) {
      scenario = `output-${name}`;
      state.projection = name;
      const operation = await observe(name, adapter, "findOne");
      assert.equal(operation.returned, true);
      assert.deepEqual(operation.stored, transformed.stored);
      projections.push(operation);
    }
    const failures = [];
    for (const { operation, phase } of nativeReplacementFailures) {
      scenario = `failure-${operation}-${phase}`;
      await reset();
      const seed = operation === "create" ? null : await observe("seed", adapter, "create", field("provided", "create"));
      if (seed) assert.equal(seed.returned, true);
      const before = raw();
      state.failure = phase;
      const supplied = ["default", "onUpdate"].includes(phase) ? {} : field("provided", operation === "update" ? "update" : "create");
      const result = await observe(`${operation}-${phase}`, defaults, operation === "read" ? "findOne" : operation, supplied);
      assert.equal(result.returned, false);
      assert.equal(result.error.sameCallbackError, true);
      if (phase !== "output" || operation === "read") assert.deepEqual(result.stored, before);
      else assert.equal(result.stored.length, 1, "Output rejection must retain the completed write");
      failures.push({ name: `${operation}-${phase}`, seed, before, result });
    }
    return { ...target, table: tableName, column, declaration, catalog, cases, defaults: defaultOperations, transformed, projections, failures };
  } catch (error) {
    diagnostics.push({ target: target.name, scenario, phase: "failure", events: state.events.splice(0), error: {
      name: error instanceof Error ? error.name : typeof error,
      message: error instanceof Error ? error.message : String(error),
      properties: error instanceof Error ? observeValue(Object.fromEntries(Object.entries(error))) : observeValue(error),
    } });
    throw error;
  } finally {
    sqlite?.close();
  }
}

export async function captureNativePluginReplacements(backend, diagnostics = []) {
  assert.ok(["memory", "sqlite"].includes(backend));
  const targets = [];
  for (const target of nativeReplacementTargets) {
    diagnostics.push({ target: target.name, scenario: "setup", phase: "start" });
    targets.push(await captureTarget(backend, target, diagnostics));
  }
  return { version, backend, targets };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  const diagnostics = [];
  try {
    const captured = await captureNativePluginReplacements(backend, diagnostics);
    writeFileSync(output, `${JSON.stringify(captured, null, 2)}\n`);
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify({ version, backend, diagnostics }, null, 2)}\n`);
  }
}
