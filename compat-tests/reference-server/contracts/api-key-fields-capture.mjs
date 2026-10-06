import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const createdAt = "2030-01-02T03:04:05.123Z";
const updatedAt = "2030-01-02T04:04:05.123Z";
const times = Array.from({ length: 6 }, (_, i) => `2031-02-03T04:05:0${i}.000Z`);
const json = value => JSON.parse(JSON.stringify(value));
const callbackValue = value => value === undefined ? { type: "undefined" } : json(value);
const policies = () => ({
  label: { type: "string", fieldName: "stored_label", required: false, defaultValue: " Default " },
  activatedAt: { type: "date", fieldName: "stored_activation", required: false },
  details: { type: "json", fieldName: "stored_details", required: false },
  revision: { type: "number", fieldName: "stored_revision", required: false, defaultValue: 1.5 },
});
const nativeFields = [
  "id", "name", "start", "prefix", "key", "referenceId", "configId", "refillInterval", "refillAmount",
  "lastRefillAt", "enabled", "rateLimitEnabled", "rateLimitTimeWindow", "rateLimitMax", "requestCount",
  "remaining", "lastRequest", "expiresAt", "createdAt", "updatedAt", "permissions", "metadata",
];
const input = () => ({
  name: "Desk", start: null, prefix: null, key: "ordinary-stored-hash", referenceId: "ordinary-owner",
  configId: "default", refillInterval: 60000, refillAmount: 10, lastRefillAt: null, enabled: true,
  rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3, requestCount: 0, remaining: 10,
  lastRequest: null, expiresAt: null, createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
  permissions: null, metadata: null,
  activatedAt: "2029-01-02T03:04:05.000Z", details: { channel: "ordinary", enabled: true },
});
export const operationNames = [
  "create", "get-id", "get-hash", "list", "decrement-input-ignored", "update", "refill", "refill-miss",
  "decrement", "start-window", "start-window-miss", "reset-window", "increment-window", "increment-window-miss",
  "last-request", "updated-at",
];
export const failureOperations = ["create", "update", "refill", "decrement", "start-window", "increment-window", "last-request", "updated-at"];

async function withFixture(backend, run) {
  const memory = { user: [], session: [], account: [], verification: [], ordinary_api_key_fields: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = fields => ({
    database: sqlite ?? memoryAdapter(memory), baseURL: "http://api-key-fields.test",
    secret: "ordinary-api-key-extra-fields-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [apiKey(), { id: "ordinary-api-key-additional-fields", schema: {
      apikey: { modelName: "ordinary_api_key_fields", fields },
    } }],
  });
  try {
    if (sqlite) await (await getMigrations(options(policies()))).runMigrations();
    const reader = (await betterAuth(options(policies())).$context).adapter;
    const events = [];
    const errors = { input: new Error("ordinary API Key input error"), output: new Error("ordinary API Key output error") };
    let failure;
    const fields = Object.fromEntries(Object.entries(policies()).map(([name, field]) => [name, {
      ...field,
      ...(name === "revision" ? {
        defaultValue() { events.push(["default", name]); return 1.5; },
        onUpdate() { events.push(["onUpdate", name]); return 2.5; },
      } : {}),
      transform: {
        input(value) {
          events.push(["input", name, callbackValue(value)]);
          if (name === "revision" && failure === "input") throw errors.input;
          return name === "label" && typeof value === "string" ? value.trim() : value;
        },
        output(value) {
          events.push(["output", name, callbackValue(value)]);
          if (name === "label" && failure === "output") throw errors.output;
          return name === "label" && typeof value === "string" ? `${value}:out` : value;
        },
      },
    }]));
    const adapter = (await betterAuth(options(fields)).$context).adapter;
    let identity;
    let expectedUpdatedAt = createdAt;
    const visible = row => {
      if (row === null) return null;
      assert.deepEqual(Object.keys(row).sort(), [...nativeFields, ...Object.keys(policies())].sort());
      assert.equal(typeof row.id, "string");
      assert.ok(row.id.length > 0);
      if (identity === undefined) identity = row.id;
      assert.equal(row.id, identity);
      assert.equal(row.referenceId, "ordinary-owner");
      assert.equal(row.key, "ordinary-stored-hash");
      assert.equal(row.configId, "default");
      assert.ok(row.createdAt instanceof Date);
      assert.equal(row.createdAt.toISOString(), createdAt);
      assert.ok(row.updatedAt instanceof Date);
      assert.equal(row.updatedAt.toISOString(), expectedUpdatedAt);
      const normalizedUpdate = expectedUpdatedAt === createdAt ? "<created-at>" : expectedUpdatedAt === updatedAt ? "<ordinary-updated-at>" : expectedUpdatedAt;
      return json({ ...row, id: "<api-key-id>", createdAt: "<created-at>", updatedAt: normalizedUpdate });
    };
    const stored = async () => {
      const rows = await reader.findMany({ model: "apikey", where: [{ field: "referenceId", value: "ordinary-owner" }] });
      assert.ok(rows.length <= 1);
      return rows.map(visible);
    };
    const execute = async (operation, id) => {
      const model = "apikey";
      const where = [{ field: "id", value: id }];
      const date = index => new Date(times[index]);
      if (operation === "create") return [await adapter.create({ model, data: input() })];
      if (operation === "get-id") return [await adapter.findOne({ model, where })];
      if (operation === "get-hash") return [await adapter.findOne({ model, where: [{ field: "key", value: "ordinary-stored-hash" }] })];
      if (operation === "list") return await adapter.findMany({ model, where: [{ field: "referenceId", value: "ordinary-owner" }] });
      if (operation === "update") {
        if (failure !== "input") expectedUpdatedAt = updatedAt;
        return [await adapter.update({ model, where, update: { name: "Desk-renamed", label: " Revised ", updatedAt: new Date(updatedAt) } })];
      }
      if (operation === "last-request") return [await adapter.update({ model, where, update: { lastRequest: date(4) } })];
      if (operation === "updated-at") {
        if (failure !== "input") expectedUpdatedAt = times[5];
        return [await adapter.update({ model, where, update: { updatedAt: date(5) } })];
      }
      let increment = {};
      let set;
      if (["decrement", "decrement-input-ignored"].includes(operation)) {
        where.push({ field: "remaining", operator: "gt", value: 0 });
        increment = { remaining: -1 };
      } else if (["refill", "refill-miss"].includes(operation)) {
        where.push({ field: "lastRefillAt", value: null });
        set = { remaining: 8, lastRefillAt: date(0) };
      } else if (["start-window", "start-window-miss", "reset-window"].includes(operation)) {
        where.push(operation === "reset-window"
          ? { field: "lastRequest", operator: "lte", value: date(1) }
          : { field: "lastRequest", value: null });
        set = { requestCount: 1, lastRequest: date(operation === "reset-window" ? 2 : 1) };
      } else {
        assert.ok(["increment-window", "increment-window-miss"].includes(operation));
        where.push({ field: "lastRequest", operator: "gt", value: date(0) });
        where.push({ field: "requestCount", operator: "lt", value: operation.endsWith("-miss") ? 2 : 3 });
        increment = { requestCount: 1 };
        set = { lastRequest: date(3) };
      }
      const row = await adapter.incrementOne({ model, where, increment, ...(set ? { set } : {}) });
      return row === null ? [] : [row];
    };
    return await run({ execute, visible, stored, events, errors, setFailure(value) { failure = value; } });
  } finally {
    sqlite?.close();
  }
}

async function captureOperations(backend) {
  return await withFixture(backend, async ({ execute, visible, stored, events, setFailure }) => {
    const operations = [];
    let id;
    for (const name of operationNames) {
      assert.equal(events.length, 0);
      if (name === "decrement-input-ignored") setFailure("input");
      const before = await stored();
      const result = await execute(name, id);
      setFailure(undefined);
      assert.equal(result.length, name.endsWith("-miss") ? 0 : 1);
      if (name === "create") id = result[0].id;
      const observation = { name, events: events.splice(0), result: result.map(visible), stored: await stored() };
      if (name.endsWith("-miss")) {
        assert.deepEqual(observation.stored, before);
        assert.ok(observation.events.every(event => event[0] !== "output"));
      }
      if (["decrement", "decrement-input-ignored"].includes(name)) assert.ok(observation.events.every(event => event[0] === "output"));
      operations.push(observation);
    }
    return operations;
  });
}

async function captureFailure(backend, operation, phase) {
  return await withFixture(backend, async ({ execute, stored, events, errors, setFailure }) => {
    let id;
    if (operation !== "create") id = (await execute("create"))[0].id;
    if (operation === "increment-window") await execute("start-window", id);
    const before = await stored();
    events.length = 0;
    setFailure(phase);
    let sameError = false;
    try { await execute(operation, id); } catch (error) {
      if (error !== errors[phase]) throw error;
      sameError = true;
    }
    assert.equal(sameError, true, "The configured callback must reject the operation");
    setFailure(undefined);
    const persisted = await stored();
    if (phase === "input") assert.deepEqual(persisted, before);
    else assert.equal(persisted.length, 1);
    return { name: `${operation}-${phase}-error`, events: events.splice(0), result: { sameError, message: errors[phase].message }, stored: persisted };
  });
}

export async function captureApiKeyFields() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const operations = await captureOperations(backend);
    const failures = [];
    for (const operation of failureOperations) {
      for (const phase of operation === "decrement" ? ["output"] : ["input", "output"]) failures.push(await captureFailure(backend, operation, phase));
    }
    backends.push({ backend, operations, failures });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureApiKeyFields(), null, 2)}\n`);
}
