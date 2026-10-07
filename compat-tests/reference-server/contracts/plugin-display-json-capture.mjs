import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { observeValue } from "./device-where-capture.mjs";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";
import { captureApiKeyCatalog } from "./api-key-catalog-capture.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key", "@better-auth/passkey"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const fixedDate = "2030-01-02T03:04:05.000Z";
const ownerId = "display-json-owner";
const rowId = "display-json-row";
const column = "stored_display";
export const displayJsonTargets = [
  { model: "apikey", field: "name" },
  { model: "passkey", field: "name" },
  { model: "passkey", field: "aaguid" },
];
export const displayJsonValues = [
  { name: "omitted", present: false, value: () => undefined },
  { name: "undefined", present: true, value: () => undefined },
  { name: "null", present: true, value: () => null },
  { name: "object", present: true, value: () => ({ label: "Desk", nested: { rank: 2, enabled: true } }) },
  { name: "array", present: true, value: () => ["Desk", { rank: 2 }, null] },
  { name: "object-text", present: true, value: () => '{"label":"Desk","rank":2}' },
  { name: "array-text", present: true, value: () => '["Desk",2,null]' },
  { name: "string-text", present: true, value: () => '"Desk"' },
  { name: "null-text", present: true, value: () => "null" },
  { name: "invalid-text", present: true, value: () => "Desk" },
  { name: "invalid-json-text", present: true, value: () => '{"label":' },
];
export const displayJsonValueOperations = ["create", "read-created", "seed", "update", "read-updated"];
export const displayJsonProjectionModes = ["object", "array", "null", "undefined", "object-text", "invalid-text"];
export const displayJsonFailureCases = [
  { operation: "create", phase: "default" },
  { operation: "create", phase: "input" },
  { operation: "create", phase: "output" },
  { operation: "update", phase: "onUpdate" },
  { operation: "update", phase: "input" },
  { operation: "update", phase: "output" },
  { operation: "read", phase: "output" },
];

function tableName({ model, field }) {
  return `display_json_${model}_${field}`;
}

function configuration(target, state, defaults = false) {
  const event = (phase, value) => {
    state.events.push({ phase, field: target.field, value: observeValue(value) });
    if (state.failure === phase) throw state.errors[phase];
  };
  const policy = {
    type: "json", required: defaults, fieldName: column,
    ...(defaults ? {
      defaultValue() { const value = { source: "default" }; event("default", value); return value; },
      onUpdate() { const value = { source: "onUpdate" }; event("onUpdate", value); return value; },
    } : {}),
    transform: {
      input(value) {
        event("input", value);
        return state.wrapInput ? { input: value } : value;
      },
      output(value) {
        event("output", value);
        if (state.wrapOutput) return { output: value };
        if (state.projection !== undefined) return displayJsonValues.find(item => item.name === state.projection).value();
        return value;
      },
    },
  };
  return {
    baseURL: "http://display-json.test",
    secret: "ordinary-display-json-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [target.model === "apikey" ? apiKey() : passkey(), {
      id: "ordinary-display-json",
      schema: { [target.model]: { modelName: tableName(target), fields: { [target.field]: policy } } },
    }],
  };
}

function input(target, display) {
  const data = target.model === "apikey" ? {
    id: rowId, configId: "default", name: "Desk", start: null, referenceId: ownerId, prefix: null,
    key: "ordinary-display-key", refillInterval: null, refillAmount: null, lastRefillAt: null,
    enabled: true, rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3,
    requestCount: 0, remaining: 10, lastRequest: null, expiresAt: null,
    createdAt: new Date(fixedDate), updatedAt: new Date(fixedDate), permissions: null, metadata: null,
  } : {
    id: rowId, name: "Desk", publicKey: "ordinary-public-key", userId: ownerId,
    credentialID: "ordinary-display-credential", counter: 0, deviceType: "singleDevice",
    backedUp: false, transports: null, createdAt: new Date(fixedDate),
    aaguid: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
  };
  delete data[target.field];
  return { ...data, ...display };
}

async function captureRows({ options, query, backend, memory }, target, state) {
  const makeAdapter = async defaults => (await betterAuth({
    ...options, ...configuration(target, state, defaults),
  }).$context).adapter;
  const adapter = await makeAdapter(false);
  const defaultAdapter = await makeAdapter(true);
  const owner = await adapter.create({ model: "user", forceAllowId: true, data: {
    id: ownerId, name: "Display owner", email: "owner@display-json.test", emailVerified: false,
    createdAt: new Date(fixedDate), updatedAt: new Date(fixedDate),
  } });
  assert.equal(owner.id, ownerId);
  const quote = name => backend === "mysql" ? `\`${name}\`` : `"${name}"`;
  const stored = async () => {
    if (memory) return memory[tableName(target)].map(row => ({ row: observeValue(row), keys: Object.keys(row) }));
    const name = quote(column);
    const textType = backend === "mysql" ? "CHAR" : "TEXT";
    const rows = await query(`SELECT *, ${name} IS NULL AS ${quote("displaySqlNull")}, CAST(${name} AS ${textType}) AS ${quote("displayText")} FROM ${quote(tableName(target))} ORDER BY ${quote("id")}`, []);
    return rows.map(({ displaySqlNull, displayText, ...row }) => ({
      row: observeValue(row), keys: Object.keys(row), displaySqlNull: observeValue(displaySqlNull), displayText: observeValue(displayText),
    }));
  };
  const observe = async (name, action) => {
    let outcome;
    try {
      const result = await action();
      outcome = { returned: true, result: observeValue(result), keys: result === null ? [] : Object.keys(result) };
    } catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      assert.ok(error instanceof Error);
      // Preserve driver diagnostics and callback identity; stack traces depend on the capture host.
      outcome = { returned: false, error: {
        name: error.name, message: error.message,
        sameCallbackError: Object.values(state.errors).includes(error),
        properties: observeValue(Object.fromEntries(Object.entries(error))),
      } };
    }
    return { name, ...outcome, events: state.events.splice(0), stored: await stored() };
  };
  const where = [{ field: "id", value: rowId }];
  const create = (selected, display) => selected.create({ model: target.model, forceAllowId: true, data: input(target, display) });
  const read = selected => selected.findOne({ model: target.model, where });
  const update = (selected, display) => selected.update({ model: target.model, where, update: {
    ...(target.model === "apikey" ? { requestCount: 1, updatedAt: new Date(fixedDate) } : { counter: 1 }), ...display,
  } });
  const reset = async () => {
    state.failure = undefined;
    state.projection = undefined;
    state.wrapInput = false;
    state.wrapOutput = false;
    assert.deepEqual(state.events.splice(0), []);
    await adapter.deleteMany({ model: target.model, where: [] });
    assert.deepEqual(await stored(), []);
  };
  const cases = [];
  for (const scenario of displayJsonValues) {
    await reset();
    const display = scenario.present ? { [target.field]: scenario.value() } : {};
    const operations = [
      await observe("create", () => create(adapter, display)),
      await observe("read-created", () => read(adapter)),
    ];
    await reset();
    const seed = await observe("seed", () => create(adapter, { [target.field]: { source: "seed" } }));
    assert.equal(seed.returned, true, "An object must create the update baseline");
    operations.push(seed, await observe("update", () => update(adapter, display)), await observe("read-updated", () => read(adapter)));
    cases.push({ name: scenario.name, input: observeValue(display), operations });
  }
  const defaults = [];
  for (const name of ["omitted", "undefined", "null"]) {
    await reset();
    const display = name === "omitted" ? {} : { [target.field]: name === "null" ? null : undefined };
    const operations = [await observe("create", () => create(defaultAdapter, display))];
    assert.equal(operations[0].returned, true);
    operations.push(await observe("update", () => update(defaultAdapter, {})), await observe("read", () => read(defaultAdapter)));
    defaults.push({ name, input: observeValue(display), operations });
  }
  await reset();
  state.wrapInput = true;
  state.wrapOutput = true;
  const transformations = [
    await observe("create", () => create(adapter, { [target.field]: { source: "request" } })),
    await observe("update", () => update(adapter, { [target.field]: ["request", 2] })),
    await observe("read", () => read(adapter)),
  ];
  await reset();
  const projectionSeed = await observe("seed", () => create(adapter, { [target.field]: { source: "seed" } }));
  assert.equal(projectionSeed.returned, true);
  const projections = [];
  for (const name of displayJsonProjectionModes) {
    state.projection = name;
    projections.push(await observe(name, () => read(adapter)));
  }
  const failures = [];
  for (const { operation, phase } of displayJsonFailureCases) {
    await reset();
    const seed = operation === "create" ? null : await observe("seed", () => create(defaultAdapter, {}));
    if (seed) assert.equal(seed.returned, true);
    const before = await stored();
    state.failure = phase;
    const result = await observe(operation, () => operation === "create" ? create(defaultAdapter, {})
      : operation === "update" ? update(defaultAdapter, {}) : read(defaultAdapter));
    assert.equal(result.returned, false);
    assert.equal(result.error.sameCallbackError, true);
    if (phase !== "output" || operation === "read") assert.deepEqual(result.stored, before);
    else assert.equal(result.stored.length, 1, "Output rejection must retain the completed write");
    failures.push({ name: `${operation}-${phase}`, seed, before, result });
  }
  return { cases, defaults, transformations, projectionSeed, projections, failures };
}

async function captureTarget(backend, target) {
  const state = { events: [], errors: Object.fromEntries(["default", "onUpdate", "input", "output"].map(phase => [phase, new Error(`ordinary display ${phase} error`)])) };
  const config = configuration(target, state);
  if (backend === "memory" || backend === "sqlite") {
    const memory = backend === "memory" ? { user: [], session: [], account: [], verification: [], [tableName(target)]: [] } : undefined;
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    try {
      const options = { ...config, database: database ?? memoryAdapter(memory) };
      if (database) await (await getMigrations(options)).runMigrations();
      const catalog = database ? observeSqliteCatalog(database, tableName(target), "The display table must exist").catalog : null;
      const columns = catalog?.columns ?? null;
      const result = await captureRows({ options, backend, memory, query: async (sql, values) => database.query(sql).all(...values) }, target, state);
      return { ...target, table: tableName(target), column, columns,
        ...(catalog ? { constraints: { indexes: catalog.indexes, foreignKeys: catalog.foreignKeys } } : {}), ...result };
    } finally { database?.close(); }
  }
  const captured = await captureFreshServerCatalog(backend, [tableName(target)], config,
    async context => ({ constraints: await observeServerIndexes(context, tableName(target)),
      ...await captureRows(context, target, state) }));
  return { ...target, table: tableName(target), column, columns: captured.columns, ...captured.observation };
}

export async function capturePluginDisplayJson(backend) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  const models = [];
  for (const target of displayJsonTargets) models.push(await captureTarget(backend, target));
  return { version, backend, models,
    ...(backend === "memory" ? {} : { apiKeyCatalog: await captureApiKeyCatalog(backend) }) };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await capturePluginDisplayJson(backend), null, 2)}\n`);
}
