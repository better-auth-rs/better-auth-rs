import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization } from "better-auth/plugins";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";
import { deviceWhereScenarios } from "./device-where-scenarios.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const fixedDate = "2030-01-02T03:04:05.000Z";
const expiry = "2032-01-02T03:04:05.000Z";
const fieldTypes = { label: "string", quantity: "number", flag: "boolean", moment: "date", labels: "string[]", payload: "json", ownerRef: "string" };

// Tagged observations retain Date, undefined, and non-finite values before JSON serialization.
export const observeValue = value => {
  if (value === undefined) return { type: "undefined" };
  if (value instanceof Date) return { type: "date", value: Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString() };
  if (typeof value === "number" && !Number.isFinite(value)) return { type: "number", value: String(value) };
  if (Array.isArray(value)) return value.map(observeValue);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, value]) => [key, observeValue(value)]));
  return value;
};

export async function captureDeviceWhereGroup(backend, serial, scenarios = deviceWhereScenarios()) {
  const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const fields = Object.fromEntries(Object.entries(fieldTypes).map(([field, type]) => [field, {
    type, required: false, fieldName: `stored_${field}`,
    ...(field === "ownerRef" ? { references: { model: "user", field: "id" } } : {}),
    transform: {
      input(value) { events.push({ phase: "input", field, value: observeValue(value) }); return value; },
      output(value) { events.push({ phase: "output", field, value: observeValue(value) }); return value; },
    },
  }]));
  const configuration = {
    baseURL: "http://device-where.test", secret: "ordinary-device-where-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: serial ? "serial" : undefined } },
    plugins: [deviceAuthorization(), { id: "device-where-fields", schema: { deviceCode: { fields } } }],
  };
  const capture = async (options, readRaw) => {
    const { adapter } = await betterAuth(options).$context;
    const owner = await adapter.create({ model: "user", forceAllowId: true, data: {
      ...(serial ? {} : { id: "ordinary-owner" }), name: "Where owner", email: "owner@device-where.test",
      emailVerified: false, image: null, createdAt: new Date(fixedDate), updatedAt: new Date(fixedDate),
    } });
    assert.equal(typeof owner.id, "string");
    assert.ok(owner.id.length > 0);
    const cases = [];
    for (const scenario of scenarios.filter(scenario => Boolean(scenario.serial) === serial)) {
      await adapter.deleteMany({ model: "deviceCode", where: [] });
      const native = {
        deviceCode: "ordinary-device", userCode: "ordinary-user", userId: owner.id,
        expiresAt: new Date(expiry), status: "approved", lastPolledAt: null,
        pollingInterval: 5000, clientId: "ordinary-client", scope: "read",
      };
      const stored = scenario.field === "ownerRef" && scenario.stored === "owner" ? owner.id : scenario.stored;
      const data = { ...native, ...Object.fromEntries(Object.keys(fields).map(field => [field, null])), [scenario.field]: stored };
      const seeded = await adapter.create({ model: "deviceCode", data });
      assert.equal(typeof seeded.id, "string");
      assert.ok(seeded.id.length > 0);
      const row = value => {
        if (value === null) return null;
        assert.equal(String(value.id), seeded.id);
        assert.equal(String(value.userId), owner.id);
        return observeValue({ ...value, id: "<device-id>", userId: "<owner-id>" });
      };
      const raw = async () => (await readRaw()).map(row);
      const storage = async () => Object.fromEntries(await Promise.all(Object.keys(memory).map(async model => [model,
        (await readRaw(model)).map(value => model === "deviceCode" ? row(value) : observeValue(
          model === "user" && String(value.id) === owner.id ? { ...value, id: "<owner-id>" } : value,
        )),
      ])));
      let value = scenario.value;
      if (scenario.sourceValue === "returned") value = seeded[scenario.field];
      if (scenario.sourceValue === "returned-array") value = [seeded[scenario.field]];
      if (scenario.sourceValue === "owner") value = owner.id;
      if (scenario.sourceValue === "owner-array") value = [owner.id, null];
      const where = [
        { field: "id", value: seeded.id },
        { field: scenario.physical ? `stored_${scenario.field}` : scenario.field, operator: scenario.operator, value, ...(scenario.mode ? { mode: scenario.mode } : {}) },
        ...(scenario.guardBindings ? ["deviceCode", "clientId", "userId"].map(field => ({ field, value: native[field] })) : []),
        { field: "status", value: "approved" },
      ];
      if (scenario.guardMismatch) {
        const guard = where.find(condition => condition.field === scenario.guardMismatch);
        assert.ok(guard, "The mismatch must replace an existing native binding");
        guard.value = `${scenario.guardMismatch}-mismatch`;
      }
      const before = await raw();
      const storageBefore = scenario.observeStorage ? await storage() : undefined;
      const seedEvents = events.splice(0);
      let result = null;
      let error = null;
      let rollbackResult = null;
      let transactionAfterConsume = null;
      const rollbackError = new Error("Rollback device reference consumption");
      try {
        const consume = async current => {
          if (scenario.sourceValue === "transaction-returned" || scenario.sourceValue === "transaction-returned-array") {
            const selected = await current.findOne({ model: "deviceCode", where: [where[0]] });
            assert.ok(selected);
            where[1].value = scenario.sourceValue === "transaction-returned-array" ? [selected[scenario.field]] : selected[scenario.field];
          }
          const consumed = row(await current.consumeOne({ model: "deviceCode", where }));
          if (scenario.rollback) {
            assert.ok(scenario.transaction, "Rollback requires a transaction");
            assert.ok(consumed, "Rollback must follow a successful consumption");
            rollbackResult = consumed;
            transactionAfterConsume = (await current.findMany({ model: "deviceCode", where: [] })).map(row);
            assert.deepEqual(transactionAfterConsume, []);
            throw rollbackError;
          }
          return consumed;
        };
        result = scenario.transaction ? await adapter.transaction(consume) : await consume(adapter);
      } catch (caught) {
        if (caught instanceof assert.AssertionError) throw caught;
        assert.ok(caught instanceof Error);
        if (scenario.rollback) assert.equal(caught, rollbackError, "Preserve the original rollback error");
        error = { name: caught.name, message: caught.message };
      }
      const after = await raw();
      if (error || result === null) assert.deepEqual(after, before, "An error or mismatch must preserve the complete stored row");
      else assert.deepEqual(after, [], "A successful consumption must remove the selected row");
      assert.ok(events.every(event => event.phase === "output"), "Where conversion must not call field input transforms");
      cases.push({
        name: scenario.name, transaction: Boolean(scenario.transaction),
        where: observeValue(where.map(condition => condition.field === "id" && condition.value === seeded.id
          ? { ...condition, value: "<device-id>" } : condition)),
        seeded: row(seeded), seedEvents, before, events: events.splice(0), result, error, after,
        ...(scenario.rollback ? { rollback: { result: rollbackResult, afterConsume: transactionAfterConsume, originalError: true } } : {}),
        ...(scenario.observeStorage ? { storage: { before: storageBefore, after: await storage() } } : {}),
      });
    }
    return { serial, cases };
  };
  try {
    if (backend === "memory") return await capture({ ...configuration, database: memoryAdapter(memory) }, async (model = "deviceCode") => memory[model]);
    if (sqlite) {
      const options = { ...configuration, database: sqlite };
      await (await getMigrations(options)).runMigrations();
      return await capture(options, async (model = "deviceCode") => sqlite.query(`SELECT * FROM "${model}" ORDER BY "${model === "deviceCode" ? "deviceCode" : "id"}"`).all());
    }
    const captured = await captureFreshServerCatalog(backend, ["deviceCode"], configuration, ({ options, query }) => capture(options, (model = "deviceCode") => query(
      backend === "postgres" ? `SELECT * FROM "${model}" ORDER BY "${model === "deviceCode" ? "deviceCode" : "id"}"` : `SELECT * FROM \`${model}\` ORDER BY \`${model === "deviceCode" ? "deviceCode" : "id"}\``, [],
    )));
    return captured.observation;
  } finally {
    sqlite?.close();
  }
}

export async function captureDeviceWhere(backend) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  const scenarios = deviceWhereScenarios();
  assert.equal(new Set(scenarios.map(scenario => scenario.name)).size, scenarios.length);
  assert.deepEqual([...new Set(scenarios.map(scenario => scenario.operator))].sort(), ["contains", "ends_with", "eq", "gt", "gte", "in", "lt", "lte", "ne", "not_in", "starts_with"]);
  const groups = [];
  for (const serial of [false, true]) groups.push(await captureDeviceWhereGroup(backend, serial));
  return { version, backend, groups };
}

export async function captureDeviceWhereTransactions(backend) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  const values = deviceWhereScenarios().filter(scenario =>
    scenario.name.startsWith("date-") || /^(array|json)-eq-/.test(scenario.name) ||
    ["number-nan", "number-infinity"].includes(scenario.name));
  const scenarios = values.map(scenario => ({ ...scenario, name: `transaction-existing-${scenario.name}`, transaction: true }));
  for (const scenario of values.filter(scenario => ["returned", "returned-array"].includes(scenario.sourceValue))) {
    scenarios.push({ ...scenario, name: `transaction-selected-${scenario.name}`, transaction: true, sourceValue: `transaction-${scenario.sourceValue}` });
  }
  assert.equal(scenarios.length, 23);
  assert.equal(new Set(scenarios.map(scenario => scenario.name)).size, scenarios.length);
  return { version, backend, groups: [await captureDeviceWhereGroup(backend, false, scenarios)] };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceWhere(backend), null, 2)}\n`);
}
