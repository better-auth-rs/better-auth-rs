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
const expiry = "2100-01-02T03:04:05.000Z";
const fieldTypes = { label: "string", quantity: "number", flag: "boolean", moment: "date", labels: "string[]", payload: "json", ownerRef: "string" };

// Tagged observations retain Date, undefined, and non-finite values before JSON serialization.
const observeValue = value => {
  if (value === undefined) return { type: "undefined" };
  if (value instanceof Date) return { type: "date", value: Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString() };
  if (typeof value === "number" && !Number.isFinite(value)) return { type: "number", value: String(value) };
  if (Array.isArray(value)) return value.map(observeValue);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, value]) => [key, observeValue(value)]));
  return value;
};

async function captureGroup(backend, serial) {
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
    for (const scenario of deviceWhereScenarios().filter(scenario => Boolean(scenario.serial) === serial)) {
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
      let value = scenario.value;
      if (scenario.sourceValue === "returned") value = seeded[scenario.field];
      if (scenario.sourceValue === "returned-array") value = [seeded[scenario.field]];
      if (scenario.sourceValue === "owner") value = owner.id;
      if (scenario.sourceValue === "owner-array") value = [owner.id, null];
      const where = [
        { field: "id", value: seeded.id },
        { field: scenario.physical ? `stored_${scenario.field}` : scenario.field, operator: scenario.operator, value, ...(scenario.mode ? { mode: scenario.mode } : {}) },
        { field: "status", value: "approved" },
      ];
      const before = await raw();
      const seedEvents = events.splice(0);
      let result = null;
      let error = null;
      try {
        const consume = async current => row(await current.consumeOne({ model: "deviceCode", where }));
        result = scenario.transaction ? await adapter.transaction(consume) : await consume(adapter);
      } catch (caught) {
        if (caught instanceof assert.AssertionError) throw caught;
        assert.ok(caught instanceof Error);
        error = { name: caught.name, message: caught.message };
      }
      const after = await raw();
      if (error || result === null) assert.deepEqual(after, before, "An error or mismatch must preserve the complete stored row");
      else assert.deepEqual(after, [], "A successful consumption must remove the selected row");
      assert.ok(events.every(event => event.phase === "output"), "Where conversion must not call field input transforms");
      cases.push({
        name: scenario.name, transaction: Boolean(scenario.transaction),
        where: observeValue([{ ...where[0], value: "<device-id>" }, ...where.slice(1)]),
        seeded: row(seeded), seedEvents, before, events: events.splice(0), result, error, after,
      });
    }
    return { serial, cases };
  };
  try {
    if (backend === "memory") return await capture({ ...configuration, database: memoryAdapter(memory) }, async () => memory.deviceCode);
    if (sqlite) {
      const options = { ...configuration, database: sqlite };
      await (await getMigrations(options)).runMigrations();
      return await capture(options, async () => sqlite.query('SELECT * FROM "deviceCode" ORDER BY "deviceCode"').all());
    }
    const captured = await captureFreshServerCatalog(backend, ["deviceCode"], configuration, ({ options, query }) => capture(options, () => query(
      backend === "postgres" ? 'SELECT * FROM "deviceCode" ORDER BY "deviceCode"' : 'SELECT * FROM `deviceCode` ORDER BY `deviceCode`', [],
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
  for (const serial of [false, true]) groups.push(await captureGroup(backend, serial));
  return { version, backend, groups };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceWhere(backend), null, 2)}\n`);
}
