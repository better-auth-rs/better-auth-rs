import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const table = "native_json_driver";
const fixedDate = "2030-01-02T03:04:05.000Z";
const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const scenarios = [
  { name: "null", value: () => null },
  { name: "string-ordinary", value: () => "ordinary" },
  { name: "string-json-scalar", value: () => '"ordinary"' },
  { name: "string-json-null", value: () => "null" },
  { name: "date-valid", value: () => new Date(fixedDate) },
  { name: "date-invalid", value: () => new Date(NaN) },
  { name: "array-empty", value: () => [] },
  { name: "array-scalars", value: () => ["ordinary", 1, null] },
  { name: "array-nested", value: () => [[1], ["ordinary", null]] },
  { name: "array-runtime-values", value: () => [new Date(fixedDate), new Date(NaN), undefined, NaN, Infinity] },
];

function configuration(events) {
  return {
    baseURL: "http://native-json-driver.test",
    secret: "ordinary-native-json-driver-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [deviceAuthorization(), {
      id: "native-json-driver-fields",
      schema: { deviceCode: { modelName: table, fields: {
        payload: {
          type: "json", required: false, fieldName: "stored_payload",
          transform: {
            input(value) { events.push({ phase: "input", field: "payload", value: observeValue(value) }); return value; },
            output(value) { events.push({ phase: "output", field: "payload", value: observeValue(value) }); return value; },
          },
        },
      } } },
    }],
  };
}

function input(id, payload) {
  return {
    id, deviceCode: id, userCode: "ABCD2345", userId: null,
    expiresAt: new Date("2032-01-02T03:04:05.000Z"), status: "pending",
    lastPolledAt: null, pollingInterval: 5, clientId: "ordinary-client", scope: null, payload,
  };
}

async function captureRows({ options, query, backend }, events) {
  const { adapter } = await betterAuth(options).$context;
  const quote = name => backend === "mysql" ? `\`${name}\`` : `"${name}"`;
  const column = quote("stored_payload");
  const textType = backend === "mysql" ? "CHAR" : "TEXT";
  const readRaw = async id => {
    const rows = await query(`SELECT *, ${column} IS NULL AS ${quote("payloadSqlNull")}, CAST(${column} AS ${textType}) AS ${quote("payloadText")} FROM ${quote(table)} ORDER BY ${quote("id")}`, []);
    assert.ok(rows.length <= 1);
    return rows.map(({ payloadSqlNull, payloadText, ...row }) => {
      assert.equal(row.id, id);
      assert.equal(row.deviceCode, id);
      assert.equal(row.userId, null);
      assert.equal(row.status, "pending");
      assert.equal(row.clientId, "ordinary-client");
      return observeValue({ row, payloadSqlNull, payloadText });
    });
  };
  const observe = async (id, action) => {
    let outcome;
    try {
      outcome = { returned: true, result: observeValue(await action()) };
    } catch (caught) {
      if (caught instanceof assert.AssertionError) throw caught;
      assert.ok(caught instanceof Error);
      // Retain driver metadata; stack traces describe the capture host rather than the database contract.
      outcome = { returned: false, error: {
        name: caught.name, message: caught.message, properties: observeValue(Object.fromEntries(Object.entries(caught))),
      } };
    }
    return { ...outcome, events: events.splice(0), stored: await readRaw(id) };
  };
  const create = (id, payload) => adapter.create({ model: "deviceCode", forceAllowId: true, data: input(id, payload) });
  const read = id => adapter.findOne({ model: "deviceCode", where: [{ field: "id", value: id }] });
  const reset = async () => {
    await adapter.deleteMany({ model: "deviceCode", where: [] });
    assert.deepEqual(await readRaw("unused"), []);
    assert.deepEqual(events.splice(0), []);
  };
  const cases = [];
  for (const scenario of scenarios) {
    await reset();
    const createdId = `create-${scenario.name}`;
    const created = await observe(createdId, () => create(createdId, scenario.value()));
    const createdRead = await observe(createdId, () => read(createdId));
    await reset();
    const updatedId = `update-${scenario.name}`;
    const seeded = await observe(updatedId, () => create(updatedId, { seed: "ordinary" }));
    assert.equal(seeded.returned, true, "The ordinary object must create the update baseline");
    const updated = await observe(updatedId, () => adapter.update({
      model: "deviceCode", where: [{ field: "id", value: updatedId }], update: { payload: scenario.value() },
    }));
    const updatedRead = await observe(updatedId, () => read(updatedId));
    cases.push({ name: scenario.name, input: observeValue(scenario.value()), created, createdRead, seeded, updated, updatedRead });
  }
  return cases;
}

export async function captureNativeJsonDriver(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend));
  const events = [];
  const config = configuration(events);
  if (backend === "sqlite") {
    const database = new Database(":memory:");
    try {
      const options = { ...config, database };
      await (await getMigrations(options)).runMigrations();
      const columns = database.query(`PRAGMA table_info("${table}")`).all();
      const cases = await captureRows({
        options, backend, query: async (sql, values) => database.query(sql).all(...values),
      }, events);
      return { version, backend, columns, cases };
    } finally {
      database.close();
    }
  }
  const captured = await captureFreshServerCatalog(backend, [table], config, context => captureRows(context, events));
  return { version, backend, columns: captured.columns, cases: captured.observation };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureNativeJsonDriver(backend), null, 2)}\n`);
}
