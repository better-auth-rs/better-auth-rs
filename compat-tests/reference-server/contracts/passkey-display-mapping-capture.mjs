import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import {
  observePasskeyFailure, observePasskeyOperations, passkeyFailureOperations,
} from "./passkey-fields-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const createdAt = "2030-01-02T03:04:05.123Z";
const firstAaguid = "EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4";
const updatedAaguid = "DD4EC289-E01D-41C9-BB89-70FA845D4BF2";
const table = "ordinary_mapped_passkey";
const nativeFields = ["id", "name", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp", "transports", "createdAt", "aaguid"];
const json = value => JSON.parse(JSON.stringify(value));
const callbackValue = value => value === undefined ? { type: "undefined" } : json(value);
export const mappingNames = ["default", "empty", "renamed"];
const mappedName = (mapping, field) => mapping === "renamed" ? `stored_${field}` : mapping === "empty" ? "" : undefined;
const policies = mapping => Object.fromEntries(["aaguid", "name"].map(field => [field, {
  type: "string", required: false,
  ...(mapping === "default" ? {} : { fieldName: mappedName(mapping, field) }),
}]));
const input = owner => ({
  name: " Desk ", userId: owner, credentialID: "ordinary-credential",
  publicKey: "ordinary-public-key", counter: 0, deviceType: "singleDevice", backedUp: false,
  transports: null, createdAt: new Date(createdAt), aaguid: ` ${firstAaguid} `,
});

async function withFixture(backend, mapping, run) {
  const memory = { user: [], session: [], account: [], verification: [], [table]: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const columns = { name: mappedName(mapping, "name") || "name", aaguid: mappedName(mapping, "aaguid") || "aaguid" };
  const physicalFields = nativeFields.map(field => columns[field] ?? field).sort();
  const options = fields => ({
    database: sqlite ?? memoryAdapter(memory), baseURL: "http://passkey-fields.test",
    secret: "ordinary-passkey-extra-fields-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [passkey({ schema: { passkey: {
      modelName: table,
      ...(mapping === "default" ? {} : { fields: { name: mappedName(mapping, "name"), aaguid: mappedName(mapping, "aaguid") } }),
    } } }), {
      id: "ordinary-passkey-display-mapping",
      schema: { passkey: { modelName: table, fields } },
    }],
  });
  try {
    if (sqlite) {
      await (await getMigrations(options(policies(mapping)))).runMigrations();
      assert.deepEqual(sqlite.query(`PRAGMA table_info(${table})`).all().map(column => column.name).sort(), physicalFields);
    }
    const reader = (await betterAuth(options(policies(mapping))).$context).adapter;
    const owner = await reader.create({ model: "user", data: {
      name: "Passkey field owner", email: "owner@passkey-fields.test", emailVerified: false,
      createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
    } });
    const events = [];
    const errors = { input: new Error("ordinary Passkey input error"), output: new Error("ordinary Passkey output error") };
    let failure;
    const fields = Object.fromEntries(Object.entries(policies(mapping)).map(([name, field]) => [name, {
      ...field,
      ...(name === "aaguid" ? {
        onUpdate() { events.push(["onUpdate", name]); return ` ${updatedAaguid} `; },
      } : {}),
      transform: {
        input(value) {
          events.push(["input", name, callbackValue(value)]);
          if (name === "aaguid" && failure === "input") throw errors.input;
          return typeof value === "string" ? name === "aaguid" ? value.trim().toLowerCase() : value.trim() : value;
        },
        output(value) {
          events.push(["output", name, callbackValue(value)]);
          if (name === "aaguid" && failure === "output") throw errors.output;
          return typeof value === "string" ? name === "aaguid" ? value.toUpperCase() : `${value}:out` : value;
        },
      },
    }]));
    const adapter = (await betterAuth(options(fields)).$context).adapter;
    let identity;
    const visible = row => {
      assert.notEqual(row, null);
      assert.deepEqual(Object.keys(row).sort(), [...nativeFields].sort());
      assert.equal(typeof row.id, "string");
      assert.ok(row.id.length > 0);
      if (identity === undefined) identity = row.id;
      assert.equal(row.id, identity);
      assert.equal(row.userId, owner.id);
      assert.equal(row.credentialID, "ordinary-credential");
      assert.equal(row.publicKey, "ordinary-public-key");
      assert.equal(row.deviceType, "singleDevice");
      assert.equal(row.backedUp, false);
      assert.equal(row.transports, null);
      assert.ok(row.createdAt instanceof Date);
      assert.equal(row.createdAt.toISOString(), createdAt);
      return json({ ...row, id: "<passkey-id>", userId: "<owner-id>", createdAt: "<created-at>" });
    };
    const stored = async () => {
      const rows = await reader.findMany({ model: "passkey", where: [{ field: "userId", value: owner.id }] });
      assert.ok(rows.length <= 1);
      // Read the physical rows directly so logical projection cannot hide a missing column mapping.
      const physical = sqlite ? sqlite.query(`SELECT * FROM ${table}`).all() : memory[table];
      assert.equal(physical.length, rows.length);
      for (const row of rows) {
        const raw = physical.find(raw => raw.id === row.id);
        assert.ok(raw);
        assert.deepEqual(Object.keys(raw).sort(), physicalFields);
        assert.equal(raw[columns.name], row.name);
        assert.equal(raw[columns.aaguid], row.aaguid);
      }
      return rows.map(visible);
    };
    const execute = async (operation, id) => {
      const where = [{ field: "id", value: id }];
      if (operation === "create") return [await adapter.create({ model: "passkey", data: input(owner.id) })];
      if (operation === "get-id") return [await adapter.findOne({ model: "passkey", where })];
      if (operation === "get-credential") return [await adapter.findOne({ model: "passkey", where: [{ field: "credentialID", value: "ordinary-credential" }] })];
      if (operation === "list") return await adapter.findMany({ model: "passkey", where: [{ field: "userId", value: owner.id }] });
      assert.ok(["update-name", "update-auth"].includes(operation));
      return [await adapter.update({ model: "passkey", where, update: operation === "update-name" ? { name: " Desk-renamed " } : { counter: 1 } })];
    };
    return await run({ execute, visible, stored, events, errors, setFailure(value) { failure = value; } });
  } finally {
    sqlite?.close();
  }
}

async function captureOperations(backend, mapping) {
  return await withFixture(backend, mapping, fixture => observePasskeyOperations(fixture, observation => {
    const updated = observation.name.startsWith("update-");
    const name = updated ? "Desk-renamed" : "Desk";
    const aaguid = updated ? updatedAaguid : firstAaguid;
    assert.equal(observation.result[0].name, `${name}:out`);
    assert.equal(observation.result[0].aaguid, aaguid);
    assert.equal(observation.stored[0].name, name);
    assert.equal(observation.stored[0].aaguid, aaguid.toLowerCase());
    assert.equal(observation.stored[0].counter, observation.name === "update-auth" ? 1 : 0);
  }));
}

async function captureFailure(backend, mapping, operation, phase) {
  return await withFixture(backend, mapping, fixture => observePasskeyFailure(fixture, operation, phase, persisted => {
    assert.equal(persisted[0].name, operation === "update-name" ? "Desk-renamed" : "Desk");
    assert.equal(persisted[0].aaguid, (operation === "create" ? firstAaguid : updatedAaguid).toLowerCase());
    assert.equal(persisted[0].counter, operation === "update-auth" ? 1 : 0);
  }));
}

export async function capturePasskeyDisplayMapping() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const cases = [];
    for (const mapping of mappingNames) {
      const operations = await captureOperations(backend, mapping);
      const failures = [];
      for (const operation of passkeyFailureOperations) {
        for (const phase of ["input", "output"]) failures.push(await captureFailure(backend, mapping, operation, phase));
      }
      cases.push({ mapping, operations, failures });
    }
    backends.push({ backend, cases });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await capturePasskeyDisplayMapping(), null, 2)}\n`);
}
