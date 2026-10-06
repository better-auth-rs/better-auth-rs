import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const createdAt = "2030-01-02T03:04:05.123Z";
const json = value => JSON.parse(JSON.stringify(value));
const callbackValue = value => value === undefined ? { type: "undefined" } : json(value);
const policies = () => ({
  label: { type: "string", fieldName: "stored_label", required: false, defaultValue: " Default " },
  activatedAt: { type: "date", fieldName: "stored_activation", required: false },
  details: { type: "json", fieldName: "stored_details", required: false },
  revision: { type: "number", fieldName: "stored_revision", required: false, defaultValue: 1.5 },
});
const nativeFields = ["id", "name", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp", "transports", "createdAt", "aaguid"];
const input = owner => ({
  name: "Desk", userId: owner, credentialID: "ordinary-credential",
  publicKey: "ordinary-public-key", counter: 0, deviceType: "singleDevice", backedUp: false,
  transports: null, createdAt: new Date(createdAt), aaguid: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
  activatedAt: "2029-01-02T03:04:05.000Z", details: { channel: "ordinary", enabled: true },
});

async function withFixture(backend, run) {
  const memory = { user: [], session: [], account: [], verification: [], ordinary_passkey_fields: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = fields => ({
    database: sqlite ?? memoryAdapter(memory),
    baseURL: "http://passkey-fields.test",
    secret: "ordinary-passkey-extra-fields-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [passkey(), {
      id: "ordinary-passkey-additional-fields",
      schema: { passkey: { modelName: "ordinary_passkey_fields", fields } },
    }],
  });
  try {
    if (sqlite) await (await getMigrations(options(policies()))).runMigrations();
    const reader = (await betterAuth(options(policies())).$context).adapter;
    const owner = await reader.create({ model: "user", data: {
      name: "Passkey field owner", email: "owner@passkey-fields.test", emailVerified: false,
      createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
    } });
    const events = [];
    const errors = {
      input: new Error("ordinary Passkey input error"),
      output: new Error("ordinary Passkey output error"),
    };
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
    const visible = row => {
      if (row === null) return null;
      assert.deepEqual(Object.keys(row).sort(), [...nativeFields, ...Object.keys(policies())].sort());
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
      assert.equal(row.aaguid, input(owner.id).aaguid);
      assert.ok(row.createdAt instanceof Date);
      assert.equal(row.createdAt.toISOString(), createdAt);
      return json({ ...row, id: "<passkey-id>", userId: "<owner-id>", createdAt: "<created-at>" });
    };
    const stored = async () => {
      const rows = await reader.findMany({ model: "passkey", where: [{ field: "userId", value: owner.id }] });
      assert.ok(rows.length <= 1);
      return rows.map(visible);
    };
    const execute = async (operation, id) => {
      const where = [{ field: "id", value: id }];
      if (operation === "create") return [await adapter.create({ model: "passkey", data: input(owner.id) })];
      if (operation === "get-id") return [await adapter.findOne({ model: "passkey", where })];
      if (operation === "get-credential") return [await adapter.findOne({ model: "passkey", where: [{ field: "credentialID", value: "ordinary-credential" }] })];
      if (operation === "list") return await adapter.findMany({ model: "passkey", where: [{ field: "userId", value: owner.id }] });
      assert.ok(["update-name", "update-auth"].includes(operation));
      return [await adapter.update({ model: "passkey", where, update: operation === "update-name" ? { name: "Desk-renamed" } : { counter: 1 } })];
    };
    events.length = 0;
    return await run({ execute, visible, stored, events, errors, setFailure(value) { failure = value; } });
  } finally {
    sqlite?.close();
  }
}

async function captureOperations(backend) {
  return await withFixture(backend, async ({ execute, visible, stored, events }) => {
    const operations = [];
    let id;
    for (const name of ["create", "get-id", "get-credential", "list", "update-name", "update-auth"]) {
      assert.equal(events.length, 0);
      const result = await execute(name, id);
      assert.equal(result.length, 1);
      assert.ok(result[0]);
      if (name === "create") id = result[0].id;
      const observation = { name, events: events.splice(0), result: result.map(visible), stored: await stored() };
      assert.equal(observation.result[0].label, "Default:out");
      assert.equal(observation.stored[0].label, "Default");
      assert.equal(observation.stored[0].revision, name.startsWith("update-") ? 2.5 : 1.5);
      assert.equal(observation.stored[0].counter, name === "update-auth" ? 1 : 0);
      operations.push(observation);
    }
    return operations;
  });
}

async function captureFailure(backend, operation, phase) {
  return await withFixture(backend, async ({ execute, stored, events, errors, setFailure }) => {
    let id;
    if (operation !== "create") id = (await execute("create"))[0].id;
    const before = await stored();
    events.length = 0;
    setFailure(phase);
    let sameError = false;
    try {
      await execute(operation, id);
    } catch (error) {
      if (error !== errors[phase]) throw error;
      sameError = true;
    }
    assert.equal(sameError, true, "The configured callback must reject the operation");
    setFailure(undefined);
    const persisted = await stored();
    if (phase === "input") assert.deepEqual(persisted, before);
    else {
      assert.equal(persisted.length, 1);
      assert.equal(persisted[0].name, operation === "update-name" ? "Desk-renamed" : "Desk");
      assert.equal(persisted[0].counter, operation === "update-auth" ? 1 : 0);
      assert.equal(persisted[0].revision, operation === "create" ? 1.5 : 2.5);
    }
    return {
      name: `${operation}-${phase}-error`, events: events.splice(0),
      result: { sameError, message: errors[phase].message }, stored: persisted,
    };
  });
}

export async function capturePasskeyFields() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const operations = await captureOperations(backend);
    const failures = [];
    for (const operation of ["create", "update-name", "update-auth"]) {
      for (const phase of ["input", "output"]) failures.push(await captureFailure(backend, operation, phase));
    }
    backends.push({ backend, operations, failures });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await capturePasskeyFields(), null, 2)}\n`);
}
