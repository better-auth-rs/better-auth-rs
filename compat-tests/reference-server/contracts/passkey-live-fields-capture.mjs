import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const rows = [
  { key: "Desk", before: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", after: "adce0002-35bc-c60a-648b-0b25f1f05503" },
  { key: "Travel", before: "dd4ec289-e01d-41c9-bb89-70fa845d4bf2", after: "08987058-cadc-4b81-b6e1-30de50dcbe96" },
];
const scenarios = [
  ...["create", "get-id", "get-credential", "list", "update-name", "update-auth"].map(path => ({ path, configuredAaguid: true, failOutput: false })),
  ...["get-id", "list"].map(path => ({ path, configuredAaguid: false, failOutput: false })),
  { path: "update-name", configuredAaguid: true, failOutput: true },
];
const createdAt = "2030-01-02T03:04:05.123Z";
const outputErrorMessage = "ordinary live Passkey output error";
const nativeFields = ["id", "name", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp", "transports", "createdAt", "aaguid"];

async function captureCase(backend, scenario) {
  const { path, configuredAaguid, failOutput } = scenario;
  const memory = { user: [], session: [], account: [], verification: [], passkey: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = fields => ({
    database: sqlite ?? memoryAdapter(memory),
    baseURL: "http://passkey-live-fields.test",
    secret: "ordinary-passkey-live-fields-contract-at-least-32-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    plugins: [passkey(), { id: "ordinary-live-passkey", schema: { passkey: { fields } } }],
  });
  try {
    if (sqlite) await (await getMigrations(options({}))).runMigrations();
    const raw = (await betterAuth(options({})).$context).adapter;
    const owner = await raw.create({ model: "user", data: {
      name: "Owner", email: "owner@passkey-live-fields.test", emailVerified: false,
      createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
    } });
    const writers = new Map();
    for (const row of rows) {
      const context = await betterAuth(options({ aaguid: {
        type: "string", required: false, onUpdate: () => row.after,
      } })).$context;
      writers.set(row.key, context.adapter);
    }
    const activeRows = path === "list" ? rows : rows.slice(0, 1);
    // Each row keeps its complete trace. Independent SQL callback completion order is outside this contract.
    const events = Object.fromEntries(activeRows.map(row => [row.key, []]));
    const outputError = new Error(outputErrorMessage);
    const fields = {
      name: { type: "string", required: false, transform: { async output(value) {
        const row = rows.find(row => value === row.key || value === `${row.key}-renamed`);
        assert.ok(row, "The selected row has its ordinary stored name");
        events[row.key].push(["name", value]);
        const writer = writers.get(row.key);
        const stored = await writer.findOne({ model: "passkey", where: [{ field: "credentialID", value: `credential:${row.key}` }] });
        assert.ok(stored, "The callback writer finds the selected credential");
        const updated = await writer.update({ model: "passkey", where: [{ field: "id", value: stored.id }], update: { name: value } });
        assert.equal(updated.name, value);
        assert.equal(updated.aaguid, row.after);
        events[row.key].push(["write", { name: updated.name, aaguid: updated.aaguid }]);
        return `${value}:out`;
      } } },
      ...(configuredAaguid ? { aaguid: { type: "string", required: false, transform: { output(value) {
        const row = rows.find(row => value === row.before || value === row.after);
        assert.ok(row, "The output callback receives a declared AAGUID");
        events[row.key].push(["aaguid", value]);
        if (failOutput) throw outputError;
        return value.toUpperCase();
      } } } } : {}),
    };
    const reader = (await betterAuth(options(fields)).$context).adapter;
    const data = row => ({
      name: row.key, userId: owner.id, credentialID: `credential:${row.key}`,
      publicKey: "ordinary-public-key", counter: 0, deviceType: "singleDevice", backedUp: false,
      transports: null, createdAt: new Date(createdAt), aaguid: row.before,
    });
    const seeded = [];
    if (path !== "create") {
      for (const row of activeRows) seeded.push(await raw.create({ model: "passkey", data: data(row) }));
    }
    let result = null;
    let error = null;
    try {
      if (path === "create") result = [await reader.create({ model: "passkey", data: data(rows[0]) })];
      else if (path === "get-id") result = [await reader.findOne({ model: "passkey", where: [{ field: "id", value: seeded[0].id }] })];
      else if (path === "get-credential") result = [await reader.findOne({ model: "passkey", where: [{ field: "credentialID", value: seeded[0].credentialID }] })];
      else if (path === "list") result = await reader.findMany({ model: "passkey", where: [{ field: "userId", value: owner.id }] });
      else result = [await reader.update({ model: "passkey", where: [{ field: "id", value: seeded[0].id }], update: path === "update-name" ? { name: "Desk-renamed" } : { counter: 1 } })];
    } catch (caught) {
      assert.equal(caught, outputError);
      error = { sameError: caught === outputError, message: caught.message };
    }
    assert.equal(error !== null, failOutput);
    const stored = await raw.findMany({ model: "passkey", where: [{ field: "userId", value: owner.id }] });
    assert.deepEqual(stored.map(row => row.credentialID), activeRows.map(row => `credential:${row.key}`));
    const visible = row => {
      assert.deepEqual(Object.keys(row).sort(), [...nativeFields].sort());
      const declaration = activeRows.find(candidate => row.credentialID === `credential:${candidate.key}`);
      assert.ok(declaration);
      const source = stored.find(candidate => candidate.credentialID === row.credentialID);
      assert.equal(row.id, source.id);
      assert.equal(typeof row.id, "string");
      assert.ok(row.id.length > 0);
      assert.equal(row.userId, owner.id);
      assert.equal(row.publicKey, "ordinary-public-key");
      assert.equal(row.counter, path === "update-auth" ? 1 : 0);
      assert.equal(row.deviceType, "singleDevice");
      assert.equal(row.backedUp, false);
      assert.equal(row.transports, null);
      assert.ok(row.createdAt instanceof Date);
      assert.equal(row.createdAt.toISOString(), createdAt);
      return { ...row, id: `<${declaration.key}-id>`, userId: "<owner-id>", createdAt: "<created-at>" };
    };
    return { ...scenario, events, result: result?.map(visible) ?? null, error, stored: stored.map(visible) };
  } finally {
    sqlite?.close();
  }
}

export async function capturePasskeyLiveFields() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const cases = [];
    for (const scenario of scenarios) cases.push(await captureCase(backend, scenario));
    backends.push({ backend, cases });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await capturePasskeyLiveFields(), null, 2)}\n`);
}
