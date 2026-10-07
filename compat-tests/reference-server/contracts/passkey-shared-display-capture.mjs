import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { testUtils } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";
import { observePasskeyOperations } from "./passkey-fields-capture.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/passkey"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const origin = "http://passkey-shared-display.test";
const table = "shared_display_passkey";
const ownerId = "shared-display-owner";
const passkeyId = "shared-display-passkey";
const createdAt = "2030-01-02T03:04:05.123Z";
const aaguid = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4";
const nativeFields = ["id", "name", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp", "transports", "createdAt", "aaguid"];
const physicalFields = [...nativeFields.filter(name => !["name", "aaguid"].includes(name)), "display"];

async function captureCase(backend, reversed) {
  const memory = { user: [], session: [], account: [], verification: [], [table]: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const http = [];
  const declarationOrder = reversed ? ["aaguid", "name"] : ["name", "aaguid"];
  const fields = Object.fromEntries(declarationOrder.map(name => [name, {
    type: "string", required: false, fieldName: "display",
    transform: {
      input(value) { events.push(["input", name, observeValue(value)]); return value; },
      output(value) { events.push(["output", name, observeValue(value)]); return value; },
    },
  }]));
  const options = {
    database: sqlite ?? memoryAdapter(memory), baseURL: origin,
    secret: "ordinary-shared-passkey-display-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    plugins: [passkey(), testUtils(), {
      id: "ordinary-shared-passkey-display",
      schema: { passkey: { modelName: table, fields } },
    }],
  };
  try {
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const catalog = sqlite ? observeSqliteCatalog(sqlite, table, "The shared Passkey table must exist") : null;
    const auth = betterAuth(options);
    const context = await auth.$context;
    const adapter = context.adapter;
    const owner = await adapter.create({ model: "user", forceAllowId: true, data: {
      id: ownerId, name: "Shared display owner", email: "owner@passkey-shared-display.test",
      emailVerified: true, image: null, createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
    } });
    assert.equal(owner.id, ownerId);
    const login = await context.test.login({ userId: ownerId });
    const cookie = login.headers.get("cookie");
    const cookieName = context.authCookies.sessionToken.name;
    assert.ok(cookie?.startsWith(`${cookieName}=`));
    const observeRow = row => ({ keys: Object.keys(row), fields: observeValue(row) });
    const visible = row => {
      assert.deepEqual(Object.keys(row).sort(), [...nativeFields].sort());
      assert.equal(row.id, passkeyId);
      assert.equal(row.userId, ownerId);
      assert.equal(row.credentialID, "ordinary-shared-display-credential");
      assert.equal(row.publicKey, "ordinary-public-key");
      assert.equal(row.deviceType, "singleDevice");
      assert.equal(row.backedUp, false);
      assert.equal(row.transports, null);
      assert.equal(row.createdAt instanceof Date ? row.createdAt.toISOString() : row.createdAt, createdAt);
      return observeRow(row);
    };
    const stored = async () => {
      const rows = sqlite ? sqlite.query(`SELECT * FROM ${table} ORDER BY id`).all() : memory[table];
      assert.equal(rows.length, 1);
      for (const row of rows) {
        assert.deepEqual(Object.keys(row).sort(), [...physicalFields].sort());
        assert.equal(row.id, passkeyId);
        assert.equal(row.userId, ownerId);
        assert.equal(row.createdAt instanceof Date ? row.createdAt.toISOString() : row.createdAt, createdAt);
      }
      return rows.map(observeRow);
    };
    const execute = async (operation, id) => {
      const where = [{ field: "id", value: id }];
      if (operation === "create") return [await adapter.create({ model: "passkey", forceAllowId: true, data: {
        id: passkeyId, name: "Desk", aaguid, userId: ownerId,
        credentialID: "ordinary-shared-display-credential", publicKey: "ordinary-public-key",
        counter: 0, deviceType: "singleDevice", backedUp: false, transports: null, createdAt: new Date(createdAt),
      } })];
      if (operation === "get-id") return [await adapter.findOne({ model: "passkey", where })];
      if (operation === "get-credential") return [await adapter.findOne({ model: "passkey", where: [{
        field: "credentialID", value: "ordinary-shared-display-credential",
      }] })];
      if (operation === "list") return await adapter.findMany({ model: "passkey", where: [{ field: "userId", value: ownerId }] });
      if (operation === "update-auth") return [await adapter.update({ model: "passkey", where, update: { counter: 1 } })];
      assert.equal(operation, "update-name");
      const headers = new Headers(login.headers);
      headers.set("origin", origin);
      headers.set("accept", "application/json");
      headers.set("content-type", "application/json");
      const body = JSON.stringify({ id, name: " Renamed " });
      const request = new Request(`${origin}/api/auth/passkey/update-passkey`, { method: "POST", headers, body });
      const response = await auth.handler(request);
      const responseBody = await response.text();
      http.push({
        name: operation, request: { url: request.url, method: request.method,
          headers: [...headers].map(([name, value]) => {
            if (name !== "cookie") return [name, value];
            assert.equal(value, cookie);
            return [name, `${cookieName}=<owner-session-cookie>`];
          }), body },
        response: { status: response.status, statusText: response.statusText,
          headers: [...response.headers], cookies: response.headers.getSetCookie(), body: responseBody },
      });
      assert.equal(response.status, 200);
      const result = JSON.parse(responseBody);
      assert.deepEqual(Object.keys(result), ["passkey"]);
      return [result.passkey];
    };
    assert.deepEqual(events, []);
    const operations = await observePasskeyOperations({ execute, visible, stored, events }, observation => {
      const updated = observation.name.startsWith("update-");
      const display = updated ? "Renamed" : aaguid;
      assert.equal(observation.result[0].fields.name, display);
      assert.equal(observation.result[0].fields.aaguid, display);
      assert.equal(observation.stored[0].fields.display, display);
      assert.equal(observation.result[0].fields.counter, observation.name === "update-auth" ? 1 : 0);
      assert.equal(observation.stored[0].fields.counter, observation.name === "update-auth" ? 1 : 0);
      if (observation.name === "create") assert.deepEqual(observation.events, [
        ["input", "name", "Desk"], ["input", "aaguid", aaguid],
        ["output", "name", aaguid], ["output", "aaguid", aaguid],
      ]);
    });
    assert.deepEqual(events, []);
    const read = await adapter.findOne({ model: "passkey", where: [{ field: "id", value: passkeyId }] });
    const finalRead = { name: "read-updated", events: events.splice(0), result: visible(read), stored: await stored() };
    assert.equal(finalRead.result.fields.name, "Renamed");
    assert.equal(finalRead.result.fields.aaguid, "Renamed");
    assert.equal(finalRead.result.fields.counter, 1);
    return { backend, declarationOrder, table, column: "display", catalog, operations, http, finalRead };
  } finally { sqlite?.close(); }
}

export async function capturePasskeySharedDisplay() {
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const reversed of [false, true]) cases.push(await captureCase(backend, reversed));
  }
  return { version, cases };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await capturePasskeySharedDisplay(), null, 2)}\n`);
}
