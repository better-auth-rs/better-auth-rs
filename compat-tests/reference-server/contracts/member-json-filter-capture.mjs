import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { getOrgAdapter } from "better-auth/plugins/organization";
import { observeValue } from "./device-where-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const instant = "2030-01-02T03:04:05.123Z";
const organizationId = "json-filter-organization";
const tables = ["user", "session", "account", "verification", "organization", "member", "invitation"];
const field = { name: "settings", type: "json", fieldName: "stored_settings" };
const members = [
  { id: "member-a", userId: "user-a", role: "owner", settings: ["red", "blue"] },
  { id: "member-b", userId: "user-b", role: "member", settings: { control: true } },
  { id: "member-c", userId: "user-c", role: "member", settings: null },
].map(row => ({ ...row, organizationId, createdAt: instant }));
const json = value => JSON.parse(JSON.stringify(value));
export const operationNames = ["array-eq", "array-in", "array-not-in", "object-eq"];
// The object control uses the Organization adapter because the public query schema rejects object values.
const inputs = ["eq", "in", "not_in", "eq"].map((operator, index) => ({
  organizationId, limit: index === 2 ? 1 : 10, offset: 0, sortBy: "id", sortOrder: "asc",
  filter: { field: field.name, value: index === 3 ? { control: true } : ["red", "blue"], operator },
}));

async function captureBackend(backend, diagnostics) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const policy = { type: field.type, required: false, fieldName: field.fieldName };
  const orgOptions = trace => ({ schema: { member: { additionalFields: { settings: {
    ...policy,
    ...(trace ? { transform: {
      input(value) { events.push(["input", "settings", observeValue(value)]); return value; },
      output(value) { events.push(["output", "settings", observeValue(value)]); return value; },
    } } : {}),
  } } } } });
  const options = trace => ({
    database: sqlite ?? memoryAdapter(memory), baseURL: "http://member-json-filter.test",
    secret: "ordinary-member-json-filter-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, plugins: [organization(orgOptions(trace))],
  });
  const diagnostic = { backend, created: [], operations: [] };
  diagnostics.push(diagnostic);
  const physical = () => observeValue(Object.fromEntries(tables.map(model => [model,
    sqlite ? sqlite.query(`SELECT * FROM "${model}" ORDER BY id`).all() : memory[model],
  ])));
  try {
    if (sqlite) await (await getMigrations(options(false))).runMigrations();
    const reader = (await betterAuth(options(false)).$context).adapter;
    const context = await betterAuth(options(true)).$context;
    const { adapter } = context;
    const org = getOrgAdapter(context, orgOptions(true));
    const stored = async () => reader.findMany({ model: "member", sortBy: { field: "id", direction: "asc" } });
    for (const row of members) {
      diagnostic.created.push(observeValue(await adapter.create({ model: "user", forceAllowId: true, data: {
        id: row.userId, name: row.userId, email: `${row.userId}@member-json-filter.test`, emailVerified: false,
        image: null, createdAt: new Date(instant), updatedAt: new Date(instant),
      } })));
    }
    diagnostic.created.push(observeValue(await adapter.create({ model: "organization", forceAllowId: true, data: {
      id: organizationId, name: "JSON filter organization", slug: "json-filter-organization", createdAt: new Date(instant),
    } })));
    const created = [];
    for (const row of members) {
      const result = await adapter.create({ model: "member", forceAllowId: true, data: { ...row, createdAt: new Date(row.createdAt) } });
      diagnostic.created.push(observeValue(result));
      created.push(json(result));
    }
    const seedEvents = events.splice(0);
    diagnostic.seedEvents = observeValue(seedEvents);
    diagnostic.seedPhysical = physical();
    const initial = await stored();
    diagnostic.stored = observeValue(initial);
    const operations = [];
    for (const [index, name] of operationNames.entries()) {
      const input = json(inputs[index]);
      const raw = { name, input: observeValue(input), before: physical() };
      diagnostic.operations.push(raw);
      let result = null;
      let error = null;
      try {
        const returned = await org.listMembers(input);
        raw.result = observeValue(returned);
        result = json(returned);
      } catch (failure) {
        raw.error = { name: failure.name, message: failure.message, stack: failure.stack };
        error = { name: failure.name, message: failure.message };
      }
      raw.events = observeValue(events.splice(0));
      const persisted = await stored();
      raw.stored = observeValue(persisted);
      raw.after = physical();
      operations.push({ name, input, result, error, events: raw.events, stored: json(persisted) });
    }
    return { backend, created, seedEvents, stored: json(initial), operations };
  } catch (error) {
    diagnostic.error = { name: error.name, message: error.message, stack: error.stack };
    throw error;
  } finally {
    sqlite?.close();
  }
}

export async function captureMemberJsonFilter({ diagnostics = [] } = {}) {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) backends.push(await captureBackend(backend, diagnostics));
  return { version, field, backends };
}

export function assertMemberJsonFilter(observed, diagnostics) {
  assert.equal(observed.version, "1.7.6");
  assert.deepEqual(observed.field, field);
  assert.deepEqual(observed.backends.map(({ backend }) => backend), ["memory", "sqlite"]);
  for (const entry of observed.backends) {
    const { backend, created, seedEvents, stored, operations } = entry;
    assert.deepEqual(created, members);
    assert.deepEqual(stored, members);
    assert.deepEqual(seedEvents, members.flatMap(row => [
      ["input", "settings", row.settings], ["output", "settings", JSON.stringify(row.settings)],
    ]));
    const diagnostic = diagnostics.find(entry => entry.backend === backend);
    assert.deepEqual(diagnostic.seedPhysical.member.map(row => ({ id: row.id, settings: row.stored_settings })),
      members.map(row => ({ id: row.id, settings: JSON.stringify(row.settings) })));
    assert.deepEqual(operations.map(({ name }) => name), operationNames);
    for (const [index, operation] of operations.entries()) {
      const { name, input, result, error, events, stored: persisted } = operation;
      assert.deepEqual(input, inputs[index]);
      assert.deepEqual(persisted, stored);
      assert.deepEqual(diagnostic.operations[index].after, diagnostic.operations[index].before);
      if (backend === "memory" && ["array-in", "array-not-in"].includes(name)) {
        assert.equal(result, null);
        assert.deepEqual(error, { name: "Error", message: "Value must be an array" });
        assert.deepEqual(events, []);
        continue;
      }
      assert.equal(error, null);
      const row = members[name === "array-not-in" || name === "object-eq" ? 1 : 0];
      assert.deepEqual(result, { members: [{ ...row, user: {
        id: row.userId, name: row.userId, email: `${row.userId}@member-json-filter.test`, image: null,
      } }], total: name === "array-not-in" ? 2 : 1 });
      assert.deepEqual(events, [["output", "settings", JSON.stringify(row.settings)]]);
    }
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the Member JSON filter fixture output path");
  const diagnostics = [];
  try {
    const observed = await captureMemberJsonFilter({ diagnostics });
    writeFileSync(`${output}.raw.json`, `${JSON.stringify(observed, null, 2)}\n`);
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
    assertMemberJsonFilter(observed, diagnostics);
    writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
