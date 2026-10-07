import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const date = new Date("2030-01-02T03:04:05.000Z");
const slots = ["implicit", "before-label", "after-label"];
const operations = ["generated", "generator-failure", "field-failure", "supplied-id"];

async function observe(backend, slot, operation) {
  const events = [];
  const memory = { user: [], account: [], session: [], verification: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const transform = field => ({
    input(value) {
      events.push(["input", `user.${field}`, value]);
      if (operation === "field-failure" && field === "label") throw new Error("label-input-failure");
      return value;
    },
    output(value) {
      events.push(["output", `user.${field}`, value]);
      return value;
    },
  });
  const fields = { name: { type: "string", transform: transform("name") } };
  const id = { type: "string", transform: transform("id") };
  if (slot === "before-label") fields.id = id;
  fields.label = { type: "string", transform: transform("label") };
  if (slot === "after-label") fields.id = id;
  const options = {
    database: sqlite ?? memoryAdapter(memory),
    baseURL: "http://user-id-order.test",
    secret: "user-id-order-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId({ model }) {
      events.push(["generateId", model]);
      if (operation === "generator-failure") throw new Error("generator-failure");
      return "generated-owner";
    } } },
    user: { additionalFields: fields },
  };
  const stored = () => sqlite ? sqlite.query('SELECT * FROM "user" ORDER BY "id"').all() : structuredClone(memory.user);
  try {
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const adapter = (await betterAuth(options).$context).adapter;
    const before = stored();
    events.length = 0;
    let result;
    try {
      result = await adapter.create({
        model: "user",
        forceAllowId: operation === "supplied-id",
        data: {
          ...(operation === "supplied-id" ? { id: "supplied-owner" } : {}),
          name: "Owner", email: "owner@user-id-order.test", emailVerified: true,
          image: "owner-image", createdAt: date, updatedAt: date, label: "Label",
        },
      });
    } catch (error) {
      result = { error: error.message };
    }
    const after = stored();
    assert.deepEqual(before, []);
    if (operation.endsWith("failure")) {
      assert.deepEqual(result, { error: operation === "field-failure" ? "label-input-failure" : "generator-failure" });
      assert.deepEqual(after, []);
    } else {
      assert.equal(result.id, operation === "supplied-id" ? "supplied-owner" : "generated-owner");
      assert.equal(after.length, 1);
    }
    return { backend, slot, operation, before, events, result, after };
  } finally {
    sqlite?.close();
  }
}

export async function captureUserIdGenerationOrder() {
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const slot of slots) {
      for (const operation of operations) cases.push(await observe(backend, slot, operation));
    }
  }
  assert.equal(cases.length, 24);
  return { version, cases };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureUserIdGenerationOrder(), (_, value) => value === undefined ? { $undefined: true } : value, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
