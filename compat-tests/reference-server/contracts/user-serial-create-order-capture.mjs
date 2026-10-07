import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const date = new Date("2030-01-02T03:04:05.000Z");
const data = label => ({
  name: label === "outer" ? "Outer owner" : "Inner owner", email: `${label}@serial-order.test`,
  emailVerified: false, image: null, createdAt: date, updatedAt: date, label,
});

async function captureCase(slot, operation) {
  const events = [];
  const memory = { user: [], account: [], session: [], verification: [] };
  let adapter;
  const fields = {};
  if (slot === "before-label") fields.id = { type: "string", transform: {
    input(value) { events.push(["input", "id", value]); return value; },
    output(value) { events.push(["output", "id", value]); return value; },
  } };
  fields.label = { type: "string", transform: {
    async input(value) {
      events.push(["input", "label", value]);
      if (value === "inner" && operation === "nested-failure") throw new Error("inner-field-failure");
      if (value === "outer") {
        const inner = await adapter.create({ model: "user", data: data("inner") });
        events.push(["nested-created", inner]);
        if (operation === "outer-failure") throw new Error("outer-field-failure");
      }
      return value;
    },
    output(value) { events.push(["output", "label", value]); return value; },
  } };
  ({ adapter } = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://serial-order.test",
    secret: "user-serial-order-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: "serial" } }, user: { additionalFields: fields },
  }).$context);
  const before = structuredClone(memory.user);
  let result = null;
  let error = null;
  try {
    result = await adapter.create({ model: "user", data: data("outer") });
  } catch (caught) {
    assert.ok(caught instanceof Error);
    error = { name: caught.name, message: caught.message };
  }
  return { slot, operation, before, events, result, error, after: structuredClone(memory.user) };
}

export async function captureUserSerialCreateOrder() {
  const cases = [];
  for (const slot of ["implicit", "before-label"]) {
    for (const operation of ["nested-success", "nested-failure", "outer-failure"]) {
      cases.push(await captureCase(slot, operation));
    }
  }
  return { version, cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass a fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureUserSerialCreateOrder(), null, 2)}\n`);
}
