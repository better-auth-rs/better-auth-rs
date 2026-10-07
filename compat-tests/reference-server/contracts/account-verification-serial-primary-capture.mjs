import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const date = new Date("2030-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const data = (model, label) => ({
  ...(model === "account"
    ? { accountId: `serial-${label}`, providerId: "ordinary", userId: "001" }
    : { identifier: `serial-${label}`, value: `value-${label}`, expiresAt }),
  createdAt: date, updatedAt: date, label,
});

async function context(model, slot, operation) {
  const events = [];
  const memory = { user: [], account: [], session: [], verification: [] };
  let adapter;
  const fields = {};
  if (slot === "before-label") fields.id = { type: "string", transform: {
    input(value) { events.push(["input", "id", observeValue(value)]); return value; },
    output(value) { events.push(["output", "id", observeValue(value)]); return value; },
  } };
  fields.label = { type: "string", transform: {
    async input(value) {
      events.push(["input", "label", observeValue(value)]);
      if (value === "inner" && operation === "nested-failure") throw new Error("inner-field-failure");
      if (value === "outer") {
        const inner = await adapter.create({ model, data: data(model, "inner") });
        events.push(["nested-created", observeValue(inner)]);
        if (operation === "outer-failure") throw new Error("outer-field-failure");
      }
      return value;
    },
    output(value) { events.push(["output", "label", observeValue(value)]); return value; },
  } };
  const ctx = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://record-serial.test",
    secret: "record-serial-primary-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: "serial" } }, [model]: { additionalFields: fields },
  }).$context;
  adapter = ctx.adapter;
  if (model === "account") await adapter.create({ model: "user", data: {
    name: "Account owner", email: "owner@record-serial.test", emailVerified: false,
    image: null, createdAt: date, updatedAt: date,
  } });
  return { adapter, internalAdapter: ctx.internalAdapter, memory, events };
}

async function captureCreateOrder(model, slot, operation) {
  const { adapter, memory, events } = await context(model, slot, operation);
  const before = observeValue(memory);
  let result = null;
  let error = null;
  try {
    result = observeValue(await adapter.create({ model, data: data(model, "outer") }));
  } catch (caught) {
    assert.ok(caught instanceof Error);
    error = { name: caught.name, message: caught.message };
  }
  return { model, slot, operation, before, events, result, error, after: observeValue(memory) };
}

async function captureLifecycle(model) {
  const { adapter, internalAdapter, memory, events } = await context(model, "implicit", "lifecycle");
  const before = observeValue(memory);
  const operations = [];
  let pending;
  let error = null;
  const step = async (name, run) => {
    pending = name;
    events.push(["operation", name]);
    const result = await run();
    operations.push({ name, result: observeValue(result), after: observeValue(memory) });
    pending = undefined;
    return result;
  };
  try {
    const first = await step("create-first", () => adapter.create({ model, data: data(model, "first") }));
    await step("create-second", () => adapter.create({ model, data: data(model, "second") }));
    const where = [{ field: "id", value: `00${first.id}` }];
    await step("read-padded-id", () => adapter.findOne({ model, where }));
    if (model === "account") {
      await step("update-padded-id", () => adapter.update({ model, where, update: { label: "updated", updatedAt: date } }));
      await step("delete-padded-id", () => adapter.delete({ model, where }));
      await step("read-deleted-id", () => adapter.findOne({ model, where }));
    } else {
      await step("consume-first", () => internalAdapter.consumeVerificationValue(first.identifier));
      await step("consume-missing", () => internalAdapter.consumeVerificationValue(first.identifier));
    }
    await step("create-after-removal", () => adapter.create({ model, data: data(model, "third") }));
    await step("read-all", () => adapter.findMany({ model }));
  } catch (caught) {
    assert.ok(caught instanceof Error);
    error = { operation: pending, name: caught.name, message: caught.message };
  }
  return { model, operation: "lifecycle", before, events, operations, error, after: observeValue(memory) };
}

export async function captureAccountVerificationSerialPrimary() {
  const cases = [];
  for (const model of ["account", "verification"]) {
    for (const slot of ["implicit", "before-label"]) {
      for (const operation of ["nested-success", "nested-failure", "outer-failure"]) {
        cases.push(await captureCreateOrder(model, slot, operation));
      }
    }
    cases.push(await captureLifecycle(model));
  }
  return { version, cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass a fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureAccountVerificationSerialPrimary(), null, 2)}\n`);
}
