import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { jwt, siwe } from "better-auth/plugins";
import { observeValue as observeSharedValue } from "./device-where-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const date = new Date("2030-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const models = ["session", "jwks", "walletAddress", "rateLimit"];

// JSON erases the sign of zero. Preserve the sign in this contract's input and hook observations.
function observeValue(value) {
  if (Object.is(value, -0)) return { type: "number", value: "-0" };
  if (Array.isArray(value)) return value.map(observeValue);
  if (value !== null && typeof value === "object" && !(value instanceof Date)) {
    return Object.fromEntries(Object.entries(value).map(([key, value]) => [key, observeValue(value)]));
  }
  return observeSharedValue(value);
}

function data(model, label) {
  switch (model) {
    case "session": return {
      token: `serial-${label}`, userId: "001", expiresAt, createdAt: date, updatedAt: date,
      ipAddress: null, userAgent: null, label,
    };
    case "jwks": return {
      publicKey: `public-${label}`, privateKey: `private-${label}`, createdAt: date,
      expiresAt: null, alg: "EdDSA", crv: null, label,
    };
    case "walletAddress": return {
      userId: "001", address: `serial-${label}`, chainId: 1, isPrimary: false,
      createdAt: date, label,
    };
    case "rateLimit": return { key: `serial-${label}`, count: 1, lastRequest: date.getTime(), label };
    default: throw new Error(`Unknown Serial model: ${model}`);
  }
}

async function context(model, slot, operation) {
  const events = [];
  const memory = { user: [], account: [], session: [], verification: [], jwks: [], walletAddress: [], rateLimit: [] };
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
        if (operation === "nested-delete") {
          const deleted = await adapter.delete({ model, where: [{ field: "id", value: inner.id }] });
          events.push(["nested-deleted", observeValue(deleted), observeValue(memory[model])]);
        }
        if (operation === "outer-failure") throw new Error("outer-field-failure");
      }
      return value;
    },
    output(value) { events.push(["output", "label", observeValue(value)]); return value; },
  } };
  const plugins = [];
  if (model === "jwks") plugins.push(jwt());
  if (model === "walletAddress") plugins.push(siwe({
    domain: "record-serial.test",
    async getNonce() { throw new Error("The Serial contract must not request a nonce"); },
    async verifyMessage() { throw new Error("The Serial contract must not verify a message"); },
  }));
  if (model !== "session") plugins.push({ id: "serial-primary-fields", schema: { [model]: { fields } } });
  const ctx = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://record-serial.test",
    secret: "record-serial-primary-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: "serial" } }, plugins,
    ...(model === "session" ? { session: { additionalFields: fields } } : {}),
    ...(model === "rateLimit" ? { rateLimit: { storage: "database" } } : {}),
    databaseHooks: { session: { update: {
      before(value) { events.push(["update-before", observeValue(value)]); },
      after(value) { events.push(["update-after", observeValue(value)]); },
    } } },
  }).$context;
  adapter = ctx.adapter;
  if (model === "session" || model === "walletAddress") await adapter.create({ model: "user", data: {
    name: "Record owner", email: "owner@record-serial.test", emailVerified: false,
    image: null, createdAt: date, updatedAt: date,
  } });
  return { adapter, internalAdapter: ctx.internalAdapter, memory, events };
}

function observedError(caught, operation) {
  if (caught instanceof assert.AssertionError) throw caught;
  assert.ok(caught instanceof Error);
  return { ...(operation === undefined ? {} : { operation }), name: caught.name, message: caught.message };
}

async function captureCreateOrder(model, slot, operation) {
  const { adapter, memory, events } = await context(model, slot, operation);
  const before = observeValue(memory);
  let result = null;
  let error = null;
  try {
    result = observeValue(await adapter.create({ model, data: data(model, "outer") }));
  } catch (caught) {
    error = observedError(caught);
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
    if (model === "session") {
      await step("update-by-token", () => internalAdapter.updateSession(first.token, { label: "updated", updatedAt: date }));
      await step("delete-by-token", () => internalAdapter.deleteSession(first.token));
    } else {
      const update = model === "rateLimit" ? { count: 2 } : { label: "updated" };
      await step("update-padded-id", () => adapter.update({ model, where, update }));
      await step("delete-padded-id", () => adapter.delete({ model, where }));
    }
    await step("read-deleted-id", () => adapter.findOne({ model, where }));
    await step("create-after-removal", () => adapter.create({ model, data: data(model, "third") }));
    await step("read-all", () => adapter.findMany({ model }));
  } catch (caught) {
    error = observedError(caught, pending);
  }
  return { model, operation: "lifecycle", before, events, operations, error, after: observeValue(memory) };
}

const sessionIdInputs = [
  ["omitted", {}], ["undefined", { id: undefined }], ["null", { id: null }],
  ["false", { id: false }], ["zero", { id: 0 }], ["negative-zero", { id: -0 }],
  ["nan", { id: NaN }], ["empty-string", { id: "" }], ["zero-string", { id: "0" }],
  ["whitespace", { id: " " }], ["empty-array", { id: [] }], ["null-array", { id: [null] }],
  ["padded-number", { id: "002" }], ["hex-number", { id: "0x2" }], ["number", { id: 2 }],
  ["true", { id: true }], ["number-array", { id: [2] }], ["invalid-string", { id: "not-a-number" }],
  ["object", { id: {} }], ["many-array", { id: [1, 2] }], ["infinity", { id: Infinity }],
  ["negative-infinity", { id: -Infinity }], ["infinity-string", { id: "Infinity" }], ["date", { id: date }],
];

async function captureSessionIdUpdate(name, input) {
  const { adapter, internalAdapter, memory, events } = await context("session", "before-label", "id-update");
  const seeded = observeValue(await adapter.create({ model: "session", data: data("session", "first") }));
  const seedEvents = events.splice(0);
  const before = observeValue(memory);
  const patch = { ...input, updatedAt: date };
  let result = null;
  let error = null;
  let reads = null;
  try {
    const updated = await internalAdapter.updateSession("serial-first", patch);
    result = observeValue(updated);
    reads = {
      byToken: observeValue(await adapter.findOne({ model: "session", where: [{ field: "token", value: "serial-first" }] })),
      byOriginalId: observeValue(await adapter.findOne({ model: "session", where: [{ field: "id", value: "001" }] })),
      byReturnedId: observeValue(await adapter.findOne({ model: "session", where: [{ field: "id", value: updated.id }] })),
    };
  } catch (caught) {
    error = observedError(caught);
  }
  return {
    model: "session", operation: "id-update", name, input: observeValue(patch), seeded, seedEvents,
    before, events, result, reads, error, after: observeValue(memory),
  };
}

export async function captureSessionJwkWalletRateLimitSerial() {
  const cases = [];
  for (const model of models) {
    if (model === "rateLimit") {
      // The builtin database RateLimit schema replaces plugin fields before adapter construction.
      cases.push(await captureCreateOrder(model, "before-label", "schema-shadowed"));
    } else {
      for (const slot of ["implicit", "before-label"]) {
        for (const operation of ["nested-success", "nested-failure", "outer-failure", "nested-delete"]) {
          cases.push(await captureCreateOrder(model, slot, operation));
        }
      }
    }
    cases.push(await captureLifecycle(model));
  }
  for (const [name, input] of sessionIdInputs) cases.push(await captureSessionIdUpdate(name, input));
  return { version, cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass a fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureSessionJwkWalletRateLimitSerial(), null, 2)}\n`);
}
