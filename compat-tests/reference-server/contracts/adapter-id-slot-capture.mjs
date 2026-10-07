import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { jwt, siwe } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const date = new Date("2030-01-02T03:04:05.000Z");
const changedAt = new Date("2031-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const models = ["user", "session", "jwks", "walletAddress"];
const slots = ["before-label", "after-label"];
const operations = ["nested-create", "live-output-id-write"];

function userData(label) {
  return {
    name: `Record ${label}`, email: `${label}@adapter-id-slot.test`, emailVerified: false,
    image: null, createdAt: date, updatedAt: date,
  };
}

function data(model, label, userId) {
  switch (model) {
    case "user": return { ...userData(label), label };
    case "session": return {
      token: `slot-${label}`, userId, expiresAt, createdAt: date, updatedAt: date,
      ipAddress: null, userAgent: null, label,
    };
    case "jwks": return {
      publicKey: `public-${label}`, privateKey: `private-${label}`, createdAt: date,
      expiresAt: null, alg: "EdDSA", crv: null, label,
    };
    case "walletAddress": return {
      userId, address: `slot-${label}`, chainId: 1, isPrimary: false, createdAt: date, label,
    };
    default: throw new Error(`Unknown ID slot model: ${model}`);
  }
}

function options(memory, model, fields, generateId) {
  const plugins = [];
  if (model === "jwks") plugins.push(jwt());
  if (model === "walletAddress") plugins.push(siwe({
    domain: "adapter-id-slot.test",
    async getNonce() { throw new Error("The ID slot contract must not request a nonce"); },
    async verifyMessage() { throw new Error("The ID slot contract must not verify a message"); },
  }));
  if (model !== "user" && model !== "session") {
    plugins.push({ id: "adapter-id-slot-fields", schema: { [model]: { fields } } });
  }
  return {
    database: memoryAdapter(memory), baseURL: "http://adapter-id-slot.test",
    secret: "adapter-id-slot-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId } }, plugins,
    ...(model === "user" ? { user: { additionalFields: fields } } : {}),
    ...(model === "session" ? { session: { additionalFields: fields } } : {}),
  };
}

function observedError(caught, phase) {
  if (caught instanceof assert.AssertionError) throw caught;
  assert.ok(caught instanceof Error);
  return { phase, name: caught.name, message: caught.message };
}

async function captureCase(model, slot, operation) {
  const memory = { user: [], account: [], session: [], verification: [], jwks: [], walletAddress: [] };
  const events = [];
  const setup = [];
  const serial = operation === "live-output-id-write";
  let sequence = 0;
  const generateId = serial ? "serial" : ({ model: generatedModel }) => {
    const id = `${generatedModel}-generated-${++sequence}`;
    events.push(["generateId", { model: generatedModel }, id, observeValue(memory)]);
    return id;
  };
  let reader;
  let writer;
  let userId;
  let selectedId;
  let phase = "initialize-writer";
  const id = { type: "string", transform: {
    input(value) {
      events.push(["input", "id", observeValue(value)]);
      throw new Error("configured-id-input-called");
    },
    output(value) {
      events.push(["output", "id", observeValue(value)]);
      throw new Error("configured-id-output-called");
    },
  } };
  const fields = {};
  if (slot === "before-label") fields.id = id;
  fields.label = { type: "string", transform: {
    async input(value) {
      events.push(["input", "label", observeValue(value)]);
      if (operation === "nested-create" && value === "outer") {
        const input = { model, data: data(model, "inner", userId) };
        events.push(["nested-create", observeValue(input), observeValue(memory)]);
        phase = "nested-create";
        const inner = await reader.adapter.create(input);
        events.push(["nested-created", observeValue(inner), observeValue(memory)]);
        phase = "outer-create";
      }
      return value;
    },
    async output(value) {
      events.push(["output", "label", observeValue(value)]);
      if (operation === "live-output-id-write") {
        const input = {
          model, where: [{ field: "id", value: selectedId }], update: {
            id: "00101",
            ...(model === "user" || model === "session" ? { updatedAt: changedAt } : {}),
          },
        };
        events.push(["writer-update", observeValue(input), observeValue(memory)]);
        phase = "writer-update";
        const updated = await writer.adapter.update(input);
        assert.ok(updated, "The writer must update the row selected by the reader");
        events.push(["writer-updated", observeValue(updated), observeValue(memory)]);
        phase = "reader-output";
        return `${value}:out`;
      }
      return value;
    },
  } };
  if (slot === "after-label") fields.id = id;

  let seedEvents = [];
  let before = observeValue(memory);
  let input = null;
  let result = null;
  let error = null;
  try {
    writer = await betterAuth(options(memory, model, {
      id: { type: "string" }, label: { type: "string" },
    }, generateId)).$context;
    if (model === "session" || model === "walletAddress") {
      phase = "seed-owner";
      const request = {
        model: "user", forceAllowId: true,
        data: { id: serial ? "001" : "ordinary-owner", ...userData("owner") },
      };
      const step = { input: observeValue(request), before: observeValue(memory), result: null, after: null };
      setup.push(step);
      const owner = await writer.adapter.create(request);
      step.result = observeValue(owner);
      step.after = observeValue(memory);
      userId = owner.id;
    }
    phase = "initialize-reader";
    reader = await betterAuth(options(memory, model, fields, generateId)).$context;
    if (serial) {
      phase = "seed-selected-row";
      const request = { model, data: data(model, "selected", userId) };
      const step = { input: observeValue(request), before: observeValue(memory), result: null, after: null };
      setup.push(step);
      const seeded = await writer.adapter.create(request);
      step.result = observeValue(seeded);
      step.after = observeValue(memory);
      assert.equal(seeded.id, "1");
      selectedId = seeded.id;
    }
    seedEvents = events.splice(0);
    before = observeValue(memory);
    if (serial) {
      phase = "reader-find";
      const request = { model, where: [{ field: "id", value: selectedId }] };
      input = observeValue(request);
      result = observeValue(await reader.adapter.findOne(request));
    } else {
      phase = "outer-create";
      const request = { model, data: data(model, "outer", userId) };
      input = observeValue(request);
      result = observeValue(await reader.adapter.create(request));
    }
  } catch (caught) {
    error = observedError(caught, phase);
  }
  return {
    model, slot, operation, idGeneration: serial ? "serial" : "custom",
    setup, seedEvents, before, input, events, result, error, after: observeValue(memory),
  };
}

async function captureCreateAlias(model, slot, serial) {
  const memory = { user: [], account: [], session: [], verification: [], jwks: [], walletAddress: [] };
  const events = [];
  const generateId = serial ? "serial" : ({ model: generatedModel }) => {
    events.push(["generateId", { model: generatedModel }, "G", observeValue(memory)]);
    return "G";
  };
  const fields = {};
  const id = { type: "string", transform: {
    input() { throw new Error("configured-id-input-called"); },
    output() { throw new Error("configured-id-output-called"); },
  } };
  if (slot === "before-alias") fields.id = id;
  fields.aliasId = { type: "string", fieldName: "id", transform: {
    input(value) {
      events.push(["input", "aliasId", observeValue(value)]);
      return value;
    },
    output(value) {
      events.push(["output", "aliasId", observeValue(value)]);
      return value;
    },
  } };
  if (slot === "after-alias") fields.id = id;
  const context = await betterAuth(options(memory, model, fields, generateId)).$context;
  const values = data(model, "alias", serial ? "001" : "owner");
  delete values.label;
  if (model === "session") {
    values.ipAddress = "";
    values.userAgent = "";
  }
  values.aliasId = "A";
  const request = { model, data: values };
  const input = observeValue(request);
  const before = observeValue(memory);
  let result = null;
  let error = null;
  try {
    result = observeValue(await context.adapter.create(request));
  } catch (caught) {
    error = observedError(caught, "create");
  }
  return {
    model, slot, operation: "create-id-alias", idGeneration: serial ? "serial" : "custom",
    setup: [], seedEvents: [], before, input, events, result, error, after: observeValue(memory),
  };
}

async function captureUndefinedIdAliasUpdate() {
  const memory = { user: [], account: [], session: [], verification: [], jwks: [], walletAddress: [] };
  const events = [];
  const context = await betterAuth(options(memory, "session", {
    aliasId: {
      type: "string", fieldName: "id", references: { model: "session", field: "id" },
      transform: {
        input(value) {
          events.push(["input", "aliasId", observeValue(value)]);
          return undefined;
        },
        output(value) {
          events.push(["output", "aliasId", observeValue(value)]);
          return value;
        },
      },
    },
  }, "serial")).$context;
  const values = data("session", "undefined-alias", "001");
  delete values.label;
  values.ipAddress = "";
  values.userAgent = "";
  values.aliasId = "seed";
  const create = { model: "session", data: values };
  const step = { input: observeValue(create), before: observeValue(memory), result: null, after: null };
  let seedEvents = [];
  let before = observeValue(memory);
  let input = null;
  let result = null;
  let error = null;
  let phase = "create";
  try {
    step.result = observeValue(await context.adapter.create(create));
    step.after = observeValue(memory);
    seedEvents = events.splice(0);
    before = observeValue(memory);
    phase = "update";
    const update = {
      model: "session", where: [{ field: "token", value: values.token }],
      update: { aliasId: "clear", updatedAt: changedAt },
    };
    input = observeValue(update);
    result = observeValue(await context.adapter.update(update));
  } catch (caught) {
    error = observedError(caught, phase);
  }
  return {
    model: "session", slot: "after-alias", operation: "update-undefined-id-alias", idGeneration: "serial",
    setup: [step], seedEvents, before, input, events, result, error, after: observeValue(memory),
  };
}

export async function captureAdapterIdSlots() {
  const cases = [];
  for (const model of models) {
    for (const slot of slots) {
      for (const operation of operations) cases.push(await captureCase(model, slot, operation));
    }
  }
  assert.equal(cases.length, 16);
  for (const model of ["user", "session"]) {
    for (const slot of ["before-alias", "after-alias"]) {
      for (const serial of [false, true]) cases.push(await captureCreateAlias(model, slot, serial));
    }
  }
  assert.equal(cases.length, 24);
  cases.push(await captureUndefinedIdAliasUpdate());
  assert.equal(cases.length, 25);
  return { version, backend: "memory", cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass a fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureAdapterIdSlots(), null, 2)}\n`);
}
