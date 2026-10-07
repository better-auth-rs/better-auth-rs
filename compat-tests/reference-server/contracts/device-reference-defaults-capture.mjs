import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureDeviceWhereGroup, observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
const models = ["user", "session", "account", "verification", "deviceCode"];

function scenarios(ownerRefType) {
  const base = {
    field: "ownerRef", stored: ownerRefType === "json" ? "owner" : 1,
    serial: false, guardBindings: true, observeStorage: true,
  };
  const inputs = ownerRefType === "json" ? [
    { suffix: "eq-owner", operator: "eq", sourceValue: "owner" },
    { suffix: "eq-object", operator: "eq", value: { value: 1 } },
    { suffix: "in-owner-null", operator: "in", sourceValue: "owner-array" },
    { suffix: "in-non-array", operator: "in", value: "ordinary-owner" },
  ] : [
    { suffix: "eq-number", operator: "eq", value: 1 },
    { suffix: "eq-date", operator: "eq", value: new Date(1) },
    { suffix: "in-date", operator: "in", value: [new Date(1)] },
    { suffix: "eq-invalid-date", operator: "eq", value: new Date(NaN) },
    { suffix: "in-non-array", operator: "in", value: 1 },
  ];
  return inputs.map((input, index) => ({
    ...base, ...input, name: `default-${ownerRefType}-reference-${input.suffix}`, physical: index % 2 === 1,
  }));
}

function expectedOutcome(backend, input) {
  switch (input.suffix) {
    case "in-non-array":
      return { name: "BetterAuthError", message: "Value must be an array" };
    case "eq-owner":
    case "eq-number":
      return "consumed";
    case "eq-object":
    case "eq-date":
      return "preserved";
    case "in-owner-null":
      if (backend === "memory") return { name: "Error", message: "Value must be an array" };
      return backend === "postgres" ? "consumed" : "preserved";
    case "in-date":
      return backend === "sqlite"
        ? { name: "TypeError", message: "Binding expected string, TypedArray, boolean, number, bigint or null" }
        : "preserved";
    case "eq-invalid-date":
      return backend === "sqlite" ? { name: "RangeError", message: "Invalid Date" } : "preserved";
    default:
      assert.fail(`Unknown captured operand: ${input.suffix}`);
  }
}

export async function captureDeviceReferenceDefaults(backend, { diagnostics = [] } = {}) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  const groups = [];
  for (const ownerRefType of ["json", "date"]) {
    // Date strings normalize before input callbacks; a numeric seed preserves a valid text ID reference.
    const ownerId = ownerRefType === "date" ? "1" : "ordinary-owner";
    const inputs = scenarios(ownerRefType);
    assert.equal(inputs.length, ownerRefType === "json" ? 4 : 5);
    assert.equal(new Set(inputs.map(input => input.name)).size, inputs.length);
    const diagnostic = { backend, ownerRefType, ownerId, serial: false, inputs: observeValue(inputs) };
    diagnostics.push(diagnostic);
    const group = {
      ownerRefType, ownerId,
      ...await captureDeviceWhereGroup(backend, false, inputs, { diagnostics, ownerRefType, ownerId }),
    };
    diagnostic.observation = group;
    assert.equal(group.serial, false);
    assert.equal(group.cases.length, inputs.length);
    for (const [index, input] of inputs.entries()) {
      const captured = group.cases[index];
      const value = input.sourceValue === "owner" ? ownerId
        : input.sourceValue === "owner-array" ? [ownerId, null] : input.value;
      assert.deepEqual(Object.keys(captured), [
        "name", "transaction", "where", "seeded", "seedEvents", "before", "events", "result", "error", "after", "storage",
      ]);
      assert.equal(captured.name, input.name);
      assert.equal(captured.transaction, false);
      assert.deepEqual(captured.where, observeValue([
        { field: "id", value: "<device-id>" },
        { field: input.physical ? "stored_ownerRef" : "ownerRef", operator: input.operator, value },
        { field: "deviceCode", value: "ordinary-device" },
        { field: "clientId", value: "ordinary-client" },
        { field: "userId", value: ownerId },
        { field: "status", value: "approved" },
      ]));
      assert.equal(captured.seeded.ownerRef, ownerId);
      assert.equal(captured.before.length, 1);
      assert.ok(Object.hasOwn(captured.before[0], "stored_ownerRef"));
      const storedValue = ownerRefType === "date" && backend === "memory" ? 1 : ownerId;
      assert.equal(captured.before[0].stored_ownerRef, storedValue);
      assert.deepEqual(captured.seedEvents.filter(event => event.field === "ownerRef" && event.phase === "input"), [
        { phase: "input", field: "ownerRef", value: ownerRefType === "json" ? ownerId : 1 },
      ]);
      assert.equal(captured.seedEvents.filter(event => event.field === "ownerRef" && event.phase === "output").length, 1);
      assert.deepEqual(captured.seedEvents.filter(event => event.field === "ownerRef"), [
        { phase: "input", field: "ownerRef", value: ownerRefType === "json" ? ownerId : 1 },
        { phase: "output", field: "ownerRef", value: storedValue },
      ]);
      for (const snapshot of [captured.storage.before, captured.storage.after]) {
        assert.deepEqual(Object.keys(snapshot), models);
        for (const model of models) assert.ok(Array.isArray(snapshot[model]));
      }
      for (const model of models.slice(0, -1)) {
        assert.deepEqual(captured.storage.after[model], captured.storage.before[model]);
      }
      assert.deepEqual(captured.storage.before.deviceCode, captured.before);
      assert.deepEqual(captured.storage.after.deviceCode, captured.after);
      const outcome = expectedOutcome(backend, input);
      if (outcome === "consumed") {
        assert.equal(captured.error, null);
        assert.deepEqual(captured.result, captured.seeded);
        assert.deepEqual(captured.after, []);
        assert.deepEqual(captured.events, captured.seedEvents.filter(event => event.phase === "output"));
      } else {
        assert.equal(captured.result, null);
        assert.deepEqual(captured.error, outcome === "preserved" ? null : outcome);
        assert.deepEqual(captured.events, []);
        assert.deepEqual(captured.storage.after, captured.storage.before);
      }
    }
    groups.push(group);
  }
  return { version, backend, idGeneration: "default", groups };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  const diagnostics = [];
  try {
    writeFileSync(output, `${JSON.stringify(await captureDeviceReferenceDefaults(backend, { diagnostics }), null, 2)}\n`);
  } catch (error) {
    diagnostics.push({ stage: "capture-error", error: {
      name: error.name, message: error.message,
      ownProperties: observeValue(Object.fromEntries(Object.getOwnPropertyNames(error).map(name => [name, error[name]]))),
    } });
    throw error;
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
