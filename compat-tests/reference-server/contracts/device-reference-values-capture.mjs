import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureDeviceWhereGroup, observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
const guards = ["id", "deviceCode", "clientId", "userId", "status"];

function scenarios(ownerRefType) {
  const base = { field: "ownerRef", stored: 1, serial: true, guardBindings: true, observeStorage: true };
  const prefix = `serial-${ownerRefType}-reference`;
  const ordinary = [
    { suffix: "eq-number", operator: "eq", value: 1, outcome: "consumed" },
    { suffix: "eq-date", operator: "eq", value: new Date(1), outcome: "date" },
    { suffix: "ne-date", operator: "ne", value: new Date(1), outcome: "date" },
    ...(ownerRefType === "json" ? [
      { suffix: "eq-object", operator: "eq", value: { value: 1 }, outcome: "json-object" },
      { suffix: "in-string-null", operator: "in", value: ["1", null], outcome: "json-array" },
    ] : [
      { suffix: "in-date", operator: "in", value: [new Date(1)], outcome: "consumed" },
      { suffix: "eq-invalid-date", operator: "eq", value: new Date(NaN), outcome: "invalid-date" },
    ]),
  ].map((input, index) => ({ ...base, ...input, name: `${prefix}-${input.suffix}`, physical: index % 2 === 1 }));
  return [
    ...ordinary,
    ...guards.map((field, index) => ({
      ...base, name: `${prefix}-${field}-mismatch`, operator: "eq", value: 1, guardMismatch: field,
      guardMismatchValue: field === "id" || field === "userId" ? "2" : `${field}-mismatch`,
      physical: index % 2 === 1, outcome: "preserved",
    })),
    { ...base, name: `${prefix}-transaction-commit`, operator: "eq", value: 1, transaction: true, outcome: "consumed" },
    { ...base, name: `${prefix}-transaction-rollback`, operator: "eq", value: 1, physical: true, transaction: true, rollback: true, outcome: "consumed" },
  ];
}

function expectedOutcome(backend, ownerRefType, input) {
  if (input.outcome === "date") {
    const equals = ownerRefType === "json" ? backend === "postgres" : backend !== "sqlite";
    return (input.operator === "eq" ? equals : !equals) ? "consumed" : "preserved";
  }
  if (input.outcome === "json-object") return backend === "postgres"
    ? { name: "error", message: "invalid input syntax for type integer: \"NaN\"" }
    : "preserved";
  if (input.outcome === "json-array") {
    if (backend === "memory") return { name: "Error", message: "Value must be an array" };
    return backend === "postgres" ? "consumed" : "preserved";
  }
  if (input.outcome === "invalid-date") {
    if (backend === "sqlite") return { name: "RangeError", message: "Invalid Date" };
    if (backend === "postgres") return { name: "error", message: "invalid input syntax for type integer: \"NaN\"" };
    if (backend === "mysql") return { name: "Error", message: "Unknown column 'NaN' in 'where clause'" };
    return "preserved";
  }
  return input.outcome;
}

export async function captureDeviceReferenceValues(backend, { diagnostics = [] } = {}) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  const groups = [];
  for (const ownerRefType of ["json", "date"]) {
    const inputs = scenarios(ownerRefType);
    assert.equal(inputs.length, 12);
    assert.equal(new Set(inputs.map(input => input.name)).size, inputs.length);
    assert.deepEqual(inputs.filter(input => input.guardMismatch).map(input => input.guardMismatch), guards);
    const diagnostic = { backend, ownerRefType, serial: true, inputs: observeValue(inputs) };
    diagnostics.push(diagnostic);
    const group = { ownerRefType, ...await captureDeviceWhereGroup(backend, true, inputs, { diagnostics, ownerRefType }) };
    diagnostic.observation = group;
    assert.equal(group.serial, true);
    assert.equal(group.cases.length, 12);
    for (const [index, input] of inputs.entries()) {
      const captured = group.cases[index];
      const outcome = expectedOutcome(backend, ownerRefType, input);
      const bindings = { id: "<device-id>", deviceCode: "ordinary-device", clientId: "ordinary-client", userId: "1", status: "approved" };
      if (input.guardMismatch) bindings[input.guardMismatch] = input.guardMismatchValue;
      assert.equal(captured.name, input.name);
      assert.equal(captured.transaction, Boolean(input.transaction));
      assert.deepEqual(captured.where, observeValue([
        { field: "id", value: bindings.id },
        { field: input.physical ? "stored_ownerRef" : "ownerRef", operator: input.operator, value: input.value },
        ...guards.slice(1).map(field => ({ field, value: bindings[field] })),
      ]));
      assert.equal(captured.seeded.ownerRef, "1");
      assert.equal(captured.before.length, 1);
      assert.equal(captured.before[0].stored_ownerRef, 1);
      assert.deepEqual(captured.seedEvents.filter(event => event.field === "ownerRef"), [
        { phase: "input", field: "ownerRef", value: 1 },
        { phase: "output", field: "ownerRef", value: 1 },
      ]);
      for (const snapshot of [captured.storage.before, captured.storage.after]) {
        assert.deepEqual(Object.keys(snapshot), ["user", "session", "account", "verification", "deviceCode"]);
      }
      for (const model of ["user", "session", "account", "verification"]) {
        assert.deepEqual(captured.storage.after[model], captured.storage.before[model]);
      }
      assert.deepEqual(captured.storage.before.deviceCode, captured.before);
      assert.deepEqual(captured.storage.after.deviceCode, captured.after);
      if (input.rollback) {
        assert.equal(captured.result, null);
        assert.deepEqual(captured.error, { name: "Error", message: "Rollback device reference consumption" });
        assert.deepEqual(captured.rollback.result, captured.seeded);
        assert.deepEqual(captured.rollback.afterConsume, []);
        assert.equal(captured.rollback.originalError, true);
        assert.deepEqual(captured.storage.after, captured.storage.before);
      } else if (outcome === "consumed") {
        assert.equal(captured.error, null);
        assert.deepEqual(captured.result, captured.seeded);
        assert.deepEqual(captured.after, []);
      } else {
        assert.equal(captured.result, null);
        assert.deepEqual(captured.error, outcome === "preserved" ? null : outcome);
        assert.deepEqual(captured.events, []);
        assert.deepEqual(captured.storage.after, captured.storage.before);
      }
      if (outcome === "consumed") assert.deepEqual(captured.events, captured.seedEvents.filter(event => event.phase === "output"));
    }
    groups.push(group);
  }
  return { version, backend, groups };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  const diagnostics = [];
  try {
    writeFileSync(output, `${JSON.stringify(await captureDeviceReferenceValues(backend, { diagnostics }), null, 2)}\n`);
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
