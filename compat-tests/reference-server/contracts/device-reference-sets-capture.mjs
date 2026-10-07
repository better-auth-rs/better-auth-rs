import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureDeviceWhereGroup, observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
const guards = ["id", "deviceCode", "clientId", "userId", "status"];

function scenarios() {
  return [false, true].flatMap(serial => {
    const base = { field: "ownerRef", stored: "owner", serial, guardBindings: true, observeStorage: true };
    const prefix = serial ? "serial-reference" : "default-reference";
    const miss = serial ? "2" : "other-owner";
    const ordinary = [
      { suffix: "in-owner", operator: "in", sourceValue: "returned-array", outcome: "consumed" },
      { suffix: "in-miss", operator: "in", value: [miss], outcome: "preserved" },
      { suffix: "in-empty", operator: "in", value: [], outcome: "empty" },
      { suffix: "in-owner-null", operator: "in", sourceValue: "owner-array", outcome: "consumed" },
      { suffix: "not-in-owner", operator: "not_in", sourceValue: "returned-array", outcome: "preserved" },
      { suffix: "not-in-miss", operator: "not_in", value: [miss], outcome: "consumed" },
      { suffix: "not-in-empty", operator: "not_in", value: [], outcome: "empty" },
      { suffix: "not-in-miss-null", operator: "not_in", value: [miss, null], outcome: "null-candidate" },
    ].map((input, index) => ({ ...base, ...input, name: `${prefix}-${input.suffix}`, physical: index % 2 === 1 }));
    const rejected = serial ? [] : ["in", "not_in"].flatMap(operator => guards.map(field => ({
      ...base, operator, name: `${prefix}-${operator}-${field}-mismatch`, guardMismatch: field,
      ...(operator === "in" ? { sourceValue: "returned-array" } : { value: [miss] }),
      physical: operator === "not_in", outcome: "preserved",
    })));
    return [
      ...ordinary,
      ...rejected,
      { ...base, name: `${prefix}-in-transaction-commit`, operator: "in", sourceValue: "returned-array", transaction: true, outcome: "consumed" },
      { ...base, name: `${prefix}-not-in-transaction-rollback`, operator: "not_in", value: [miss], physical: true, transaction: true, rollback: true, outcome: "consumed" },
    ];
  });
}

function expectedOutcome(backend, input) {
  if (input.outcome === "empty") {
    if (backend === "postgres" || backend === "mysql") return "error";
    return input.operator === "in" ? "preserved" : "consumed";
  }
  if (input.outcome === "null-candidate") return input.serial || backend === "memory" ? "consumed" : "preserved";
  return input.outcome;
}

export async function captureDeviceReferenceSets(backend, { diagnostics = [] } = {}) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  const inputs = scenarios();
  assert.equal(inputs.length, 30);
  assert.equal(new Set(inputs.map(input => input.name)).size, inputs.length);
  for (const operator of ["in", "not_in"]) {
    assert.deepEqual(inputs.filter(input => input.operator === operator && input.guardMismatch).map(input => input.guardMismatch), guards);
  }
  const groups = [];
  for (const serial of [false, true]) {
    const selected = inputs.filter(input => input.serial === serial);
    const diagnostic = { backend, serial, inputs: observeValue(selected) };
    diagnostics.push(diagnostic);
    const group = await captureDeviceWhereGroup(backend, serial, selected, { diagnostics });
    diagnostic.observation = group;
    assert.equal(group.serial, serial);
    assert.equal(group.cases.length, serial ? 10 : 20);
    for (const [index, input] of selected.entries()) {
      const captured = group.cases[index];
      const outcome = expectedOutcome(backend, input);
      const owner = serial ? "1" : "ordinary-owner";
      const bindings = { id: "<device-id>", deviceCode: "ordinary-device", clientId: "ordinary-client", userId: owner, status: "approved" };
      if (input.guardMismatch) bindings[input.guardMismatch] = `${input.guardMismatch}-mismatch`;
      const value = input.sourceValue === "returned-array" ? [owner] : input.sourceValue === "owner-array" ? [owner, null] : input.value;
      assert.equal(captured.name, input.name);
      assert.equal(captured.transaction, Boolean(input.transaction));
      assert.deepEqual(captured.where, [
        { field: "id", value: bindings.id },
        { field: input.physical ? "stored_ownerRef" : "ownerRef", operator: input.operator, value },
        ...guards.slice(1).map(field => ({ field, value: bindings[field] })),
      ]);
      assert.equal(captured.seeded.ownerRef, owner);
      assert.equal(captured.before[0].stored_ownerRef, serial ? 1 : "ordinary-owner");
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
        if (outcome === "error") {
          assert.ok(captured.error);
          assert.equal(typeof captured.error.name, "string");
          assert.equal(typeof captured.error.message, "string");
          assert.ok(captured.error.message.length > 0);
        } else assert.equal(captured.error, null);
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
    writeFileSync(output, `${JSON.stringify(await captureDeviceReferenceSets(backend, { diagnostics }), null, 2)}\n`);
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
