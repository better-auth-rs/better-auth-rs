import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureDeviceWhereGroup } from "./device-where-capture.mjs";

const version = "1.7.6";
const guards = ["id", "deviceCode", "clientId", "userId", "status"];

function scenarios() {
  return [false, true].flatMap(physical => {
    const base = {
      field: "ownerRef", stored: "owner", operator: "eq", sourceValue: "owner",
      physical, guardBindings: true, observeStorage: true,
    };
    const prefix = physical ? "physical-reference" : "logical-reference";
    return [
      { ...base, name: `${prefix}-success` },
      { ...base, name: `${prefix}-owner-mismatch`, sourceValue: undefined, value: "other-owner" },
      { ...base, name: `${prefix}-transaction-commit`, transaction: true },
      { ...base, name: `${prefix}-rollback`, transaction: true, rollback: true },
      ...guards.map(field => ({ ...base, name: `${prefix}-${field}-mismatch`, guardMismatch: field })),
    ];
  });
}

export async function captureDeviceWhereReferences(backend) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  const inputs = scenarios();
  assert.equal(inputs.length, 18);
  assert.equal(new Set(inputs.map(input => input.name)).size, inputs.length);
  const group = await captureDeviceWhereGroup(backend, false, inputs);
  assert.equal(group.serial, false);
  assert.equal(group.cases.length, inputs.length);
  for (const [index, input] of inputs.entries()) {
    const captured = group.cases[index];
    assert.equal(captured.name, input.name);
    assert.deepEqual(captured.where.map(condition => condition.field), [
      "id", input.physical ? "stored_ownerRef" : "ownerRef", "deviceCode", "clientId", "userId", "status",
    ]);
    assert.ok(captured.where.every(condition => condition.connector === undefined));
    assert.equal(captured.seeded.ownerRef, "ordinary-owner");
    assert.equal(captured.before[0].stored_ownerRef, "ordinary-owner");
    for (const model of ["user", "session", "account", "verification"]) {
      assert.deepEqual(captured.storage.after[model], captured.storage.before[model]);
    }
    assert.deepEqual(captured.storage.before.deviceCode, captured.before);
    assert.deepEqual(captured.storage.after.deviceCode, captured.after);
    const rejected = input.name.endsWith("-mismatch");
    if (input.rollback) {
      assert.equal(captured.result, null);
      assert.deepEqual(captured.error, { name: "Error", message: "Rollback device reference consumption" });
      assert.deepEqual(captured.rollback.result, captured.seeded);
      assert.deepEqual(captured.rollback.afterConsume, []);
      assert.equal(captured.rollback.originalError, true);
      assert.deepEqual(captured.storage.after, captured.storage.before);
    } else if (rejected) {
      assert.equal(captured.result, null);
      assert.equal(captured.error, null);
      assert.deepEqual(captured.events, []);
      assert.deepEqual(captured.storage.after, captured.storage.before);
    } else {
      assert.equal(captured.error, null);
      assert.deepEqual(captured.result, captured.seeded);
      assert.deepEqual(captured.after, []);
    }
    if (!rejected) assert.deepEqual(captured.events, captured.seedEvents.filter(event => event.phase === "output"));
  }
  return { version, backend, idGeneration: "default", groups: [group] };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceWhereReferences(backend), null, 2)}\n`);
}
