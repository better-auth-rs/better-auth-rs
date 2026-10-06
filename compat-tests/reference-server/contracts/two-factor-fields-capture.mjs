import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";
import {
  recordTwoFactorFailure,
  resetTwoFactorFailures,
} from "../node_modules/better-auth/dist/plugins/two-factor/verify-two-factor.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const base = {
  baseURL: "http://two-factor-fields.test",
  secret: "ordinary-two-factor-fields-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};
const initialActivation = "2029-01-02T03:04:05.000Z";
const updatedActivation = "2029-02-03T04:05:06.789Z";
const lockDeadline = "2030-01-02T03:04:05.123Z";
const json = value => JSON.parse(JSON.stringify(value));
const callbackValue = value => value === undefined ? { type: "undefined" } : json(value);
const nativeFields = ["id", "secret", "backupCodes", "userId", "verified", "failedVerificationCount", "lockedUntil"];

const policies = () => ({
  label: { type: "string", fieldName: "stored_label", required: false, defaultValue: " Default " },
  activatedAt: { type: "date", fieldName: "stored_activation", required: false },
  details: { type: "json", fieldName: "stored_details", required: false },
  revision: { type: "number", fieldName: "stored_revision", required: false, defaultValue: 1.5 },
});
const plugin = fields => ({
  id: "ordinary-two-factor-additional-fields",
  schema: { twoFactor: { fields } },
});
const factorInput = userId => ({
  userId, secret: "ordinary-encrypted-secret", backupCodes: "ordinary-encrypted-codes",
  verified: false, lockedUntil: null,
  activatedAt: initialActivation, details: { channel: "ordinary", enabled: true },
});
const factorUpdate = () => ({
  verified: true, label: " Changed ", activatedAt: updatedActivation,
  details: { channel: "updated", enabled: false },
});

function visible(row) {
  if (row === null) return null;
  assert.deepEqual(Object.keys(row).sort(), [...nativeFields, ...Object.keys(policies())].sort());
  assert.equal(typeof row.id, "string");
  assert.equal(typeof row.userId, "string");
  assert.ok(row.id.length > 0);
  assert.ok(row.userId.length > 0);
  return json({ ...row, id: "<two-factor-id>", userId: "<owner-id>" });
}

async function withFixture(backend, run) {
  const memory = { user: [], session: [], account: [], verification: [], twoFactor: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  try {
    const database = sqlite ?? memoryAdapter(memory);
    const factorPlugin = () => twoFactor({ accountLockout: { maxFailedAttempts: 2, durationSeconds: 900 } });
    const options = { ...base, database, plugins: [factorPlugin(), plugin(policies())] };
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const reader = (await betterAuth(options).$context).adapter;
    const owner = await reader.create({ model: "user", data: {
      name: "TwoFactor field owner", email: "owner@two-factor-fields.test", emailVerified: false,
      createdAt: new Date("2030-01-01T00:00:00.000Z"), updatedAt: new Date("2030-01-01T00:00:00.000Z"),
    } });
    const events = [];
    const errors = {
      input: new Error("ordinary TwoFactor input error"),
      output: new Error("ordinary TwoFactor output error"),
    };
    let failure;
    const fields = Object.fromEntries(Object.entries(policies()).map(([name, field]) => [name, {
      ...field,
      ...(name === "revision" ? {
        defaultValue() { events.push(["default", name]); return 1.5; },
        onUpdate() { events.push(["onUpdate", name]); return 2.5; },
      } : {}),
      transform: {
        input(value) {
          events.push(["input", name, callbackValue(value)]);
          if (name === "revision" && failure === "input") throw errors.input;
          return name === "label" && typeof value === "string" ? value.trim() : value;
        },
        output(value) {
          events.push(["output", name, callbackValue(value)]);
          if (name === "label" && failure === "output") throw errors.output;
          return name === "label" && typeof value === "string" ? `${value}:out` : value;
        },
      },
    }]));
    const context = await betterAuth({ ...base, database, plugins: [factorPlugin(), plugin(fields)] }).$context;
    const stored = async () => visible(await reader.findOne({
      model: "twoFactor", where: [{ field: "userId", value: owner.id }],
    }));
    events.length = 0;
    return await run({
      context, adapter: context.adapter, ownerId: owner.id, events, errors, stored,
      setFailure(value) { failure = value; },
    });
  } finally {
    sqlite?.close();
  }
}

async function captureOperations(backend) {
  return await withFixture(backend, async ({ context, adapter, ownerId, events, stored }) => {
    const operations = [];
    const observe = async (name, operation, project = value => value) => {
      assert.equal(events.length, 0);
      const result = project(await operation());
      operations.push({ name, events: events.splice(0), result, stored: await stored() });
      return result;
    };
    let id;
    await observe("create", async () => {
      const row = await adapter.create({ model: "twoFactor", data: factorInput(ownerId) });
      id = row.id;
      return row;
    }, visible);
    const where = [{ field: "id", value: id }];
    await observe("read", () => adapter.findOne({
      model: "twoFactor", where: [{ field: "userId", value: ownerId }],
    }), visible);
    await observe("update", () => adapter.update({ model: "twoFactor", where, update: factorUpdate() }), visible);
    await observe("update-backup-codes", () => adapter.update({
      model: "twoFactor", where: [{ field: "userId", value: ownerId }],
      update: { backupCodes: "ordinary-updated-codes" },
    }), visible);
    const exchange = (previous, replacement) => adapter.incrementOne({
      model: "twoFactor", where: [...where, { field: "backupCodes", value: previous }],
      increment: {}, set: { backupCodes: replacement },
    });
    await observe("cas-success", () => exchange("ordinary-updated-codes", "ordinary-cas-codes"), row => row !== null);
    await observe("cas-mismatch", () => exchange("ordinary-updated-codes", "must-not-replace"), row => row !== null);
    const recordFailure = async () => {
      const originalNow = Date.now;
      try {
        Date.now = () => Date.parse(lockDeadline) - 900_000;
        await recordTwoFactorFailure({ context }, "twoFactor", { id });
      } finally {
        Date.now = originalNow;
      }
      return null;
    };
    await observe("failure-increment", recordFailure);
    await observe("failure-lock", recordFailure);
    const guardedReset = async before => {
      await adapter.incrementOne({
        model: "twoFactor", where: [...where, { field: "lockedUntil", operator: "lte", value: new Date(before) }],
        increment: {}, set: { failedVerificationCount: 0, lockedUntil: null },
      });
      return null;
    };
    await observe("reset-guard-mismatch", () => guardedReset("2030-01-01T00:00:00.000Z"));
    await observe("reset-guard-success", () => guardedReset("2030-01-03T00:00:00.000Z"));
    await observe("failure-increment-after-reset", recordFailure);
    await observe("reset-unconditional", async () => {
      await resetTwoFactorFailures({ context }, "twoFactor", { id });
      return null;
    });
    assert.equal(operations[4].result, true);
    assert.equal(operations[5].result, false);
    assert.deepEqual(operations[5].stored, operations[4].stored);
    assert.equal(operations[6].stored.failedVerificationCount, 1);
    assert.equal(operations[6].stored.lockedUntil, null);
    assert.equal(operations[7].stored.failedVerificationCount, 2);
    assert.equal(operations[7].stored.lockedUntil, lockDeadline);
    assert.deepEqual(operations[8].stored, operations[7].stored);
    assert.equal(operations[9].stored.failedVerificationCount, 0);
    assert.equal(operations[9].stored.lockedUntil, null);
    assert.equal(operations[10].stored.failedVerificationCount, 1);
    assert.equal(operations[11].stored.failedVerificationCount, 0);
    for (const index of [6, 10]) {
      assert.equal(operations[index].events.some(([phase]) => phase === "onUpdate"), false);
      assert.equal(operations[index].events.filter(([phase]) => phase === "output").length, 4);
    }
    for (const index of [5, 8]) {
      assert.equal(operations[index].events.some(([phase]) => phase === "onUpdate"), true);
      assert.equal(operations[index].events.some(([phase]) => phase === "output"), false);
    }
    return operations;
  });
}

async function captureFailure(backend, operation, phase) {
  return await withFixture(backend, async ({ adapter, ownerId, events, errors, stored, setFailure }) => {
    let id;
    if (operation !== "create") {
      const seeded = await adapter.create({ model: "twoFactor", data: factorInput(ownerId) });
      id = seeded.id;
    }
    const before = await stored();
    events.length = 0;
    setFailure(phase);
    let sameError = false;
    try {
      if (operation === "create") {
        await adapter.create({ model: "twoFactor", data: factorInput(ownerId) });
      } else if (operation === "update") {
        await adapter.update({ model: "twoFactor", where: [{ field: "id", value: id }], update: factorUpdate() });
      } else {
        await adapter.incrementOne({
          model: "twoFactor", where: [
            { field: "id", value: id }, { field: "backupCodes", value: "ordinary-encrypted-codes" },
          ],
          increment: {}, set: { backupCodes: "ordinary-error-cas-codes" },
        });
      }
    } catch (error) {
      if (error !== errors[phase]) throw error;
      sameError = true;
    }
    assert.equal(sameError, true, "The configured field callback must reject the operation");
    setFailure(undefined);
    const persisted = await stored();
    if (phase === "input") assert.deepEqual(persisted, before);
    else {
      assert.notEqual(persisted, null);
      if (operation === "create") assert.equal(persisted.label, "Default");
      else if (operation === "update") {
        assert.equal(persisted.label, "Changed");
        assert.equal(persisted.verified, true);
      } else assert.equal(persisted.backupCodes, "ordinary-error-cas-codes");
    }
    return {
      name: `${operation}-${phase}-error`, events: events.splice(0),
      result: { sameError, message: errors[phase].message }, stored: persisted,
    };
  });
}

export async function captureTwoFactorFields() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const operations = await captureOperations(backend);
    const failures = [];
    for (const operation of ["create", "update", "cas"]) {
      for (const phase of ["input", "output"]) failures.push(await captureFailure(backend, operation, phase));
    }
    backends.push({ backend, operations, failures });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureTwoFactorFields(), null, 2)}\n`);
}
