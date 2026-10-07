import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const timestamp = "2030-01-02T03:04:05.000Z";

function input(name) {
  const moment = new Date(name === "invalid-date-null" ? NaN : timestamp);
  const labels = name === "array-object-key-order" ? [{ a: 1, b: 2 }] : ["Alpha"];
  return {
    id: "owner", name: "Owner", email: "owner@memory-values.test", emailVerified: false,
    image: null, createdAt: new Date(timestamp), updatedAt: new Date(timestamp),
    moment, mirrorMoment: moment, labels, mirrorLabels: labels,
    quantity: name.startsWith("nonfinite-") ? NaN : 2,
  };
}

function patch(name) {
  switch (name) {
    case "same-date": return { moment: new Date(timestamp) };
    case "changed-date": return { moment: new Date("2031-01-02T03:04:05.000Z") };
    case "invalid-date-null": return { moment: null };
    case "nonfinite-infinity": return { quantity: Infinity };
    case "nonfinite-null": return { quantity: null };
    case "same-array": return { labels: ["Alpha"] };
    case "changed-array": return { labels: ["Beta"] };
    case "array-object-key-order": return { labels: [{ b: 2, a: 1 }] };
    case "rollback": return { labels: ["Uncommitted"] };
    default: return {};
  }
}

const identity = row => ({ datesAliased: row.moment === row.mirrorMoment, arraysAliased: row.labels === row.mirrorLabels });
const sameObjects = (left, right) => ({ date: left.moment === right.moment, array: left.labels === right.labels });

async function captureCase(name) {
  const db = { user: [], session: [], account: [], verification: [] };
  const events = [];
  const fields = Object.fromEntries(Object.entries({ moment: "date", mirrorMoment: "date", labels: "string[]", mirrorLabels: "string[]", quantity: "number" }).map(([field, type]) => [field, {
    type, required: false,
    transform: {
      input(value) { events.push({ phase: "input", field, value: observeValue(value) }); return value; },
      output(value) { events.push({ phase: "output", field, value: observeValue(value) }); return value; },
    },
  }]));
  const { adapter } = await betterAuth({
    database: memoryAdapter(db), baseURL: "http://memory-values.test",
    secret: "memory-transaction-values-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, user: { additionalFields: fields },
  }).$context;
  const seeded = await adapter.create({ model: "user", forceAllowId: true, data: input(name) });
  const seedEvents = events.splice(0);
  const before = observeValue(db.user);
  const where = [{ field: "id", value: "owner" }];
  const read = current => current.findOne({ model: "user", where });
  const observation = { name, seeded: observeValue(seeded), seedIdentity: identity(seeded), seedEvents, before };
  let result = null;
  let error = null;
  try {
    result = await adapter.transaction(async current => {
      const selected = await read(current);
      assert.ok(selected);
      observation.transactionIdentity = identity(selected);
      observation.transactionVersusSeed = sameObjects(selected, seeded);
      if (name === "nested") {
        observation.nested = await current.transaction(async nested => {
          const selectedNested = await read(nested);
          assert.ok(selectedNested);
          return { row: observeValue(selectedNested), identity: identity(selectedNested), versusParent: sameObjects(selectedNested, selected) };
        });
      }
      await adapter.update({ model: "user", where, update: { name: "Concurrent owner", updatedAt: new Date(timestamp) } });
      if (!['untouched', 'nested'].includes(name)) {
        await current.update({ model: "user", where, update: { ...patch(name), updatedAt: new Date(timestamp) } });
      }
      const final = await read(current);
      assert.ok(final);
      observation.transactionFinalIdentity = identity(final);
      if (name === "rollback") throw new Error("transaction-rollback");
      return observeValue(final);
    });
  } catch (caught) {
    if (caught instanceof assert.AssertionError) throw caught;
    assert.ok(caught instanceof Error);
    error = { name: caught.name, message: caught.message };
  }
  assert.equal(db.user.length, 1);
  observation.result = result;
  observation.error = error;
  observation.events = events;
  observation.after = observeValue(db.user);
  observation.afterIdentity = identity(db.user[0]);
  observation.afterVersusSeed = sameObjects(db.user[0], seeded);
  return observation;
}

export async function captureMemoryTransactionValues() {
  const cases = [];
  for (const name of ["untouched", "same-date", "changed-date", "invalid-date-null", "nonfinite-infinity", "nonfinite-null", "same-array", "changed-array", "array-object-key-order", "nested", "rollback"]) {
    cases.push(await captureCase(name));
  }
  return { version, cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass a fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureMemoryTransactionValues(), null, 2)}\n`);
}
