import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { withFixture } from "./api-key-fields-capture.mjs";
import { observeValue } from "./device-where-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const createdAt = "2030-01-02T03:04:05.123Z";
const ordinaryUpdatedAt = "2030-01-02T04:04:05.123Z";
const times = [
  "2031-02-03T04:05:00.123Z",
  "2031-02-03T04:05:01.234567Z",
  "2031-02-03T04:05:02.345678Z",
  "2031-02-03T04:05:03.456789Z",
  "2031-02-03T04:05:04.567891Z",
  "2031-02-03T04:05:05.678912Z",
  "2031-02-03T04:05:06.789123Z",
];
const json = value => JSON.parse(JSON.stringify(value));
const iso = value => new Date(value).toISOString();
export const operationNames = [
  "create", "seed-dates", "refill-some-equal", "refill-some-miss", "refill-from-readback",
  "start-window-equal", "increment-window-equal-miss", "increment-window-after", "last-request", "updated-at",
];

async function captureBackend(backend, diagnostics) {
  return await withFixture(backend, async ({ adapter, reader, createInput, physicalRows, events }) => {
    const model = "apikey";
    const operations = [];
    let identity;
    const visible = row => {
      const value = json(row);
      return {
        ...value,
        id: value.id === identity ? "<api-key-id>" : value.id,
        createdAt: value.createdAt === createdAt ? "<created-at>" : value.createdAt,
        updatedAt: value.updatedAt === createdAt ? "<created-at>"
          : value.updatedAt === ordinaryUpdatedAt ? "<ordinary-updated-at>" : value.updatedAt,
      };
    };
    const stored = () => reader.findMany({ model, where: [{ field: "referenceId", value: "ordinary-owner" }] });
    for (const name of operationNames) {
      const diagnostic = { backend, name };
      diagnostics.push(diagnostic);
      diagnostic.before = observeValue(await stored());
      diagnostic.physicalBefore = observeValue(await physicalRows());
      const where = [{ field: "id", value: identity }];
      let method;
      let payload;
      let input;
      if (name === "create") {
        input = {};
        method = "create";
        payload = { model, data: createInput() };
      } else if (name === "seed-dates") {
        input = { lastRefillAt: times[0], lastRequest: times[0] };
        method = "update";
        payload = { model, where, update: {
          lastRefillAt: new Date(input.lastRefillAt), lastRequest: new Date(input.lastRequest), updatedAt: new Date(ordinaryUpdatedAt),
        } };
      } else if (name.startsWith("refill-")) {
        let previous;
        if (name === "refill-from-readback") {
          const readback = await reader.findOne({ model, where });
          diagnostic.readback = observeValue(readback);
          previous = readback.lastRefillAt;
          input = { previous: previous.toISOString(), previousSource: "reader-findOne", remaining: 6, at: times[2] };
        } else {
          input = name === "refill-some-equal"
            ? { previous: times[0], previousSource: "literal", remaining: 8, at: times[1] }
            : { previous: "2031-02-03T04:05:00.122Z", previousSource: "literal", remaining: 7, at: times[2] };
          previous = new Date(input.previous);
        }
        method = "incrementOne";
        payload = { model, where: [...where, { field: "lastRefillAt", value: previous }], increment: {},
          set: { remaining: input.remaining, lastRefillAt: new Date(input.at) } };
      } else if (name === "start-window-equal") {
        input = { previousBefore: times[0], at: times[3] };
        method = "incrementOne";
        payload = { model, where: [...where, { field: "lastRequest", operator: "lte", value: new Date(input.previousBefore) }],
          increment: {}, set: { requestCount: 1, lastRequest: new Date(input.at) } };
      } else if (name.startsWith("increment-window-")) {
        input = { previousAfter: name === "increment-window-equal-miss" ? iso(times[3]) : times[0], maximum: 3, at: times[4] };
        method = "incrementOne";
        payload = { model, where: [...where,
          { field: "lastRequest", operator: "gt", value: new Date(input.previousAfter) },
          { field: "requestCount", operator: "lt", value: input.maximum },
        ], increment: { requestCount: 1 }, set: { lastRequest: new Date(input.at) } };
      } else {
        input = { at: times[name === "last-request" ? 5 : 6] };
        method = "update";
        payload = { model, where, update: { [name === "last-request" ? "lastRequest" : "updatedAt"]: new Date(input.at) } };
      }
      diagnostic.input = json(input);
      diagnostic.method = method;
      diagnostic.payload = observeValue(payload);
      let result;
      try {
        result = await adapter[method](payload);
      } catch (error) {
        diagnostic.error = { name: error.name, message: error.message };
        diagnostic.events = observeValue(events.splice(0));
        diagnostic.physicalAfter = observeValue(await physicalRows());
        throw error;
      }
      diagnostic.result = observeValue(result);
      diagnostic.events = observeValue(events.splice(0));
      if (name === "create") identity = result.id;
      const rows = result === null ? [] : [result];
      const normalizedResult = rows.map(visible);
      const persisted = await stored();
      diagnostic.stored = observeValue(persisted);
      diagnostic.physicalAfter = observeValue(await physicalRows());
      operations.push({ name, input, events: diagnostic.events, result: normalizedResult, stored: persisted.map(visible) });
    }
    return { backend, operations };
  });
}

export async function captureApiKeyDateUsage({ diagnostics = [], backends = ["memory", "sqlite"] } = {}) {
  const observed = [];
  for (const backend of backends) observed.push(await captureBackend(backend, diagnostics));
  return { version, backends: observed };
}

export function assertApiKeyDateUsage(observed, backends = ["memory", "sqlite"]) {
  assert.equal(observed.version, "1.7.6");
  assert.deepEqual(observed.backends.map(({ backend }) => backend), backends);
  for (const { backend, operations } of observed.backends) {
    assert.deepEqual(operations.map(({ name }) => name), operationNames);
    let before = [];
    for (const operation of operations) {
      const { name, input, result, stored, events } = operation;
      const missed = name.endsWith("-miss") || backend === "memory" && name === "refill-some-equal";
      assert.equal(result.length, missed ? 0 : 1, `${backend}/${name}`);
      assert.equal(stored.length, 1);
      if (missed) {
        assert.deepEqual(stored, before);
        assert.ok(events.every(event => event[0] !== "output"));
      } else {
        assert.equal(result[0].id, "<api-key-id>");
        assert.equal(result[0].createdAt, "<created-at>");
        assert.deepEqual(result[0], { ...stored[0], label: `${stored[0].label}:out` });
      }
      const row = stored[0];
      assert.equal(row.updatedAt, name === "create" ? "<created-at>"
        : name === "updated-at" ? iso(times[6]) : "<ordinary-updated-at>");
      if (name === "seed-dates") {
        assert.equal(row.lastRefillAt, times[0]);
        assert.equal(row.lastRequest, times[0]);
      }
      if (name.startsWith("refill-") && !missed) {
        assert.equal(row.lastRefillAt, iso(input.at));
        assert.equal(row.remaining, input.remaining);
      }
      if (name === "refill-from-readback") assert.equal(input.previous, before[0].lastRefillAt);
      if (name === "start-window-equal" || name === "increment-window-after" || name === "last-request") {
        assert.equal(row.lastRequest, iso(input.at));
        assert.equal(row.requestCount, name === "start-window-equal" ? 1 : 2);
      }
      before = stored;
    }
  }
}

if (import.meta.main) {
  const [first, second] = process.argv.slice(2);
  const output = second ?? first;
  const backends = second === undefined ? ["memory", "sqlite"] : [first];
  assert.ok(output, "Pass the API Key Date usage fixture output path");
  const diagnostics = [];
  try {
    const observed = await captureApiKeyDateUsage({ diagnostics, backends });
    writeFileSync(`${output}.raw.json`, `${JSON.stringify(observed, null, 2)}\n`);
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
    assertApiKeyDateUsage(observed, backends);
    writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
