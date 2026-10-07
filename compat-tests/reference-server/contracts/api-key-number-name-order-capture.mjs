import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureApiKeyNumberName } from "./api-key-number-name-capture.mjs";

const plan = {
  input(value) {
    if (value === "Key 10") return 10;
    if (value === "Key 2") return 2;
    return value;
  },

  async run({ call, operations, required, ownerId }) {
    const fallback = required ? 7 : null;
    const created = [];
    for (const [operation, body, input, output] of [
      ["create-ten", { name: "Key 10" }, "Key 10", 10],
      ["create-two", { name: "Key 2" }, "Key 2", 2],
      ["create-default", {}, fallback, fallback],
    ]) {
      const result = await call(operation, "POST", "/api-key/create", body);
      operations.push(result.observation);
      assert.equal(result.observation.response?.status, 200);
      assert.equal(result.json.name, output);
      assert.equal(result.json.referenceId, ownerId);
      const stored = result.raw.find(row => row.id === result.json.id);
      assert.ok(stored);
      assert.equal(stored.name, output);
      assert.deepEqual(result.observation.events.filter(event => event.field === "name"), [
        { kind: "input", field: "name", value: input },
        { kind: "output", field: "name", value: output },
      ]);
      created.push({ id: result.json.id, name: output });
    }

    const get = await call("get", "GET", "/api-key/get", undefined, { id: created[0].id });
    operations.push(get.observation);
    assert.equal(get.observation.response?.status, 200);
    assert.equal(get.json.id, created[0].id);
    assert.equal(get.json.name, 10);

    const listed = await call("list", "GET", "/api-key/list");
    operations.push(listed.observation);
    assert.equal(listed.observation.response?.status, 200);
    assert.equal(listed.json.total, 3);
    const byId = (left, right) => left.id.localeCompare(right.id);
    assert.deepEqual(listed.json.apiKeys.map(({ id, name }) => ({ id, name })).sort(byId), [...created].sort(byId));

    for (const [direction, order] of [
      ["asc", required ? [1, 2, 0] : [2, 1, 0]],
      ["desc", required ? [0, 2, 1] : [0, 1, 2]],
    ]) {
      const result = await call(`list-name-${direction}`, "GET", "/api-key/list", undefined, {
        sortBy: "name", sortDirection: direction,
      });
      operations.push(result.observation);
      assert.equal(result.observation.response?.status, 200);
      assert.equal(result.json.total, 3);
      assert.deepEqual(result.json.apiKeys.map(({ id, name }) => ({ id, name })), order.map(index => created[index]));
      assert.deepEqual(result.observation.events.filter(event => event.field === "name"), order.map(index => ({
        kind: "output", field: "name", value: created[index].name,
      })));
    }

    const rejected = await call("reject-number-input", "POST", "/api-key/create", { name: 7 });
    operations.push(rejected.observation);
    assert.equal(rejected.observation.response?.status, 400);
    assert.deepEqual(rejected.observation.events, []);
    assert.equal(rejected.raw.length, 3);
  },
};

export async function captureApiKeyNumberNameOrder() {
  return captureApiKeyNumberName(plan);
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the new sorting fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureApiKeyNumberNameOrder(), null, 2)}\n`);
}
