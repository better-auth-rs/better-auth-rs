import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key", "@better-auth/memory-adapter"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

const table = "memory_name_coercion";
const column = "stored_name";
const date = "2030-01-02T03:04:05.000Z";
const unconvertible = { toString: 0 };
export const memoryNameCoercionCases = [
  { name: "null-first", values: [null, unconvertible] },
  { name: "null-last", values: [unconvertible, null] },
  { name: "undefined-first", values: [undefined, unconvertible] },
  { name: "undefined-last", values: [unconvertible, undefined] },
  { name: "object-only", values: [unconvertible] },
  { name: "string-first", values: ["desk", unconvertible] },
  { name: "string-last", values: [unconvertible, "desk"] },
];

function display(row) {
  return { id: row.id, present: Object.hasOwn(row, "name"), value: observeValue(row.name) };
}

async function captureCase(scenario) {
  const memory = { user: [], session: [], account: [], verification: [], [table]: [] };
  const events = [];
  const { adapter } = await betterAuth({
    baseURL: "http://memory-name-coercion.test",
    secret: "ordinary-memory-name-coercion-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    database: memoryAdapter(memory),
    plugins: [apiKey(), { id: "memory-name-coercion", schema: { apikey: { modelName: table, fields: { name: {
      type: "string", required: false, fieldName: column,
      transform: {
        input(value) { events.push({ phase: "input", value: observeValue(value) }); return value; },
        output(value) { events.push({ phase: "output", value: observeValue(value) }); return value; },
      },
    } } } } }],
  }).$context;
  const seeds = [];
  for (const [index, value] of scenario.values.entries()) {
    const row = await adapter.create({ model: "apikey", forceAllowId: true, data: {
      id: `key-${index}`, name: value, referenceId: "sort-owner", configId: "default", key: `ordinary-${index}`,
      enabled: true, rateLimitEnabled: false, requestCount: 0, createdAt: new Date(date), updatedAt: new Date(date),
    } });
    seeds.push({ input: observeValue(value), result: display(row), events: events.splice(0) });
  }
  const stored = observeValue(memory[table]);
  const operations = [];
  for (const direction of [null, "asc", "desc"]) {
    let result;
    try {
      const rows = await adapter.findMany({ model: "apikey", where: [{ field: "referenceId", value: "sort-owner" }],
        ...(direction === null ? {} : { sortBy: { field: "name", direction } }),
      });
      result = { returned: true, rows: rows.map(display) };
    } catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      assert.ok(error instanceof Error);
      result = { returned: false, error: {
        name: error.name, message: error.message, properties: observeValue(Object.fromEntries(Object.entries(error))),
      } };
    }
    const after = observeValue(memory[table]);
    assert.deepEqual(after, stored, "Sorting must preserve the raw table and insertion order");
    operations.push({ direction, ...result, events: events.splice(0), stored: after });
  }
  return { name: scenario.name, seeds, stored, operations };
}

export async function captureMemoryNameCoercion() {
  const cases = [];
  for (const scenario of memoryNameCoercionCases) cases.push(await captureCase(scenario));
  return { version, backend: "memory", model: "apikey", field: "name", table, column, cases };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the operation fixture path");
  writeFileSync(output, `${JSON.stringify(await captureMemoryNameCoercion(), null, 2)}\n`);
}
