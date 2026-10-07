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

const table = "ordinary_memory_sort";
const column = "stored_name";
const date = "2030-01-02T03:04:05.000Z";
function observe(input) {
  if (Object.is(input, -0)) return { type: "number", value: "-0" };
  if (Array.isArray(input)) return input.map(observe);
  if (input !== null && typeof input === "object" && !(input instanceof Date)) {
    return Object.fromEntries(Object.entries(input).map(([key, value]) => [key, observe(value)]));
  }
  return observeValue(input);
}
const value = (name, input) => ({ name, present: true, value: () => input });
export const memorySortStrings = [
  "z", "Z", "a", "A", "a-2", "a_2", "a 2", "a.2", "a2", "a10", "02", "2", "10", "",
  "é", "e\u0301", "e", "É", "ä", "å", "ö", "ß", "ss", "I", "i", "İ", "ı", "中", "文", "😀", "🦀",
];
const mixed = () => [
  value("number-two", 2), value("string-ten", "10"), value("false", false),
  value("string-two", "2"), value("true", true), value("array-two", [2]),
  value("object", { label: "desk" }), value("null", null), value("undefined", undefined),
  { name: "omitted", present: false, value: () => undefined },
  value("empty", ""), value("nested-array", [1, null, [2, 3]]),
  value("false-text", "false"), value("object-text", "[object Object]"), value("number-ten", 10),
];
export const memorySortCases = [
  { name: "strings", declaration: "string", values: () => memorySortStrings.map((input, index) => value(`string-${index}`, input)) },
  { name: "string-ties", declaration: "string", values: () => [value("first", "desk"), value("composed", "é"), value("second", "desk"), value("decomposed", "e\u0301")] },
  { name: "numbers", declaration: "string", values: () => [10, 2, -4, 0, -0, 1.5, 2].map((input, index) => value(`number-${index}`, input)) },
  { name: "booleans", declaration: "string", values: () => [true, false, true, false].map((input, index) => value(`boolean-${index}`, input)) },
  { name: "nullish", declaration: "string", values: () => [
    value("null-first", null), value("word", "desk"), value("undefined", undefined),
    { name: "omitted", present: false, value: () => undefined }, value("null-last", null), value("empty", ""),
  ] },
  { name: "dates", declaration: "string", values: () => [
    value("later", new Date("2030-01-03T00:00:00.000Z")), value("earlier", new Date("2030-01-01T00:00:00.000Z")),
    value("same-time", new Date("2030-01-03T00:00:00.000Z")),
  ] },
  { name: "heterogeneous-raw", declaration: "string", values: mixed },
  { name: "heterogeneous-json", declaration: "json", values: mixed },
  { name: "json-documents", declaration: "json", values: () => [
    value("object", { label: "é" }), value("array", ["é", 2]), value("object-json", '{"label":"é"}'),
    value("array-json", '["é",2]'), value("quoted-string", '"é"'), value("null", null),
    value("null-json", "null"), value("invalid-json", "é"),
  ] },
  { name: "nonconvertible-single", declaration: "string", values: () => [value("object", { toString: null })] },
  { name: "nonconvertible-pair", declaration: "string", values: () => [value("object", { toString: null }), value("word", "desk")] },
];
export const memorySortOperations = ["unsorted", "ascending", "descending", "ascending-page", "descending-page"];

function display(row, field) {
  return { id: row.id, present: Object.hasOwn(row, field), value: observe(row[field]) };
}

async function captureCase(scenario) {
  const memory = { user: [], session: [], account: [], verification: [], [table]: [] };
  const events = [];
  const { adapter } = await betterAuth({
    baseURL: "http://memory-sort.test",
    secret: "ordinary-memory-sort-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    database: memoryAdapter(memory),
    plugins: [apiKey(), { id: "ordinary-memory-sort", schema: { apikey: { modelName: table, fields: { name: {
      type: scenario.declaration, required: false, fieldName: column,
      transform: {
        input(input) { events.push({ phase: "input", value: observe(input) }); return input; },
        output(input) { events.push({ phase: "output", value: observe(input) }); return input; },
      },
    } } } } }],
  }).$context;
  const seeds = [];
  for (const input of scenario.values()) {
    const supplied = input.present ? { name: input.value() } : {};
    const created = await adapter.create({ model: "apikey", forceAllowId: true, data: {
      id: input.name, ...supplied, configId: "default", referenceId: "sort-owner", key: `ordinary-${input.name}`,
      enabled: true, rateLimitEnabled: false, requestCount: 0, createdAt: new Date(date), updatedAt: new Date(date),
    } });
    seeds.push({ input: { id: input.name, ...observe(supplied) }, result: display(created, "name"), events: events.splice(0) });
  }
  const stored = memory[table].map(row => display(row, column));
  const operations = [];
  for (const [name, sortBy, page] of [
    ["unsorted", undefined, {}],
    ["ascending", { field: "name", direction: "asc" }, {}],
    ["descending", { field: "name", direction: "desc" }, {}],
    ["ascending-page", { field: "name", direction: "asc" }, { offset: 1, limit: 2 }],
    ["descending-page", { field: "name", direction: "desc" }, { offset: 1, limit: 2 }],
  ]) {
    let outcome;
    try {
      const rows = await adapter.findMany({ model: "apikey", where: [{ field: "referenceId", value: "sort-owner" }], sortBy, ...page });
      outcome = { returned: true, rows: rows.map(row => display(row, "name")) };
    } catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      assert.ok(error instanceof Error);
      outcome = { returned: false, error: { name: error.name, message: error.message, properties: observe(Object.fromEntries(Object.entries(error))) } };
    }
    const after = memory[table].map(row => display(row, column));
    assert.deepEqual(after, stored, "Sorting must preserve the raw table and insertion order");
    operations.push({ name, ...outcome, events: events.splice(0), stored: after });
  }
  return { name: scenario.name, declaration: scenario.declaration, seeds, stored, operations };
}

export function memorySortProvenance() {
  return {
    version,
    collator: new Intl.Collator().resolvedOptions(),
    runtime: { bun: Bun.version, versions: { ...process.versions } },
    environment: Object.fromEntries(["LANG", "LANGUAGE", "LC_ALL", "LC_COLLATE", "LC_CTYPE", "TZ"].map(name => [name, process.env[name] ?? null])),
  };
}

export async function captureMemorySort() {
  const cases = [];
  for (const scenario of memorySortCases) cases.push(await captureCase(scenario));
  return {
    version, backend: "memory", model: "apikey", field: "name", table, column,
    stringComparisons: {
      values: memorySortStrings,
      signs: memorySortStrings.map(left => memorySortStrings.map(right => Math.sign(left.localeCompare(right)))),
    },
    cases,
  };
}

if (import.meta.main) {
  const [output, provenanceOutput = `${output}.provenance.json`] = process.argv.slice(2);
  assert.ok(output, "Pass the operation fixture path; the separate provenance path is optional");
  writeFileSync(output, `${JSON.stringify(await captureMemorySort(), null, 2)}\n`);
  writeFileSync(provenanceOutput, `${JSON.stringify(memorySortProvenance(), null, 2)}\n`);
}
