import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
const referenceId = "number-sort-owner";
const date = "2030-01-02T03:04:05.000Z";
const pairs = [
  { name: "signed-zero", values: [0, -0] },
  { name: "nan-finite", values: [NaN, 1] },
  { name: "positive-infinity", values: [Infinity, Infinity] },
  { name: "negative-infinity", values: [-Infinity, -Infinity] },
];
const orders = ["forward", "reverse"];
const directions = ["asc", "desc"];

function seedRows(pair, order) {
  const rows = pair.values.map((remaining, index) => ({
    id: `${pair.name}-${index}`, name: `number-${index}`, start: null, prefix: null,
    key: `stored-${pair.name}-${index}`, referenceId, configId: "default",
    refillInterval: null, refillAmount: null, lastRefillAt: null, enabled: true,
    rateLimitEnabled: true, rateLimitTimeWindow: 60_000, rateLimitMax: 1,
    requestCount: 0, remaining, lastRequest: null, expiresAt: null,
    createdAt: new Date(date), updatedAt: new Date(date), permissions: null, metadata: null,
  }));
  return order === "reverse" ? rows.reverse() : rows;
}

function snapshot(rows) {
  return rows.map(row => ({
    ...observeValue(row),
    remaining: Object.is(row.remaining, -0) ? { type: "number", value: "-0" } : observeValue(row.remaining),
  }));
}

export async function captureApiKeyNumberSort(diagnostics = []) {
  const versions = Object.fromEntries(["better-auth", "@better-auth/core", "@better-auth/api-key", "@better-auth/memory-adapter"].map(name => [
    name, JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version,
  ]));
  const observed = { version, versions, backend: "memory", model: "apikey", field: "remaining", seedBoundary: "raw-records", cases: [] };
  diagnostics.push(observed);
  for (const pair of pairs) {
    for (const order of orders) {
      const rows = seedRows(pair, order);
      const memory = { user: [], session: [], account: [], verification: [], apikey: rows };
      const scenario = { pair: pair.name, order, input: snapshot(rows), stored: [], operations: [] };
      observed.cases.push(scenario);
      try {
        const { adapter } = await betterAuth({
          baseURL: "http://api-key-number-sort.test",
          secret: "api-key-number-sort-contract-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          database: memoryAdapter(memory), plugins: [apiKey()],
        }).$context;
        scenario.stored = snapshot(memory.apikey);
        const where = [{ field: "referenceId", value: referenceId }];
        for (const direction of directions) {
          const selected = await adapter.findMany({ model: "apikey", where, sortBy: { field: "remaining", direction } });
          scenario.operations.push({
            direction, rows: snapshot(selected), total: await adapter.count({ model: "apikey", where }),
            stored: snapshot(memory.apikey),
          });
        }
      } catch (error) {
        diagnostics.push({ pair: pair.name, order, error: { name: error?.name, message: error?.message, stack: error?.stack }, stored: snapshot(memory.apikey) });
        throw error;
      }
    }
  }
  return observed;
}

export function assertApiKeyNumberSort(observed) {
  for (const capturedVersion of Object.values(observed.versions)) assert.equal(capturedVersion, version);
  assert.equal(observed.cases.length, pairs.length * orders.length);
  for (const [index, scenario] of observed.cases.entries()) {
    const pair = pairs[Math.floor(index / orders.length)];
    const order = orders[index % orders.length];
    const expected = snapshot(seedRows(pair, order));
    assert.deepEqual(scenario, {
      pair: pair.name, order, input: expected, stored: expected,
      operations: directions.map(direction => ({ direction, rows: expected, total: expected.length, stored: expected })),
    });
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the API Key number sort fixture output path");
  const diagnostics = [];
  try {
    const observed = await captureApiKeyNumberSort(diagnostics);
    writeFileSync(`${output}.raw.json`, `${JSON.stringify(observed, null, 2)}\n`);
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
    assertApiKeyNumberSort(observed);
    writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
