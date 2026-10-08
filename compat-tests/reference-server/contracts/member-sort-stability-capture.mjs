import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";

const version = "1.7.6";
const organizationId = "sort-organization";
const input = [
  ["later-first", "2030-01-03T00:00:00.000Z"],
  ["earlier-first", "2030-01-01T00:00:00.000Z"],
  ["later-second", "2030-01-03T00:00:00.000Z"],
  ["earlier-second", "2030-01-01T00:00:00.000Z"],
  ["middle", "2030-01-02T00:00:00.000Z"],
].map(([id, createdAt]) => ({
  id, organizationId, userId: `user-${id}`, role: "member", createdAt,
}));
const operations = [
  { name: "ascending", direction: "asc" },
  { name: "descending", direction: "desc" },
  { name: "ascending-page", direction: "asc", offset: 1, limit: 3 },
  { name: "descending-page", direction: "desc", offset: 1, limit: 3 },
];
const snapshot = value => JSON.parse(JSON.stringify(value));

export async function captureMemberSortStability(diagnostics = []) {
  const versions = Object.fromEntries(["better-auth", "@better-auth/core", "@better-auth/memory-adapter"].map(name => [
    name, JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version,
  ]));
  const memory = { user: [], session: [], account: [], verification: [], organization: [], member: [], invitation: [] };
  const observed = { version, versions, backend: "memory", field: "createdAt", input, created: [], stored: [], operations: [] };
  diagnostics.push(observed);
  try {
    const { adapter } = await betterAuth({
      baseURL: "http://member-sort-stability.test",
      secret: "member-sort-stability-contract-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      database: memoryAdapter(memory), plugins: [organization()],
    }).$context;
    for (const row of input) {
      observed.created.push(snapshot(await adapter.create({
        model: "member", forceAllowId: true, data: { ...row, createdAt: new Date(row.createdAt) },
      })));
    }
    observed.stored = snapshot(memory.member);
    const where = [{ field: "organizationId", value: organizationId }];
    for (const operation of operations) {
      const rows = await adapter.findMany({
        model: "member", where, sortBy: { field: "createdAt", direction: operation.direction },
        ...(operation.limit === undefined ? {} : { limit: operation.limit }),
        ...(operation.offset === undefined ? {} : { offset: operation.offset }),
      });
      observed.operations.push({
        ...operation, rows: snapshot(rows), total: await adapter.count({ model: "member", where }),
        stored: snapshot(memory.member),
      });
    }
    return observed;
  } catch (error) {
    diagnostics.push({ error: { name: error?.name, message: error?.message, stack: error?.stack }, stored: snapshot(memory) });
    throw error;
  }
}

export function assertMemberSortStability(observed) {
  for (const capturedVersion of Object.values(observed.versions)) assert.equal(capturedVersion, version);
  assert.deepEqual(observed.created, input);
  assert.deepEqual(observed.stored, input);
  const expectedIds = [
    ["earlier-first", "earlier-second", "middle", "later-first", "later-second"],
    ["later-first", "later-second", "middle", "earlier-first", "earlier-second"],
    ["earlier-second", "middle", "later-first"],
    ["later-second", "middle", "earlier-first"],
  ];
  assert.equal(observed.operations.length, operations.length);
  for (const [index, operation] of observed.operations.entries()) {
    const expectedRows = expectedIds[index].map(id => input.find(row => row.id === id));
    assert.deepEqual(operation, { ...operations[index], rows: expectedRows, total: input.length, stored: input });
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the Member sort stability fixture output path");
  const diagnostics = [];
  try {
    const observed = await captureMemberSortStability(diagnostics);
    writeFileSync(`${output}.raw.json`, `${JSON.stringify(observed, null, 2)}\n`);
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
    assertMemberSortStability(observed);
    writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
