import { notEqual, ok } from "node:assert/strict";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

type Query = {
  name: string;
  field: string;
  value: string | string[];
  operator: "eq" | "in";
  sortField?: string;
  limit?: number;
  offset?: number;
};
const queryCases: Query[] = [
  { name: "logical-label", field: "label", value: "alpha:in", operator: "eq" },
  { name: "physical-label", field: "stored_label", value: "alpha:in", operator: "eq" },
  { name: "pre-transform-label", field: "label", value: "alpha", operator: "eq" },
  { name: "numeric-string", field: "rank", value: "12", operator: "eq" },
  { name: "numeric-string-in", field: "stored_rank", value: ["3", "20"], operator: "in", sortField: "stored_rank" },
  { name: "boolean-string", field: "highlighted", value: "true", operator: "eq" },
  { name: "paginated-total", field: "highlighted", value: "true", operator: "eq", limit: 1, offset: 1 },
];
const seeds = [
  { name: "Display Alpha", email: "alpha@user-display-query.test", label: "alpha", rank: 20, highlighted: true },
  { name: "Display Beta", email: "beta@user-display-query.test", label: "beta", rank: 3, highlighted: false },
  { name: "Display Gamma", email: "gamma@user-display-query.test", label: "gamma", rank: 12, highlighted: true },
];
const display = (row: Record<string, unknown>) => Object.fromEntries(["label", "rank", "highlighted"].map((name) => {
  ok(Object.hasOwn(row, name), `Expected declared display field ${name}`);
  const value = row[name];
  notEqual(value, undefined, `Expected supplied display field ${name}`);
  return [name, value];
}));

export async function captureUserDisplayQuery() {
  const backends = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    try {
      const events: unknown[] = [];
      let nextId = 1;
      const options = {
        baseURL: "http://user-display-query.test",
        secret: "ordinary-user-display-query-secret-at-least-32-characters",
        database: db ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
        advanced: { database: { generateId: () => String(nextId++) } },
        logger: { disabled: true },
        telemetry: { enabled: false },
        user: { additionalFields: {
          label: {
            type: "string" as const, required: false, fieldName: "stored_label",
            transform: {
              input(value: unknown) {
                notEqual(value, undefined, "Expected the supplied display label");
                events.push(["input", "label", value]);
                return `${value}:in`;
              },
              output(value: unknown) {
                notEqual(value, undefined, "Expected the stored display label");
                events.push(["output", "label", value]);
                return `${value}:out`;
              },
            },
          },
          rank: { type: "number" as const, required: false, fieldName: "stored_rank" },
          highlighted: { type: "boolean" as const, required: false, fieldName: "stored_highlighted" },
        } },
      };
      if (db) await (await getMigrations(options)).runMigrations();
      const { adapter, internalAdapter } = await betterAuth(options).$context;
      for (const seed of seeds) {
        await adapter.create({ model: "user", data: {
          ...seed, emailVerified: false,
          createdAt: new Date("2030-01-01T00:00:00Z"), updatedAt: new Date("2030-01-01T00:00:00Z"),
        } });
      }
      events.length = 0;
      const queries = [];
      for (const query of queryCases) {
        const where = [{ field: query.field, value: query.value, operator: query.operator }];
        const rows = await internalAdapter.listUsers(
          query.limit ?? 10, query.offset ?? 0,
          { field: query.sortField ?? "rank", direction: "asc" }, where,
        );
        const total = await internalAdapter.countTotalUsers(where);
        queries.push({ name: query.name, events: events.splice(0), result: { users: rows.map(display), total } });
      }
      backends.push({ backend, queries });
    } finally {
      db?.close();
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    backends,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureUserDisplayQuery(), null, 2));
