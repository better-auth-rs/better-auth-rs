import { notEqual, ok } from "node:assert/strict";
import type { DBPrimitive } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

type Query = {
  name: string;
  filter?: string;
  sort: string;
  direction: "asc" | "desc";
  limit?: number;
};
const queries: Query[] = [
  { name: "unknown-zero", filter: "absent", sort: "unknownDisplay", direction: "asc" },
  { name: "unknown-one", filter: "alpha", sort: "unknownDisplay", direction: "asc" },
  { name: "unknown-two", sort: "unknownDisplay", direction: "asc" },
  { name: "logical-rank", sort: "rank", direction: "asc" },
  { name: "physical-rank", sort: "stored_rank", direction: "desc", limit: 1 },
];
const display = (row: Record<string, unknown>) => Object.fromEntries(["label", "rank"].map((name) => {
  ok(Object.hasOwn(row, name), `Expected declared display field ${name}`);
  const value = row[name];
  notEqual(value, undefined, `Expected supplied display field ${name}`);
  return [name, value];
}));

export async function captureUserSortField() {
  const backends = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    try {
      const events: unknown[] = [];
      let nextId = 1;
      const options = {
        baseURL: "http://user-sort-field.test",
        secret: "ordinary-user-sort-field-secret-at-least-32-characters",
        database: db ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
        advanced: { database: { generateId: () => String(nextId++) } },
        logger: { disabled: true },
        telemetry: { enabled: false },
        user: { additionalFields: {
          label: {
            type: "string" as const, required: false, fieldName: "stored_label",
            transform: { output(value: DBPrimitive) {
              notEqual(value, undefined, "Expected the supplied display label");
              events.push(["output", "label", value]);
              return value;
            } },
          },
          rank: { type: "number" as const, required: false, fieldName: "stored_rank" },
        } },
      };
      if (db) await (await getMigrations(options)).runMigrations();
      const { adapter, internalAdapter } = await betterAuth(options).$context;
      for (const seed of [
        { name: "Sort Alpha", email: "alpha@user-sort-field.test", label: "alpha", rank: 20 },
        { name: "Sort Beta", email: "beta@user-sort-field.test", label: "beta", rank: 3 },
      ]) {
        await adapter.create({ model: "user", data: {
          ...seed, emailVerified: false,
          createdAt: new Date("2030-01-01T00:00:00Z"), updatedAt: new Date("2030-01-01T00:00:00Z"),
        } });
      }
      events.length = 0;
      const observations = [];
      for (const query of queries) {
        const where = query.filter === undefined
          ? undefined
          : [{ field: "label", value: query.filter, operator: "eq" as const }];
        let rows: Awaited<ReturnType<typeof internalAdapter.listUsers>>;
        try {
          rows = await internalAdapter.listUsers(
            query.limit ?? 10, 0, { field: query.sort, direction: query.direction }, where,
          );
        } catch (error) {
          ok(error instanceof Error, "Expected the original sort field error");
          observations.push({ name: query.name, events: events.splice(0), error: {
            kind: error.name, message: error.message,
          } });
          continue;
        }
        const total = await internalAdapter.countTotalUsers(where);
        observations.push({ name: query.name, events: events.splice(0), result: {
          users: rows.map(display), total,
        } });
      }
      backends.push({ backend, queries: observations });
    } finally {
      db?.close();
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    backends,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureUserSortField(), null, 2));
