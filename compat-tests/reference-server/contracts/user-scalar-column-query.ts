import type { DBPrimitive } from "@better-auth/core/db";
import type { Where } from "@better-auth/core/db/adapter";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

type Query = {
  name: string;
  where?: Where[];
  sortBy: { field: string; direction: "asc" | "desc" };
  limit?: number;
};
const nullQueries: Query[] = [
  { name: "logical-boolean-eq-null", where: [{ field: "highlighted", value: null, operator: "eq" }], sortBy: { field: "marker", direction: "asc" } },
  { name: "physical-boolean-ne-null", where: [{ field: "stored_highlighted", value: null, operator: "ne" }], sortBy: { field: "marker", direction: "asc" } },
  { name: "logical-number-eq-null", where: [{ field: "rank", value: null, operator: "eq" }], sortBy: { field: "marker", direction: "asc" } },
  { name: "physical-number-ne-null", where: [{ field: "stored_rank", value: null, operator: "ne" }], sortBy: { field: "marker", direction: "asc" } },
];
const sqliteQueries: Query[] = [
  { name: "logical-boolean-false", where: [{ field: "highlighted", value: false, operator: "eq" }], sortBy: { field: "marker", direction: "asc" } },
  { name: "physical-boolean-false", where: [{ field: "stored_highlighted", value: "false", operator: "eq" }], sortBy: { field: "marker", direction: "asc" } },
  { name: "logical-boolean-sort", sortBy: { field: "highlighted", direction: "asc" } },
  { name: "physical-boolean-sort-page", sortBy: { field: "stored_highlighted", direction: "desc" }, limit: 2 },
  ...nullQueries,
];
const display = (row: Record<string, unknown>) => Object.fromEntries(
  ["marker", "highlighted", "rank"].map((name) => [name, {
    own: Object.hasOwn(row, name),
    present: row[name] !== undefined,
    value: row[name] === undefined ? null : row[name],
  }]),
);

function options(database: Database | ReturnType<typeof memoryAdapter>, events?: unknown[]) {
  let nextId = 1;
  const output = (field: string) => events
    ? { output(value: DBPrimitive) {
      events.push({
        field,
        present: value !== undefined,
        kind: value === null ? "null" : typeof value,
        value: value === undefined ? null : value,
      });
      return value;
    } }
    : undefined;
  return {
    baseURL: "http://user-scalar-column-query.test",
    secret: "ordinary-user-scalar-column-query-secret-at-least-32-characters",
    database,
    advanced: { database: { generateId: () => String(nextId++) } },
    logger: { disabled: true },
    telemetry: { enabled: false },
    user: { additionalFields: {
      marker: { type: "string" as const, required: true, fieldName: "stored_marker" },
      highlighted: {
        type: "boolean" as const, required: false, fieldName: "stored_highlighted",
        transform: output("highlighted"),
      },
      rank: {
        type: "number" as const, required: false, fieldName: "stored_rank",
        transform: output("rank"),
      },
    } },
  };
}

export async function captureUserScalarColumnQuery() {
  const backends = [];
  for (const backend of ["sqlite", "memory"] as const) {
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    try {
      const database = db ?? memoryAdapter({ user: [], session: [], account: [], verification: [] });
      const writerOptions = options(database);
      if (db) await (await getMigrations(writerOptions)).runMigrations();
      const { adapter: writer } = await betterAuth(writerOptions).$context;
      for (const seed of [
        { marker: "false", name: "Scalar Query False", email: "false@user-scalar-column-query.test", highlighted: false, rank: 0.5 },
        {
          marker: "null", name: "Scalar Query Null", email: "null@user-scalar-column-query.test",
          ...(backend === "memory" ? { highlighted: null, rank: null } : {}),
        },
        { marker: "true", name: "Scalar Query True", email: "true@user-scalar-column-query.test", highlighted: true, rank: 12.5 },
      ]) {
        await writer.create({ model: "user", data: {
          ...seed, emailVerified: false,
          createdAt: new Date("2030-01-01T00:00:00Z"), updatedAt: new Date("2030-01-01T00:00:00Z"),
        } });
      }
      const events: unknown[] = [];
      const { internalAdapter: reader } = await betterAuth(options(database, events)).$context;
      const queries = [];
      for (const query of backend === "sqlite" ? sqliteQueries : nullQueries) {
        const rows = await reader.listUsers(query.limit ?? 10, 0, query.sortBy, query.where);
        const total = await reader.countTotalUsers(query.where);
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

if (import.meta.main) console.log(JSON.stringify(await captureUserScalarColumnQuery(), null, 2));
