import { ok } from "node:assert/strict";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const observed = (value: unknown) => value === undefined
  ? { defined: false }
  : { defined: true, value };
const display = (row: Record<string, unknown>) => Object.fromEntries(
  ["marker", "label"].map((name) => [name, {
    own: Object.hasOwn(row, name),
    value: observed(row[name]),
  }]),
);
const queries = [
  { name: "logical-eq-null", field: "label", operator: "eq" as const },
  { name: "physical-eq-null", field: "stored_label", operator: "eq" as const },
  { name: "logical-ne-null", field: "label", operator: "ne" as const },
  { name: "physical-ne-null", field: "stored_label", operator: "ne" as const },
];
const seeds = [
  { marker: "alpha", name: "Null Query Alpha", email: "alpha@user-null-query.test" },
  { marker: "beta", name: "Null Query Beta", email: "beta@user-null-query.test", label: null },
  { marker: "gamma", name: "Null Query Gamma", email: "gamma@user-null-query.test", label: "ordinary" },
];

export async function captureUserNullQuery() {
  const backends = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    try {
      const events: unknown[] = [];
      let nextId = 1;
      const options = {
        baseURL: "http://user-null-query.test",
        secret: "ordinary-user-null-query-secret-at-least-32-characters",
        database: db ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
        advanced: { database: { generateId: () => String(nextId++) } },
        logger: { disabled: true },
        telemetry: { enabled: false },
        user: { additionalFields: {
          marker: { type: "string" as const, required: false, fieldName: "stored_marker" },
          label: {
            type: "string" as const, required: false, fieldName: "stored_label",
            transform: { output(value: unknown) {
              events.push(["output", "label", observed(value)]);
              return value === undefined ? "(missing)" : value;
            } },
          },
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
      const observations = [];
      for (const query of queries) {
        const where = [{ field: query.field, value: null, operator: query.operator }];
        const rows = await internalAdapter.listUsers(10, 0, { field: "marker", direction: "asc" }, where);
        const total = await internalAdapter.countTotalUsers(where);
        observations.push({ name: query.name, events: events.splice(0), result: { users: rows.map(display), total } });
      }
      const errors = [];
      const unknown = [{ field: "unknownLabel", value: "ordinary", operator: "eq" as const }];
      for (const [name, call] of [
        ["unknown-list", () => internalAdapter.listUsers(10, 0, { field: "marker", direction: "asc" }, unknown)],
        ["unknown-count", () => internalAdapter.countTotalUsers(unknown)],
      ] satisfies [string, () => Promise<unknown>][]) {
        let caught: Error | undefined;
        try {
          await call();
        } catch (error) {
          ok(error instanceof Error, "Expected the original schema error");
          caught = error;
        }
        ok(caught, "The undeclared filter must fail");
        errors.push({ name, events: events.splice(0), error: { kind: caught.name, message: caught.message } });
      }
      backends.push({ backend, queries: observations, errors });
    } finally {
      db?.close();
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    backends,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureUserNullQuery(), null, 2));
