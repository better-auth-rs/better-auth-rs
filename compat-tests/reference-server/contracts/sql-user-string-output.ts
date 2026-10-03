import { ok } from "node:assert/strict";
import type { DBPrimitive } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

const observed = (value: unknown) => value === undefined
  ? { defined: false }
  : { defined: true, value };
const display = (row: Record<string, unknown>) => Object.fromEntries(
  ["marker", "label", "note"].map((name) => [name, {
    own: Object.hasOwn(row, name),
    value: observed(row[name]),
  }]),
);

function options(db: Database, events?: unknown[]) {
  let nextId = 1;
  const output = (name: string) => events
    ? { output(value: DBPrimitive) {
      events.push(["output", name, observed(value)]);
      return value;
    } }
    : undefined;
  return {
    baseURL: "http://sql-user-string-output.test",
    secret: "ordinary-sql-user-string-output-secret-at-least-32-characters",
    database: db,
    advanced: { database: { generateId: () => String(nextId++) } },
    logger: { disabled: true },
    telemetry: { enabled: false },
    user: { additionalFields: {
      marker: { type: "string" as const, required: false, fieldName: "stored_marker" },
      label: {
        type: "string" as const, required: false, fieldName: "stored_label",
        transform: output("label"),
      },
      note: {
        type: "string" as const, required: false, fieldName: "stored_note",
        transform: output("note"),
      },
    } },
  };
}

export async function captureSqlUserStringOutput() {
  const db = new Database(":memory:");
  try {
    const writerOptions = options(db);
    await (await getMigrations(writerOptions)).runMigrations();
    const { adapter: writer } = await betterAuth(writerOptions).$context;
    let firstId: string | undefined;
    for (const seed of [
      { marker: "a", label: null, note: "", name: "String Output A", email: "a@sql-user-string-output.test" },
      { marker: "b", label: "blue", note: "visible", name: "String Output B", email: "b@sql-user-string-output.test" },
    ]) {
      const created = await writer.create({ model: "user", data: {
        ...seed, emailVerified: false,
        createdAt: new Date("2030-01-01T00:00:00Z"), updatedAt: new Date("2030-01-01T00:00:00Z"),
      } });
      firstId ??= created.id;
    }
    ok(firstId, "The writer returns the first stored user ID");
    const events: unknown[] = [];
    const { internalAdapter: reader } = await betterAuth(options(db, events)).$context;
    const point = await reader.findUserById(firstId);
    ok(point, "The reader finds the first stored row");
    const pointObservation = { events: events.splice(0), result: display(point) };
    const rows = await reader.listUsers(10, 0, { field: "marker", direction: "asc" });
    const total = await reader.countTotalUsers();
    return {
      version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
      backend: "sqlite",
      point: pointObservation,
      batch: { events: events.splice(0), result: { users: rows.map(display), total } },
    };
  } finally {
    db.close();
  }
}

if (import.meta.main) console.log(JSON.stringify(await captureSqlUserStringOutput(), null, 2));
