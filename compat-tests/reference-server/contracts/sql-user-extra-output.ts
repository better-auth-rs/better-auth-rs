import { equal, ok } from "node:assert/strict";
import type { DBPrimitive } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

const displayNames = ["marker", "rank", "highlighted", "displayAt", "settings", "tags", "scores"] as const;

// Date uses its JSON wire value; the event kind retains the callback's actual type.
const jsonValue = (value: unknown) => value === undefined
  ? null
  : value instanceof Date ? value.toISOString() : value;
const kind = (value: unknown) => value === null
  ? "null"
  : value instanceof Date ? "date" : Array.isArray(value) ? "array" : typeof value;
const display = (row: Record<string, unknown>) => Object.fromEntries(
  displayNames.map((name) => [name, {
    own: Object.hasOwn(row, name),
    present: row[name] !== undefined,
    value: jsonValue(row[name]),
  }]),
);

function options(db: Database, events?: unknown[]) {
  let nextId = 1;
  const output = (field: string) => events
    ? { output(value: DBPrimitive) {
      events.push({ field, present: value !== undefined, kind: kind(value), value: jsonValue(value) });
      return value;
    } }
    : undefined;
  return {
    baseURL: "http://sql-user-extra-output.test",
    secret: "ordinary-sql-user-extra-output-secret-at-least-32-characters",
    database: db,
    advanced: { database: { generateId: () => String(nextId++) } },
    logger: { disabled: true },
    telemetry: { enabled: false },
    user: { additionalFields: {
      marker: { type: "string" as const, required: true, fieldName: "stored_marker" },
      rank: {
        type: "number" as const, required: false, fieldName: "stored_rank",
        transform: output("rank"),
      },
      highlighted: {
        type: "boolean" as const, required: false, fieldName: "stored_highlighted",
        transform: output("highlighted"),
      },
      displayAt: {
        type: "date" as const, required: false, fieldName: "stored_displayAt",
        transform: output("displayAt"),
      },
      settings: {
        type: "json" as const, required: false, fieldName: "stored_settings",
        transform: output("settings"),
      },
      tags: {
        type: "string[]" as const, required: false, fieldName: "stored_tags",
        transform: output("tags"),
      },
      scores: {
        type: "number[]" as const, required: false, fieldName: "stored_scores",
        transform: output("scores"),
      },
    } },
  };
}

export async function captureSqlUserExtraOutput() {
  const db = new Database(":memory:");
  try {
    const writerOptions = options(db);
    await (await getMigrations(writerOptions)).runMigrations();
    const { adapter: writer } = await betterAuth(writerOptions).$context;
    const ids = new Map<string, string>();
    for (const seed of [
      { marker: "a", name: "Extra Output A", email: "a@sql-user-extra-output.test" },
      {
        marker: "b", name: "Extra Output B", email: "b@sql-user-extra-output.test",
        rank: 0.5, highlighted: false, displayAt: new Date("2030-01-02T03:04:05.006Z"),
        settings: {}, tags: [], scores: [],
      },
      {
        marker: "c", name: "Extra Output C", email: "c@sql-user-extra-output.test",
        rank: 12.5, highlighted: true, displayAt: new Date("2031-02-03T04:05:06.007Z"),
        settings: { theme: "blue" }, tags: ["blue", "green"], scores: [1.25, 2.5],
      },
      { marker: "d", name: "Extra Output D", email: "d@sql-user-extra-output.test" },
    ]) {
      const created = await writer.create<Record<string, unknown>>({ model: "user", data: {
        ...seed, emailVerified: false,
        createdAt: new Date("2030-01-01T00:00:00Z"), updatedAt: new Date("2030-01-01T00:00:00Z"),
      } });
      ok(typeof created.id === "string", "The writer returns the stored row ID");
      ids.set(seed.marker, created.id);
    }
    const literalNullId = ids.get("d");
    ok(literalNullId, "The writer returns the JSON literal-null row ID");
    const changed = db.query('UPDATE "user" SET "stored_settings" = ? WHERE "id" = ?')
      .run("null", literalNullId);
    equal(changed.changes, 1, "The fixture stores JSON literal null on the selected display row");

    const events: unknown[] = [];
    const { internalAdapter: reader } = await betterAuth(options(db, events)).$context;
    const points = [];
    for (const [name, marker] of [["sql-null", "a"], ["json-null", "d"]] as const) {
      const id = ids.get(marker);
      ok(id, "The writer returns the selected point-read row ID");
      const row = await reader.findUserById(id);
      ok(row, "The reader finds the selected display row");
      points.push({ name, events: events.splice(0), result: display(row) });
    }
    const rows = await reader.listUsers(10, 0, { field: "marker", direction: "asc" });
    const total = await reader.countTotalUsers();
    return {
      version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
      backend: "sqlite",
      points,
      batch: { events: events.splice(0), result: { users: rows.map(display), total } },
    };
  } finally {
    db.close();
  }
}

if (import.meta.main) console.log(JSON.stringify(await captureSqlUserExtraOutput(), null, 2));
