import { ok } from "node:assert/strict";
import type { DBPrimitive } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";

const displayNames = ["requiredSettings", "settings"] as const;
const physicalNames = ["stored_required_settings", "stored_settings"] as const;

const kind = (value: unknown) => value === null
  ? "null"
  : Array.isArray(value) ? "array" : typeof value;
const presentValue = (value: unknown) => value === undefined
  ? { present: false }
  : { present: true, value };
const display = (row: Record<string, unknown>) => Object.fromEntries(
  displayNames.map((name) => [name, {
    own: Object.hasOwn(row, name),
    ...presentValue(row[name]),
  }]),
);

export async function captureSqliteJsonGeneration() {
  const db = new Database(":memory:");
  const events: unknown[] = [];
  let nextId = 1;
  const transform = (field: string) => ({
    input(value: DBPrimitive) {
      events.push({ phase: "input", field, kind: kind(value), ...presentValue(value) });
      return value;
    },
    output(value: DBPrimitive) {
      events.push({ phase: "output", field, kind: kind(value), ...presentValue(value) });
      return value;
    },
  });
  const options = {
    baseURL: "http://sqlite-json-generation.test",
    secret: "ordinary-sqlite-json-generation-secret-at-least-32-characters",
    database: db,
    advanced: { database: { generateId: () => String(nextId++) } },
    telemetry: { enabled: false },
    plugins: [organization({ schema: { organization: { additionalFields: {
      requiredSettings: {
        type: "json" as const,
        required: true,
        defaultValue: { theme: "default" },
        fieldName: "stored_required_settings",
        transform: transform("requiredSettings"),
      },
      settings: {
        type: "json" as const,
        required: false,
        fieldName: "stored_settings",
        transform: transform("settings"),
      },
    } } } })],
  };
  try {
    await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    const storedPhysical = (id: string) => {
      const row = db.query<Record<string, unknown>, [string]>(
        'SELECT "stored_required_settings", "stored_settings" FROM "organization" WHERE "id" = ?',
      ).get(id);
      ok(row, "The physical organization display row exists");
      return Object.fromEntries(physicalNames.map((name) => {
        ok(Object.hasOwn(row, name), "The SQL observation contains each selected physical display column");
        return [name, row[name]];
      }));
    };
    const observe = (row: Record<string, unknown>, id: string) => ({
      events: events.splice(0),
      result: display(row),
      storedPhysical: storedPhysical(id),
    });
    const read = async (id: string) => {
      const row = await adapter.findOne<Record<string, unknown>>({
        model: "organization", where: [{ field: "id", value: id }],
      });
      ok(row, "The adapter finds the created display row");
      return observe(row, id);
    };
    const cases = [];
    let objectId: string | undefined;
    const seeds: { name: string; fields: Record<string, unknown> }[] = [
      { name: "omitted", fields: {} },
      { name: "null", fields: { settings: null } },
      { name: "object", fields: { settings: { theme: "light", enabled: true } } },
      { name: "array", fields: { settings: ["display", 12] } },
      { name: "encoded-string", fields: { settings: '"display"' } },
      { name: "invalid-text", fields: { settings: "not-json" } },
      { name: "whitespace-object", fields: { settings: ' { "theme": "spaced" } ' } },
      { name: "integer", fields: { settings: 12 } },
      { name: "fractional", fields: { settings: 12.5 } },
      { name: "false", fields: { settings: false } },
      { name: "true", fields: { settings: true } },
    ];
    for (const { name, fields } of seeds) {
      const row = await adapter.create<Record<string, unknown>>({
        model: "organization",
        data: {
          name: `JSON Generation ${name}`,
          slug: `json-generation-${name}`,
          createdAt: new Date("2030-01-01T00:00:00Z"),
          ...fields,
        },
      });
      ok(typeof row.id === "string", "The adapter returns the created row ID for subsequent ordinary operations");
      if (name === "object") objectId = row.id;
      const create = observe(row, row.id);
      cases.push({ name, create, read: await read(row.id) });
    }
    ok(objectId, "The ordinary object case supplies the display-update row");
    const updates = [];
    const changes: { name: string; fields: Record<string, unknown> }[] = [
      { name: "null", fields: { settings: null } },
      { name: "invalid-text", fields: { settings: "not-json" } },
      { name: "omitted", fields: { requiredSettings: { theme: "default" } } },
    ];
    for (const { name, fields } of changes) {
      const row = await adapter.update<Record<string, unknown>>({
        model: "organization", where: [{ field: "id", value: objectId }], update: fields,
      });
      ok(row, "The adapter updates the ordinary display row");
      const update = observe(row, objectId);
      updates.push({ name, update, read: await read(objectId) });
    }
    return {
      version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
      backend: "sqlite",
      cases,
      updates,
    };
  } finally {
    db.close();
  }
}

if (import.meta.main) console.log(JSON.stringify(await captureSqliteJsonGeneration(), null, 2));
