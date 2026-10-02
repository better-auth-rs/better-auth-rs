import { deepStrictEqual, equal, ok } from "node:assert/strict";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const base = {
  baseURL: "http://field-json-text.test",
  secret: "ordinary-field-json-text-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};

const jsonOracle = () => JSON.parse('{"4294967295":"last-index","01":"leading-zero","4294967294":1e21,"0":-0.0,"numbers":[0.0,-0.0,1e-7,1e-6,1e20,1e21],"nested":{"2":2.0,"1":1.0,"01":1.0}}');

export async function captureFieldJsonText() {
  const cases = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const memory = { user: [], session: [], account: [], verification: [], jwks: [] as Record<string, unknown>[] };
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    const events: unknown[] = [];
    const outputTexts: string[] = [];
    const plugin = {
      id: "ordinary-field-json-text",
      schema: { jwks: { fields: {
        settings: {
          type: "json" as const,
          fieldName: "stored_settings",
          required: false,
          transform: {
            input(value: unknown) {
              events.push(["input", "settings"]);
              return value;
            },
            output(value: unknown) {
              equal(typeof value, "string", "the output callback receives stored JSON text");
              const text = value as string;
              events.push(["output", "settings", text]);
              outputTexts.push(text);
              return text;
            },
          },
        },
      } } },
    };
    try {
      const options = { ...base, database: db ?? memoryAdapter(memory), plugins: [jwt(), plugin] };
      if (db) await (await getMigrations(options)).runMigrations();
      const adapter = (await betterAuth(options).$context).adapter;
      events.push(["operation", "create"]);
      const created = await adapter.create<any>({
        model: "jwks",
        data: {
          publicKey: "public", privateKey: "private", createdAt: new Date("2030-01-01T00:00:00Z"),
          expiresAt: null, alg: "EdDSA", crv: null,
          settings: jsonOracle(),
        },
      });
      equal(outputTexts.length, 1, "create projects the display field once");
      const createdText = outputTexts[0];
      deepStrictEqual(created.settings, JSON.parse(createdText));
      const createdMatchesText = true;

      events.push(["operation", "read"]);
      const read = await adapter.findOne<any>({ model: "jwks", where: [{ field: "id", value: created.id }] });
      ok(read, "the created display row is readable");
      equal(outputTexts.length, 2, "read projects the display field once");
      const readText = outputTexts[1];
      deepStrictEqual(read.settings, JSON.parse(readText));
      const readMatchesText = true;

      const stored = db
        ? db.query("SELECT stored_settings FROM jwks").get() as Record<string, unknown> | null
        : memory.jwks[0];
      ok(stored, "the raw display row exists");
      const storedText = stored.stored_settings;
      equal(typeof storedText, "string", "the physical display field contains JSON text");
      equal(createdText, storedText, "create callback text preserves physical storage bytes");
      equal(readText, storedText, "read callback text preserves physical storage bytes");
      cases.push({ backend, events, storedText, createdMatchesText, readMatchesText });
    } finally {
      db?.close();
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureFieldJsonText(), null, 2));
