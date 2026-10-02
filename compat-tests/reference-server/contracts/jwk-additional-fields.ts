import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const base = {
  baseURL: "http://jwk-fields.test",
  secret: "ordinary-jwk-extra-fields-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};
const policies = () => ({
  label: { type: "string" as const, fieldName: "stored_label", required: false },
  note: { type: "string" as const, required: false, defaultValue: "default-note" },
  settings: { type: "json" as const, fieldName: "stored_settings", required: false },
});
const plugin = (fields: ReturnType<typeof policies>) => ({
  id: "ordinary-jwk-additional-fields",
  schema: { jwks: { fields } },
});
const input = () => ({
  publicKey: "public", privateKey: "private", createdAt: new Date("2030-01-01T00:00:00Z"),
  expiresAt: null, alg: "EdDSA", crv: null,
  label: " Display ", settings: { compact: true, theme: "dark" },
});
const display = (row: any) => ({ label: row.label, note: row.note, settings: row.settings });

export async function captureJwkAdditionalFields() {
  const cases = [];
  for (const backend of ["memory", "sqlite"] as const) {
    for (const scenario of ["success", "input-error", "output-error"] as const) {
      const memory = { user: [], session: [], account: [], verification: [], jwks: [] };
      const db = backend === "sqlite" ? new Database(":memory:") : undefined;
      try {
        const database = db ?? memoryAdapter(memory);
        const readerOptions = { ...base, database, plugins: [jwt(), plugin(policies())] };
        if (db) await (await getMigrations(readerOptions)).runMigrations();
        const reader = (await betterAuth(readerOptions).$context).adapter;
        const events: unknown[] = [];
        const callbackError = new Error(`ordinary JWK ${scenario}`);
        const fields = {
          label: { ...policies().label, transform: {
            input(value: unknown) {
              events.push(["input", "label", value]);
              if (scenario === "input-error") throw callbackError;
              return typeof value === "string" ? value.trim() : value;
            },
            output(value: unknown) {
              events.push(["output", "label", value]);
              if (scenario === "output-error") throw callbackError;
              return `${value}:out`;
            },
          } },
          note: { ...policies().note, transform: {
            input(value: unknown) { events.push(["input", "note", value]); return value; },
            output(value: unknown) { events.push(["output", "note", value]); return value; },
          } },
          settings: { ...policies().settings, transform: {
            input(value: unknown) { events.push(["input", "settings", value]); return value; },
            output(value: unknown) { events.push(["output", "settings", value]); return value; },
          } },
        };
        const projecting = (await betterAuth({ ...base, database, plugins: [jwt(), plugin(fields)] }).$context).adapter;
        let result: unknown;
        if (scenario === "success") {
          events.push(["operation", "create-1"]);
          const first = await projecting.create<any>({ model: "jwks", data: input() });
          events.push(["operation", "create-2"]);
          const second = await projecting.create<any>({ model: "jwks", data: input() });
          events.push(["operation", "read"]);
          const read = await projecting.findOne<any>({ model: "jwks", where: [{ field: "id", value: first.id }] });
          events.push(["operation", "list"]);
          const listed = await projecting.findMany<any>({ model: "jwks" });
          result = { created: [display(first), display(second)], read: display(read), listed: listed.map(display) };
        } else {
          events.push(["operation", "create"]);
          let sameError = false;
          try { await projecting.create({ model: "jwks", data: input() }); }
          catch (error) {
            if (error !== callbackError) throw error;
            sameError = true;
          }
          result = { sameError, message: callbackError.message };
        }
        const stored = (await reader.findMany<any>({ model: "jwks" })).map(display);
        cases.push({ backend, scenario, events, result, stored });
      } finally {
        db?.close();
      }
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureJwkAdditionalFields(), null, 2));
