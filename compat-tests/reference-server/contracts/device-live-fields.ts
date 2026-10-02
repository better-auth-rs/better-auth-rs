import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const base = {
  baseURL: "http://device-fields.test",
  secret: "ordinary-device-extra-fields-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};
const policies = () => ({
  label: { type: "string" as const, fieldName: "stored_label", required: false },
  note: { type: "string" as const, fieldName: "unconfigured", required: false },
});
const plugin = (fields: ReturnType<typeof policies>) => ({
  id: "ordinary-device-live-fields",
  schema: { deviceCode: { fields } },
});
const display = (row: any) => ({ label: row.label, note: row.note });

export async function captureDeviceLiveFields() {
  const cases = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    try {
      const writerOptions = {
        ...base,
        database: db ?? memoryAdapter(memory),
        plugins: [deviceAuthorization(), plugin(policies())],
      };
      if (db) await (await getMigrations(writerOptions)).runMigrations();
      const writer = (await betterAuth(writerOptions).$context).adapter;
      const created = await writer.create<any>({ model: "deviceCode", data: {
        deviceCode: "ordinary-device:live-fields", userCode: "ordinary-user:live-fields",
        userId: null, expiresAt: new Date("2030-01-01T00:00:00Z"), status: "pending",
        lastPolledAt: null, pollingInterval: 5000, clientId: "ordinary-client", scope: "read",
        label: "label-before", note: "note-before",
      } });
      const where = [{ field: "id", value: created.id }];
      const events: unknown[] = [];
      const readerFields = {
        label: { ...policies().label, transform: { async output(value: unknown) {
          events.push(["label", value]);
          await writer.update({ model: "deviceCode", where, update: { note: "note-after" } });
          events.push(["note-write", "note-after"]);
          return `${value}:out`;
        } } },
        note: { ...policies().note, transform: { output(value: unknown) {
          events.push(["note", value]);
          return `${value}:out`;
        } } },
      };
      const reader = (await betterAuth({
        ...base,
        database: db ?? memoryAdapter(memory),
        plugins: [deviceAuthorization(), plugin(readerFields)],
      }).$context).adapter;
      for (const selector of ["deviceCode", "userCode"] as const) {
        await writer.update({ model: "deviceCode", where, update: { note: "note-before" } });
        events.length = 0;
        const selected = await reader.findOne({ model: "deviceCode", where: [{ field: selector, value: created[selector] }] });
        const stored = await writer.findOne({ model: "deviceCode", where });
        cases.push({ backend, selector, events: [...events], result: display(selected), stored: display(stored) });
      }
    } finally {
      db?.close();
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureDeviceLiveFields(), null, 2));
