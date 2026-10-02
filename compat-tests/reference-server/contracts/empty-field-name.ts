import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getSchema } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";

const base = {
  baseURL: "http://device-fields.test",
  secret: "ordinary-device-extra-fields-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};
const fields = (alias: string | undefined) => ({
  label: {
    type: "string" as const,
    required: false,
    ...(alias === undefined ? {} : { fieldName: alias }),
  },
});
const plugin = (alias: string | undefined) => ({
  id: "ordinary-empty-field-name",
  schema: { deviceCode: { fields: fields(alias) } },
});
const display = (row: any) => {
  if (!row) throw new Error("Expected the ordinary display-field row");
  return { hasLabel: Object.hasOwn(row, "label"), label: row.label ?? null };
};

export async function captureEmptyFieldName() {
  const cases = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    try {
      const options = (alias: string | undefined) => ({
        ...base,
        database: db ?? memoryAdapter(memory),
        plugins: [deviceAuthorization(), plugin(alias)],
      });
      if (db) await (await getMigrations(options(""))).runMigrations();
      const empty = (await betterAuth(options("")).$context).adapter;
      const omitted = (await betterAuth(options(undefined)).$context).adapter;
      const where = [{ field: "deviceCode", value: "ordinary-device:empty-field-name" }];
      const created = await empty.create<any>({ model: "deviceCode", data: {
        deviceCode: "ordinary-device:empty-field-name", userCode: "ordinary-user:empty-field-name",
        userId: null, expiresAt: new Date("2030-01-01T00:00:00Z"), status: "pending",
        lastPolledAt: null, pollingInterval: 5000, clientId: "ordinary-client", scope: "read",
        label: "label-created",
      } });
      const readByOmitted = await omitted.findOne({ model: "deviceCode", where });
      const updated = await omitted.update({
        model: "deviceCode", where: [{ field: "id", value: created.id }],
        update: { label: "label-updated" },
      });
      const readByEmpty = await empty.findOne({ model: "deviceCode", where });
      cases.push({
        backend,
        createdByEmpty: display(created),
        readByOmitted: display(readByOmitted),
        updatedByOmitted: display(updated),
        readByEmpty: display(readByEmpty),
      });
    } finally {
      db?.close();
    }
  }
  const native = getSchema({ ...base, plugins: [deviceAuthorization()] }).deviceCode.fields;
  const schemas = [
    ["empty", ""], ["omitted", undefined], ["space", " "],
  ].map(([view, alias]) => {
    const schema = getSchema({ ...base, plugins: [deviceAuthorization(), plugin(alias)] });
    return {
      view,
      columns: Object.keys(schema.deviceCode.fields).filter((name) => !Object.hasOwn(native, name)),
    };
  });
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
    schemas,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureEmptyFieldName(), null, 2));
