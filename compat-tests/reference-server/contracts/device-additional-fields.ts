import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const memoryTables = () => ({ user: [], session: [], account: [], verification: [], deviceCode: [] });
const base = {
  baseURL: "http://device-fields.test",
  secret: "ordinary-device-extra-fields-secret-at-least-32-characters",
  logger: { disabled: true }, telemetry: { enabled: false },
};
const data = (label: string) => ({
  deviceCode: `ordinary-device:${label}`, userCode: `ordinary-user:${label}`,
  userId: null, expiresAt: new Date("2030-01-01T00:00:00Z"), status: "pending",
  lastPolledAt: null, pollingInterval: 5000, clientId: "ordinary-client", scope: "read",
  activatedAt: "2029-01-02T03:04:05.000Z", details: { channel: "ordinary", enabled: true },
});
const observe = (name: string, row: any) => ({
  name, scope: row.scope,
  fields: { label: row.label, activatedAt: row.activatedAt.toISOString(), details: row.details, revision: row.revision },
});

export async function captureDeviceAdditionalFields() {
  const backends = [];
  for (const backend of ["memory", "sqlite"] as const) {
    let failure = "";
    const inputError = new Error("ordinary additional input error");
    const outputError = new Error("ordinary additional output error");
    const fields = {
      label: { type: "string" as const, fieldName: "stored_label", required: false, defaultValue: " Default ", transform: {
        input(value: unknown) { if (failure === "input-error") throw inputError; return typeof value === "string" ? value.trim() : value; },
        output(value: unknown) { if (failure === "output-error") throw outputError; return typeof value === "string" ? `${value}:out` : value; },
      } },
      activatedAt: { type: "date" as const, fieldName: "stored_activation", required: false },
      details: { type: "json" as const, fieldName: "stored_details", required: false },
      revision: { type: "number" as const, fieldName: "stored_revision", required: false, defaultValue: 1.5, onUpdate: () => 2.5 },
    };
    const memory = memoryTables();
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = { ...base, database: db ?? memoryAdapter(memory), plugins: [
      deviceAuthorization(), { id: "ordinary-device-additional-fields", schema: { deviceCode: { fields } } },
    ] };
    if (db) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    const owner = await adapter.create<any>({ model: "user", data: {
      name: "Owner", email: "owner@device-fields.test", emailVerified: false,
      createdAt: new Date(), updatedAt: new Date(),
    } });
    const created = await adapter.create<any>({ model: "deviceCode", data: data("main") });
    const where = [{ field: "id", value: created.id }];
    const cases: unknown[] = [observe("create", created)];
    cases.push(observe("read", await adapter.findOne({ model: "deviceCode", where: [{ field: "userCode", value: created.userCode }] })));
    cases.push(observe("update", await adapter.update({ model: "deviceCode", where, update: { label: " Changed " } })));
    await adapter.incrementOne({ model: "deviceCode", where: [...where, { field: "status", value: "pending" }, { field: "userId", value: null }], increment: {}, set: { userId: owner.id } });
    cases.push(observe("claim", await adapter.findOne({ model: "deviceCode", where })));
    await adapter.update({ model: "deviceCode", where: [...where, { field: "status", value: "pending" }], update: { status: "approved" } });
    cases.push(observe("approve", await adapter.findOne({ model: "deviceCode", where })));
    await adapter.update({ model: "deviceCode", where, update: { label: " Final " } });
    cases.push(observe("consume", await adapter.consumeOne({ model: "deviceCode", where: [
      ...where, { field: "deviceCode", value: created.deviceCode }, { field: "clientId", value: "ordinary-client" },
      { field: "userId", value: owner.id }, { field: "status", value: "approved" },
    ] })));
    for (const name of ["input-error", "output-error"]) {
      failure = name;
      let sameError = false;
      try { await adapter.create({ model: "deviceCode", data: data(name) }); }
      catch (error) {
        const expected = name === "input-error" ? inputError : outputError;
        if (error !== expected) throw error;
        sameError = true;
      }
      failure = "";
      const persisted = !!await adapter.findOne({ model: "deviceCode", where: [{ field: "deviceCode", value: `ordinary-device:${name}` }] });
      cases.push({ name, sameError, persisted });
    }
    backends.push({ backend, cases });
    db?.close();
  }
  const outputInputs: unknown[] = [];
  const serial = betterAuth({ ...base, database: memoryAdapter(memoryTables()), advanced: { database: { generateId: "serial" } }, plugins: [
    deviceAuthorization(), { id: "ordinary-device-reference", schema: { deviceCode: { fields: {
      target: { type: "string", required: false, references: { model: "user", field: "id" }, transform: {
        output(value: unknown) { outputInputs.push(value); return value; },
      } },
    } } } },
  ] });
  const { adapter } = await serial.$context;
  const created = await adapter.create<any>({ model: "deviceCode", data: { ...data("serial-reference"), target: "002" } });
  const read = await adapter.findOne<any>({ model: "deviceCode", where: [{ field: "deviceCode", value: created.deviceCode }] });
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    backends, serialReference: { created: created.target, read: read?.target, outputInputs },
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureDeviceAdditionalFields(), null, 2));
