import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const describe = (value: unknown) => value === undefined ? "undefined" : JSON.stringify(value);

export async function captureDeviceScope() {
  const backends = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = [];
    const inputError = new Error("ordinary scope input error");
    const outputError = new Error("ordinary scope output error");
    let failure = "";
    const fields = { scope: {
      type: "string" as const, required: false,
      defaultValue: " Default ", onUpdate: () => { trace.push("onUpdate"); return " Renewed "; },
      transform: {
        async input(value: string | null | undefined) {
          trace.push(`input:${describe(value)}`);
          if (failure === "input") throw inputError;
          return typeof value === "string" ? value.trim() : value;
        },
        async output(value: string | null | undefined) {
          trace.push(`output:${describe(value)}`);
          if (failure === "output") throw outputError;
          return typeof value === "string" ? `${value}:out` : value;
        },
      },
    } };
    const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    const db = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = {
      database: db ?? memoryAdapter(memory), baseURL: "http://device-fields.test",
      secret: "ordinary-device-fields-contract-at-least-32-characters", logger: { disabled: true }, telemetry: { enabled: false },
      plugins: [deviceAuthorization(), { id: "ordinary-device-scope", schema: { deviceCode: { fields } } }],
    };
    if (db) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    const user: any = await adapter.create({ model: "user", data: { name: "Owner", email: "owner@device-fields.test", emailVerified: false, createdAt: new Date(), updatedAt: new Date() } });
    const create = async (label: string, scope: object) => adapter.create<any>({ model: "deviceCode", data: {
      deviceCode: `ordinary-device:${label}`, userCode: `ordinary-user:${label}`, status: "pending", expiresAt: new Date("2030-01-01T00:00:00Z"), ...scope,
    } });
    const raw = (id: string): any => db ? db.query<any, [string]>("SELECT scope,status,userId FROM deviceCode WHERE id=?").get(id) : memory.deviceCode.find(row => row.id === id);
    const cases: unknown[] = [];
    for (const [name, value] of [["supplied", { scope: " Read " }], ["omitted", {}], ["null", { scope: null }]] as const) {
      trace.length = 0;
      const row = await create(name, value);
      cases.push({ name: `create ${name}`, scope: describe(row.scope), stored: describe(raw(row.id).scope), events: [...trace] });
    }
    const row: any = await adapter.findOne({ model: "deviceCode", where: [{ field: "deviceCode", value: "ordinary-device:supplied" }] });
    const where = [{ field: "id", value: row.id }];
    for (const field of ["deviceCode", "userCode"]) {
      trace.length = 0;
      const found: any = await adapter.findOne({ model: "deviceCode", where: [{ field, value: `ordinary-${field === "deviceCode" ? "device" : "user"}:supplied` }] });
      cases.push({ name: `find ${field}`, scope: describe(found.scope), events: [...trace] });
    }
    for (const [name, update] of [["supplied", { scope: " Changed " }], ["omitted", { lastPolledAt: new Date("2029-01-01T00:00:00Z") }], ["null", { scope: null }]] as const) {
      trace.length = 0;
      const changed: any = await adapter.update({ model: "deviceCode", where, update });
      cases.push({ name: `update ${name}`, scope: describe(changed.scope), stored: describe(raw(row.id).scope), events: [...trace] });
    }
    trace.length = 0;
    const claimed: any = await adapter.incrementOne({ model: "deviceCode", where: [...where, { field: "status", value: "pending" }, { field: "userId", value: null }], increment: {}, set: { userId: user.id } });
    cases.push({ name: "claim", success: !!claimed, scope: describe(claimed?.scope), stored: describe(raw(row.id).scope), events: [...trace] });
    for (const [name, current] of [["conditional update", "pending"], ["conditional no match", "pending"]]) {
      trace.length = 0;
      const updated: any = await adapter.update({ model: "deviceCode", where: [...where, { field: "status", value: current }], update: { status: "approved" } });
      cases.push({ name, success: !!updated, scope: describe(updated?.scope), stored: describe(raw(row.id).scope), events: [...trace] });
    }
    for (const mode of ["input", "output"]) {
      trace.length = 0; failure = mode;
      let sameError = false;
      try { await adapter.update({ model: "deviceCode", where, update: { scope: ` ${mode} value ` } }); }
      catch (error) { sameError = error === (mode === "input" ? inputError : outputError); }
      cases.push({ name: `${mode} error`, sameError, stored: describe(raw(row.id).scope), events: [...trace] });
    }
    backends.push({ backend, cases });
    db?.close();
  }
  return { version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version, backends };
}

if (import.meta.main) console.log(JSON.stringify(await captureDeviceScope(), null, 2));
