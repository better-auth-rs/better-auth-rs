import { Database } from "bun:sqlite";

import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { serializeSignedCookie } from "better-call";
export { runWithTransaction, queueAfterTransactionHook } from "@better-auth/core/context";

export type Mode = "database" | "cache" | "database-cache";
export type Model = "account" | "verification";
export const modes: Mode[] = ["database", "cache", "database-cache"];
export const secret = "account-verification-field-fixture-secret-thirty-two-characters";
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const present = (value: any) => value === undefined ? "<undefined>" : value;

export async function fixture(mode: Mode) {
  const database = new Database(":memory:");
  database.exec("PRAGMA foreign_keys = ON");
  const entries = new Map<string, string>();
  const events: any[] = [];
  const control: { fail?: string; patch?: Record<string, unknown> } = {};
  const stored = (model: Model) => model === "verification" && mode === "cache" ? [] : database.query(`SELECT * FROM "${model}" ORDER BY id`).all();
  function event(kind: string, value?: unknown) {
    events.push({ kind, value: present(value) });
    if (control.fail === kind) throw new Error(`fixture ${kind} rejected`);
  }
  function fields(model: Model) {
    return {
      label: {
        type: "string" as const, required: false, fieldName: "stored_label",
        defaultValue() { event(`${model}.default`); return "default"; },
        onUpdate() { event(`${model}.onUpdate`); return "updated"; },
        transform: {
          input(value: unknown) { event(`${model}.input`, value); return `${String(value)}:in`; },
          output(value: unknown) { event(`${model}.output`, value); return `${String(value)}:out`; },
        },
      },
      hidden: { type: "string" as const, required: false, returned: false, defaultValue: "secret" },
      protected: { type: "string" as const, required: false, input: false, defaultValue: "server" },
    };
  }
  function hooks(model: Model) {
    return Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
      before(data: any) {
        event(`${model}.${operation}.before`, { label: present(data.label), hidden: present(data.hidden), protected: present(data.protected) });
        if (control.patch) return { data: control.patch };
      },
      after(data: any) {
        event(`${model}.${operation}.after`, data === null ? null : {
          label: present(data.label), hidden: present(data.hidden), protected: present(data.protected),
          rows: stored(model).length,
          cacheLabel: present(entries.has("verification:code") ? JSON.parse(entries.get("verification:code")!).label : undefined),
        });
      },
    }]));
  }
  const storage = {
    async get(key: string) { event("cache.get", key); return entries.get(key) ?? null; },
    async set(key: string, value: string) { event("cache.set", key); entries.set(key, value); },
    async delete(key: string) { event("cache.delete", key); entries.delete(key); },
    async getAndDelete(key: string) {
      event("cache.getAndDelete", key);
      const value = entries.get(key) ?? null;
      entries.delete(key);
      return value;
    },
  };
  const options = {
    database, baseURL: "http://localhost:3000", secret,
    logger: { disabled: true }, rateLimit: { enabled: false },
    ...(mode === "database" ? {} : { secondaryStorage: storage }),
    session: { storeSessionInDatabase: true },
    account: { additionalFields: fields("account") },
    verification: { additionalFields: fields("verification"), storeInDatabase: mode !== "cache", disableCleanup: true },
    databaseHooks: { account: hooks("account"), verification: hooks("verification") },
  };
  const auth = betterAuth(options);
  await (await getMigrations(options)).runMigrations();
  const context = await auth.$context;
  const user = await context.adapter.create({ model: "user", forceAllowId: true, data: {
    id: "u1", name: "Fields", email: "fields@example.com", emailVerified: true,
    createdAt: new Date("2020-01-01T00:00:00Z"), updatedAt: new Date("2020-01-01T00:00:00Z"),
  } });
  const create = (model: Model, input: Record<string, unknown> = {}) => model === "account"
    ? context.internalAdapter.linkAccount({ userId: user.id, providerId: "mock", accountId: "provider-account", accessToken: "private-token", password: "private-password", scope: "read, write", ...input })
    : context.internalAdapter.createVerificationValue({ identifier: "code", value: "123456", expiresAt, ...input });
  const update = (model: Model, id: string, input: Record<string, unknown> = {}) => model === "account"
    ? context.internalAdapter.updateAccount(id, { accessToken: "refreshed-token", ...input })
    : context.internalAdapter.updateVerificationByIdentifier("code", { value: "654321", ...input });
  const read = (model: Model) => model === "account"
    ? context.internalAdapter.findAccounts(user.id).then((rows: any[]) => rows[0] ?? null)
    : context.internalAdapter.findVerificationValue("code");
  function snapshot() {
    return {
      accounts: stored("account").map((row: any) => ({ label: row.stored_label, hidden: row.hidden, protected: row.protected })),
      verifications: stored("verification").map((row: any) => ({ label: row.stored_label, hidden: row.hidden, protected: row.protected, value: row.value })),
      cached: entries.has("verification:code") ? JSON.parse(entries.get("verification:code")!) : null,
      events: [...events],
    };
  }
  async function listAccounts() {
    const session = await context.internalAdapter.createSession(user.id);
    const signed = await serializeSignedCookie("better-auth.session_token", session.token, secret);
    const response = await auth.handler(new Request("http://localhost:3000/api/auth/list-accounts", { headers: { cookie: signed.split(";")[0] } }));
    return { status: response.status, body: await response.json() };
  }
  return { database, context, create, update, read, snapshot, events, control, listAccounts, close: () => database.close() };
}
