import { expect } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { getWithHooks } from "../node_modules/better-auth/dist/db/with-hooks.mjs";

export type Backend = "memory" | "sqlite";
export type Fields = Record<string, unknown>;
export const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);
export const row = (id: unknown, accountId = "subject", accessToken = "before"): Fields => ({
  id, accountId, providerId: "provider", userId: "owner", accessToken,
  refreshToken: "refresh", idToken: "id-token", accessTokenExpiresAt: date(10),
  refreshTokenExpiresAt: date(20), scope: "read", password: "password",
  createdAt: date(0), updatedAt: date(0),
});
export const retained = () => row("retained", "retained-subject", "retained");
export function withoutId(value: Fields): Fields {
  const copy = { ...value };
  delete copy.id;
  return copy;
}

export const idSentinel = () => ({
  type: "string" as const, fieldName: "ignored_id",
  transform: {
    input() { throw new TypeError("application ID input must be replaced"); },
    output() { throw new TypeError("application ID output must be replaced"); },
  },
});

export function generator(events: unknown[], failure?: TypeError) {
  return ({ model }: { model: string }) => {
    events.push(["generate", model]);
    if (failure) throw failure;
    return "generated";
  };
}

export async function created(operation: () => Promise<unknown>, expected: Fields | null) {
  if (expected) {
    expect(await operation()).toStrictEqual(expected);
  } else {
    let caught: unknown;
    try { await operation(); } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(Error);
    const error = caught as Error & { code?: string; errno?: number };
    expect({ name: error.name, message: error.message, code: error.code, errno: error.errno }).toStrictEqual({
      name: "SQLiteError", message: "NOT NULL constraint failed: account.id",
      code: "SQLITE_CONSTRAINT_NOTNULL", errno: 1299,
    });
  }
}

export async function setup(backend: Backend) {
  const memory: Record<string, Fields[]> = { user: [], account: [], session: [], verification: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options: BetterAuthOptions = {
    database: sqlite ?? memoryAdapter(memory), baseURL: "http://account-id-input.test",
    secret: "account-id-input-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
  };
  if (sqlite) await (await getMigrations(options)).runMigrations();
  const writer = await betterAuth(options).$context;
  await writer.adapter.create({ model: "user", forceAllowId: true, data: {
    id: "owner", name: "Owner", email: "owner@account-id-input.test", emailVerified: true,
    image: null, createdAt: date(0), updatedAt: date(0),
  } });
  const seed = (data: Fields) => writer.adapter.create({ model: "account", data, forceAllowId: true });
  await seed(retained());
  return {
    seed,
    async reader(extra: BetterAuthOptions, events: unknown[]) {
      const hooks = { account: {
        create: { after(value: unknown) { events.push(["after-create", value]); } },
        update: { after(value: unknown) { events.push(["after-update", value]); } },
      } };
      const configured = { ...options, ...extra };
      const context = await betterAuth(configured).$context;
      return { context, withHooks: getWithHooks(context.adapter, { options: configured, hooks: [{ source: "user", hooks }] }) };
    },
    storage: () => sqlite ? sqlite.query("SELECT * FROM account ORDER BY rowid").all() : memory.account,
    stored: (value: Fields) => sqlite ? Object.fromEntries(Object.entries(value).map(([key, value]) => [
      key, value instanceof Date ? value.toISOString() : key === "id" && typeof value === "number" ? String(value) : value,
    ])) : value,
    close: () => sqlite?.close(),
  };
}
