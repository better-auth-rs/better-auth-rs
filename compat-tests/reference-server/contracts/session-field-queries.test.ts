import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

type Fields = Record<string, unknown>;
type Declaration = NonNullable<NonNullable<BetterAuthOptions["session"]>["additionalFields"]>;
type Backend = "memory" | "sqlite";
const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);
const values = (id: string, token: string, userId: string) => ({
  id, token, userId, expiresAt: date(100), createdAt: date(0), updatedAt: date(0),
  ipAddress: "seed-ip", userAgent: "seed-agent",
});

async function setup(backend: Backend, fields: Declaration, overrides: Partial<BetterAuthOptions> = {}) {
  const memory: Record<string, Fields[]> = { user: [], session: [], account: [], verification: [] };
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  // An application schema can omit the token index; adapter updates still cover every matched row.
  database?.exec(`CREATE TABLE session (id TEXT PRIMARY KEY NOT NULL, token TEXT NOT NULL, userId TEXT NOT NULL, expiresAt TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL, ipAddress TEXT, userAgent TEXT);
    CREATE TABLE user (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, emailVerified INTEGER NOT NULL, image TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL);`);
  const options: BetterAuthOptions = {
    database: database ?? memoryAdapter(memory), baseURL: "http://session-field-queries.test",
    secret: "session-field-query-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, ...overrides,
    session: { additionalFields: fields, ...overrides.session },
  };
  const context = await betterAuth(options).$context;
  return { ...context,
    raw: () => structuredClone(database ? database.query("SELECT * FROM session ORDER BY rowid").all() as Fields[] : memory.session),
    close: () => database?.close(),
  };
}

async function primitiveFailure(operation: Promise<unknown>) {
  try { await operation; }
  catch (error) {
    if (!(error instanceof TypeError)) throw error;
    expect({ name: error.name, message: error.message }).toStrictEqual({ name: "TypeError", message: "No default value" });
    return;
  }
  throw new Error("Session token conversion unexpectedly succeeded");
}

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} Session query errors precede input callbacks and ambiguous joins`, async () => {
    const events: string[] = [];
    const context = await setup(backend, {
      token: { type: "string", references: { model: "user", field: "id" } },
      ipAddress: { type: "string", transform: { input() { events.push("input"); throw new Error("session-input-rejected"); } } },
    }, { advanced: { database: { generateId: "serial" } } });
    const bad = { toString: null };
    try {
      // Reflect.apply supplies a native value that the public TypeScript token annotation excludes.
      await primitiveFailure(Reflect.apply(context.internalAdapter.updateSession, context.internalAdapter, [bad, { ipAddress: "changed" }]));
      expect(events).toStrictEqual([]);
      await primitiveFailure(Reflect.apply(context.adapter.findOne, context.adapter, [{ model: "session", where: [{ field: "token", value: bad }], join: { user: true } }]));
      expect(events).toStrictEqual([]);
      await expect(context.adapter.findOne({ model: "session", where: [{ field: "token", value: "7" }], join: { user: true } })).rejects.toThrow("Multiple foreign keys found for model user and base model session while performing join operation. Only one foreign key is supported.");
      expect(context.raw()).toStrictEqual([]);
    } finally { context.close(); }
  });

  test(`${backend} Session update changes duplicate tokens and projects only the first match`, async () => {
    const events: string[] = [];
    const context = await setup(backend, {
      ipAddress: { type: "string", fieldName: "userAgent", transform: {
        input(value) { events.push("input"); return value; },
        output(value) { events.push("output"); return value; },
      } },
      userAgent: { type: "string", fieldName: "ipAddress" },
    });
    try {
      const create = (data: Fields) => context.adapter.create<Fields>({ model: "session", data, forceAllowId: true });
      const first = await create(values("first", "shared", "1"));
      const second = await create(values("second", "shared", "1"));
      const retained = await create(values("retained", "other", "2"));
      events.length = 0;
      const expectedFirst = { ...first, ipAddress: "changed", updatedAt: date(3) };
      const expectedSecond = { ...second, ipAddress: "changed", updatedAt: date(3) };
      expect(await context.internalAdapter.updateSession("shared", { ipAddress: "changed", updatedAt: date(3) })).toStrictEqual(expectedFirst);
      expect(events).toStrictEqual(["input", "output"]);
      expect(await context.internalAdapter.listSessions("1")).toStrictEqual([expectedFirst, expectedSecond]);
      expect(await context.internalAdapter.listSessions("2")).toStrictEqual([retained]);
      expect(context.raw()).toStrictEqual([
        { ...values("first", "shared", "1"), ipAddress: "seed-agent", userAgent: "changed", updatedAt: date(3) },
        { ...values("second", "shared", "1"), ipAddress: "seed-agent", userAgent: "changed", updatedAt: date(3) },
        { ...values("retained", "other", "2"), ipAddress: "seed-agent", userAgent: "seed-ip" },
      ].map(row => backend === "sqlite" ? { ...row, expiresAt: row.expiresAt.toISOString(), createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString() } : row));
    } finally { context.close(); }
  });

  test(`${backend} Session active queries and preservation use mapped dates and onUpdate`, async () => {
    const events: string[] = [];
    let ending = false;
    const context = await setup(backend, {
      expiresAt: { type: "date", fieldName: "createdAt", transform: { input(value) {
        if (ending) { expect(value).toBeInstanceOf(Date); events.push("expiry-input"); return date(-1_000_000_000); }
        return value;
      } } },
      createdAt: { type: "date", fieldName: "expiresAt" },
      updatedAt: { type: "date", onUpdate() { events.push("updated-on-update"); return date(9); }, transform: { input(value) { events.push("updated-input"); return value; } } },
    }, {
      session: { storeSessionInDatabase: true, preserveSessionInDatabase: true },
      secondaryStorage: { async get() { return null; }, async set() {}, async delete() {}, async getAndDelete() { return null; } },
    });
    try {
      const create = (data: Fields) => context.adapter.create<Fields>({ model: "session", data, forceAllowId: true });
      const active = await create(values("active", "active", "1"));
      const expired = await create({ ...values("expired", "expired", "1"), expiresAt: date(-1_000_000_000), createdAt: date(-1_000_000_000) });
      const retained = await create(values("retained", "other", "2"));
      const activeRows = () => context.adapter.findMany({ model: "session", where: [{ field: "userId", value: "1" }, { field: "expiresAt", operator: "gt", value: new Date() }] });
      expect(await activeRows()).toStrictEqual([active]);
      events.length = 0;
      ending = true;
      await context.internalAdapter.deleteUserSessions("1");
      expect(events).toStrictEqual(["expiry-input", "updated-on-update", "updated-input"]);
      const ended = { ...active, expiresAt: date(-1_000_000_000), updatedAt: date(9) };
      expect(await context.adapter.findOne({ model: "session", where: [{ field: "token", value: "active" }] })).toStrictEqual(ended);
      expect(await context.adapter.findMany({ model: "session", where: [{ field: "userId", value: "1" }] })).toStrictEqual([ended, expired]);
      // Kysely resolves WHERE aliases twice, so SQLite still filters the unchanged public createdAt.
      expect(await activeRows()).toStrictEqual(backend === "sqlite" ? [ended] : []);
      expect(await context.adapter.findMany({ model: "session", where: [{ field: "userId", value: "2" }] })).toStrictEqual([retained]);
      expect(context.raw()).toStrictEqual([
        { ...values("active", "active", "1"), createdAt: date(-1_000_000_000), expiresAt: date(0), updatedAt: date(9) },
        { ...values("expired", "expired", "1"), createdAt: date(-1_000_000_000), expiresAt: date(-1_000_000_000) },
        { ...values("retained", "other", "2"), createdAt: date(100), expiresAt: date(0) },
      ].map(row => backend === "sqlite" ? { ...row, expiresAt: row.expiresAt.toISOString(), createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString() } : row));
      if (backend === "memory") {
        ending = false;
        await create(values("later-active", "later-active", "1"));
        await create({ ...values("later-invalid", "later-invalid", "1"), expiresAt: { toString: null } });
        const before = context.raw();
        events.length = 0;
        ending = true;
        await primitiveFailure(context.internalAdapter.deleteUserSessions("1"));
        expect(events).toStrictEqual(["expiry-input", "updated-on-update", "updated-input"]);
        expect(context.raw()).toStrictEqual(before);
      }
    } finally { context.close(); }
  });

  for (const failQuery of [false, true]) test(`${backend} Session reentrant ${failQuery ? "failed query restores" : "read replaces"} ID input policy`, async () => {
    const events: Fields[] = [];
    let enabled = false;
    const context: Awaited<ReturnType<typeof setup>> = await setup(backend, {
      token: { type: "string", references: { model: "user", field: "id" } },
      label: { type: "string", fieldName: "ipAddress", transform: { async input(value) {
        if (enabled) {
          events.push({ kind: "input", value });
          const session = await context.adapter.findOne({ model: "session", where: [{ field: "token", value: "7" }] });
          events.push({ kind: "read", session });
          if (failQuery) {
            await primitiveFailure(Reflect.apply(context.adapter.findOne, context.adapter, [{ model: "session", where: [{ field: "token", value: { toString: null } }] }]));
            events.push({ kind: "caught", name: "TypeError", message: "No default value" });
          }
        }
        return value;
      } } },
      id: { type: "string", defaultValue: "1", transform: {
        input() { throw new Error("Application ID input must be replaced"); },
        output() { throw new Error("Application ID output must be replaced"); },
      } },
    }, { advanced: { database: { generateId: "serial" } } });
    try {
      const before = { ...values("1", "7", "1"), ipAddress: "seed-label", label: "seed-label" };
      expect(await context.adapter.create({ model: "session", forceAllowId: true, data: { ...values("1", "7", "1"), label: "seed-label" } })).toStrictEqual(before);
      enabled = true;
      const id = failQuery ? "100" : "00100";
      const expected = { ...before, id, ipAddress: "outer", label: "outer", updatedAt: date(3) };
      expect(await context.internalAdapter.updateSession("7", { label: "outer", id: "00100", updatedAt: date(3) })).toStrictEqual(expected);
      expect(events).toStrictEqual([
        { kind: "input", value: "outer" }, { kind: "read", session: before },
        ...(failQuery ? [{ kind: "caught", name: "TypeError", message: "No default value" }] : []),
      ]);
      expect(await context.adapter.findOne({ model: "session", where: [{ field: "token", value: "7" }] })).toStrictEqual(expected);
      const stored = { ...values(id, "7", "1"), ipAddress: "outer", updatedAt: date(3) };
      expect(context.raw()).toStrictEqual([backend === "sqlite"
        ? { ...stored, expiresAt: date(100).toISOString(), createdAt: date(0).toISOString(), updatedAt: date(3).toISOString() }
        : { ...stored, id: failQuery ? 100 : "00100", token: 7, userId: 1 },
      ]);
    } finally { context.close(); }
  });

  for (const mode of ["normal", "output-failure", "cancel"] as const) test(`${backend} Session delete operation order with ${mode}`, async () => {
    const events: Fields[] = [];
    let enabled = false;
    const context = await setup(backend, {
      ipAddress: { type: "string", transform: { output(value) {
        if (enabled) {
          events.push({ kind: "output", value });
          if (mode === "output-failure") throw new Error("session-output-rejected");
        }
        return value;
      } } },
    }, { databaseHooks: { session: { delete: {
      async before(session: unknown) {
        events.push({ kind: "before-delete", session: structuredClone(session) });
        if (mode === "cancel") return false;
      },
      async after(session: unknown) { events.push({ kind: "after-delete", session: structuredClone(session) }); },
    } } } });
    try {
      const candidate = values("candidate", "candidate", "1");
      const retained = values("retained", "retained", "2");
      for (const data of [candidate, retained]) {
        expect(await context.adapter.create({ model: "session", data, forceAllowId: true })).toStrictEqual(data);
      }
      const findMany = context.adapter.findMany;
      context.adapter.findMany = async <T>(args: Parameters<typeof findMany>[0]): Promise<T[]> => {
        events.push({ kind: "query", operation: "findMany", model: args.model });
        return findMany<T>(args);
      };
      const deleteRow = context.adapter.delete;
      context.adapter.delete = async <T>(args: Parameters<typeof deleteRow>[0]): Promise<void> => {
        events.push({ kind: "query", operation: "delete", model: args.model });
        return deleteRow<T>(args);
      };
      enabled = true;
      await context.internalAdapter.deleteSession("candidate");
      expect(events).toStrictEqual([
        { kind: "query", operation: "findMany", model: "session" },
        { kind: "output", value: "seed-ip" },
        ...(mode === "output-failure" ? [] : [{ kind: "before-delete", session: candidate }]),
        ...(mode === "normal" ? [
          { kind: "query", operation: "delete", model: "session" },
          { kind: "after-delete", session: candidate },
        ] : []),
      ]);
      expect(context.raw()).toStrictEqual((mode === "normal" ? [retained] : [candidate, retained]).map(row => backend === "sqlite"
        ? { ...row, expiresAt: row.expiresAt.toISOString(), createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString() }
        : row));
    } finally { context.close(); }
  });
}
for (const backend of ["memory", "sqlite"] as const) for (const joins of [false, true]) {
  test(`${backend} raw Session dates survive reads, ${joins ? "native" : "fallback"} joins, and delete hooks`, async () => {
    const events: Fields[] = [];
    const expected = {
      ...values("raw-session", "raw-token", "raw-user"),
      createdAt: "created-is-not-a-date",
    };
    const context = await setup(backend, {
      createdAt: { type: "string" },
      expiresAt: { type: "string", transform: { output(value) {
        expect(value).toBe("expiry-is-not-a-date");
        events.push({ kind: "output", field: "expiresAt", value });
        return date(100);
      } } },
    }, {
      advanced: { database: { joins, generateId: ({ model }: { model: string }) => `raw-${model}` } },
      databaseHooks: { session: { delete: {
        async before(session: unknown) {
          expect(session).toStrictEqual(expected);
          events.push({ kind: "before-delete", session: structuredClone(session) });
        },
        async after(session: unknown) {
          expect(session).toStrictEqual(expected);
          events.push({ kind: "after-delete", session: structuredClone(session) });
        },
      } } },
    });
    try {
      const user = await context.adapter.create<Fields>({ model: "user", forceAllowId: true, data: {
        id: "raw-user", name: "Raw dates owner", email: "raw-dates@example.test", emailVerified: true,
        image: null, createdAt: date(0), updatedAt: date(0),
      } });
      expect(await context.adapter.create<Fields>({ model: "session", forceAllowId: true, data: {
        ...expected, expiresAt: "expiry-is-not-a-date",
      } })).toStrictEqual(expected);
      expect(await context.adapter.findOne({ model: "session", where: [{ field: "token", value: "raw-token" }] })).toStrictEqual(expected);
      expect(await context.internalAdapter.listSessions("raw-user")).toStrictEqual([expected]);
      expect(await context.adapter.findOne({ model: "session", where: [{ field: "token", value: "raw-token" }], join: { user: true } })).toStrictEqual({ ...expected, user });
      expect(await context.adapter.findMany({ model: "session", where: [{ field: "token", value: ["raw-token"], operator: "in" }], join: { user: true } })).toStrictEqual([{ ...expected, user }]);
      expect(await context.internalAdapter.findSession("raw-token")).toStrictEqual({ session: expected, user });
      expect(context.raw()).toStrictEqual([{
        ...expected, expiresAt: "expiry-is-not-a-date",
        ...(backend === "sqlite" ? { updatedAt: date(0).toISOString() } : {}),
      }]);
      events.length = 0;
      await context.internalAdapter.deleteSession("raw-token");
      expect(events).toStrictEqual([
        { kind: "output", field: "expiresAt", value: "expiry-is-not-a-date" },
        { kind: "before-delete", session: expected },
        { kind: "after-delete", session: expected },
      ]);
      expect(context.raw()).toStrictEqual([]);
      expect(await context.adapter.findOne({ model: "session", where: [{ field: "token", value: "raw-token" }] })).toBeNull();
      expect(await context.internalAdapter.listSessions("raw-user")).toStrictEqual([]);
      expect(await context.adapter.findOne({ model: "user", where: [{ field: "id", value: "raw-user" }] })).toStrictEqual(user);
    } finally { context.close(); }
  });
}
