import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export type StorageMode = "database" | "cache" | "database-cache" | "preserved";
export const fixturePath = "/__test/database-lifecycle";
const createdAt = "2020-01-02T03:04:05.000Z";
const updatedAt = "2021-02-03T04:05:06.000Z";
const expiresAt = "2100-01-02T03:04:05.000Z";

function dates(input: Record<string, unknown>) {
  return Object.fromEntries(Object.entries(input).map(([key, value]) =>
    [key, key.endsWith("At") && typeof value === "string" ? new Date(value) : value]));
}

function sessionView(row: any) {
  if (!row) return null;
  return Object.fromEntries(["id", "token", "userId", "label", "createdAt", "updatedAt", "expiresAt"].map(key =>
    [key, key.endsWith("At") ? new Date(row[key]).toISOString() : row[key] ?? null]));
}

export function createDatabaseLifecycleFixture(mode: StorageMode, database: Database) {
  const secondary = mode !== "database";
  const storesSessions = mode !== "cache";
  const entries = new Map<string, string>();
  const events: any[] = [];
  let control: any = {};

  function rawSessions() {
    return storesSessions ? database.query('SELECT * FROM "session" ORDER BY id').all().map(sessionView) : [];
  }
  function event(kind: string, data: any) {
    events.push({ kind, data: data === undefined ? null : JSON.parse(JSON.stringify(data)),
      databaseSessions: rawSessions().map(row => ({ id: row.id, label: row.label })) });
  }
  const storage = {
    async get(key: string) {
      event("cache.get", { key });
      if (control.cacheFailure === "get") throw new Error("fixture cache get rejected");
      return entries.get(key) ?? null;
    },
    async set(key: string, value: string, _ttl?: number) {
      event("cache.set", { key });
      if (control.cacheFailure === "set") throw new Error("fixture cache set rejected");
      entries.set(key, value);
    },
    async delete(key: string) {
      event("cache.delete", { key });
      if (control.cacheFailure === "delete" || control.failDeleteKey === key) throw new Error("fixture cache delete rejected");
      entries.delete(key);
    },
  };
  function deletionHooks(model: string) {
    return {
      before: async (row: any) => {
        const kind = `${model}.delete.before`;
        event(kind, { id: row.id });
        if (control.fail === `${kind}:${row.id}`) throw new Error("fixture before rejected");
        if (control.cancel === `${model}:${row.id}`) return false;
      },
      after: async (row: any) => {
        const kind = `${model}.delete.after`;
        event(kind, { id: row.id });
        if (control.fail === `${kind}:${row.id}`) throw new Error("fixture after rejected");
      },
    };
  }
  const options = {
    ...(secondary ? { secondaryStorage: storage } : {}),
    session: {
      storeSessionInDatabase: storesSessions,
      preserveSessionInDatabase: mode === "preserved",
      additionalFields: { label: { type: "string" as const, required: false } },
    },
    databaseHooks: {
      user: { delete: deletionHooks("user") },
      account: { delete: deletionHooks("account") },
      session: {
        delete: deletionHooks("session"),
        update: {
          before: async (patch: any) => {
            event("session.update.before", patch);
            if (control.fail === "session.update.before") throw new Error("fixture before rejected");
            if (control.cancel === "session.update") return false;
            if (control.patch) return { data: dates(control.patch) };
          },
          after: async (row: any) => {
            event("session.update.after", sessionView(row));
            if (control.fail === "session.update.after") throw new Error("fixture after rejected");
          },
        },
      },
    },
  };

  function snapshot() {
    return {
      users: database.query('SELECT id FROM "user" ORDER BY id').all().map((row: any) => row.id),
      accounts: database.query('SELECT id FROM "account" ORDER BY id').all().map((row: any) => row.id),
      sessions: rawSessions(),
      cache: [...entries].filter(([key]) => !key.startsWith("active-sessions-")).sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => {
          // Retain malformed cache entries in the observation without repairing them.
          let session = null;
          try { session = sessionView(JSON.parse(value).session); } catch {}
          return { key, session };
        }),
      references: [...entries].filter(([key]) => key.startsWith("active-sessions-")).sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => ({ key, tokens: JSON.parse(value).map((item: any) => item.token).sort() })),
      events: [...events],
    };
  }

  async function route(request: Request, auth: any) {
    if (new URL(request.url).pathname !== fixturePath) return null;
    const body = await request.json();
    const context = await auth.$context;
    const adapter = context.internalAdapter;
    if (body.action === "seed") {
      control = {};
      database.exec("DROP TRIGGER IF EXISTS fixture_reject_session_update");
      database.exec("DROP TRIGGER IF EXISTS fixture_reject_session_batch");
      entries.clear();
      for (const model of ["account", ...(storesSessions ? ["session"] : []), "user"]) {
        await context.adapter.deleteMany({ model, where: [] });
      }
      const user = await context.adapter.create({ model: "user", forceAllowId: true, data: {
        id: "u1", name: "Lifecycle", email: "lifecycle@example.test", emailVerified: true,
        createdAt: new Date(createdAt), updatedAt: new Date(updatedAt),
      } });
      for (const id of ["a1", "a2"]) {
        await context.adapter.create({ model: "account", forceAllowId: true, data: {
          id, accountId: id, providerId: id, userId: "u1", createdAt: new Date(createdAt), updatedAt: new Date(updatedAt),
        } });
      }
      for (const id of ["s1", "s2"]) {
        const session = { id, token: `${id}-token`, userId: "u1", label: `${id}-old`, createdAt, updatedAt, expiresAt };
        if (storesSessions) await context.adapter.create({ model: "session", forceAllowId: true, data: dates(session) });
        if (secondary) entries.set(session.token, JSON.stringify({ session, user }));
      }
      if (secondary) entries.set("active-sessions-u1", JSON.stringify(["s1", "s2"].map(id => ({ token: `${id}-token`, expiresAt: new Date(expiresAt).getTime() }))));
      events.length = 0;
      return Response.json({ ok: true, state: snapshot() });
    }
    if (body.action === "configure") {
      control = body.options ?? {};
      if (control.databaseUpdateFailure) database.exec(`CREATE TRIGGER fixture_reject_session_update BEFORE UPDATE ON "session" BEGIN SELECT RAISE(ABORT, 'fixture session update rejected'); END`);
      if (control.batchWriteFailure) database.exec(`CREATE TRIGGER fixture_reject_session_batch BEFORE ${mode === "preserved" ? "UPDATE" : "DELETE"} ON "session" BEGIN SELECT RAISE(ABORT, 'fixture session batch rejected'); END`);
      if (control.expireSecond && storesSessions) database.query('UPDATE "session" SET expiresAt = ? WHERE id = ?').run(new Date("2000-01-01T00:00:00Z").getTime(), "s2");
      if (control.evictCache) entries.delete("s1-token");
      if (control.missingIndex) entries.delete("active-sessions-u1");
      if (control.corruptSession) entries.set("s1-token", "not-json");
      if (control.deleteDatabaseSession && storesSessions) await context.adapter.delete({ model: "session", where: [{ field: "id", value: "s1" }] });
      events.length = 0;
      return Response.json({ ok: true, state: snapshot() });
    }
    if (body.action === "execute") {
      try {
        let result: any;
        if (body.operation === "delete-user-sessions") result = await adapter.deleteUserSessions("u1");
        else if (body.operation === "delete-user") result = await adapter.deleteUser("u1");
        else if (body.operation === "delete-session") result = await adapter.deleteSession("s1-token");
        else if (body.operation === "update-session") result = await adapter.updateSession("s1-token", dates(body.patch ?? { label: "request" }));
        else throw new Error(`Unknown fixture operation: ${body.operation}`);
        return Response.json({ ok: true, result: body.operation === "update-session" ? sessionView(result) : null, state: snapshot() });
      } catch {
        // The fixture compares error propagation and committed state, not driver-specific error text.
        return Response.json({ ok: false, result: null, state: snapshot() });
      }
    }
    return Response.json({ ok: true, state: snapshot() });
  }
  return { options, route };
}


export async function createStandaloneDatabaseLifecycleFixture(profile: string, baseURL: string) {
  const modes: Record<string, StorageMode> = {
    "database-lifecycle": "database", "database-lifecycle-cache": "cache",
    "database-lifecycle-database": "database-cache", "database-lifecycle-preserved": "preserved",
  };
  const mode = modes[profile];
  if (!mode) throw new Error("Unknown database lifecycle profile");
  const database = new Database(":memory:");
  database.exec("PRAGMA foreign_keys = ON");
  const fixture = createDatabaseLifecycleFixture(mode, database);
  const options = { database, baseURL, secret: "database-lifecycle-fixture-secret-at-least-thirty-two-characters", logger: { disabled: true }, ...fixture.options };
  const auth = betterAuth(options);
  await (await getMigrations(options)).runMigrations();
  return { async handle(request: Request) {
    const path = new URL(request.url).pathname;
    if (path === "/health" || path === "/__health") return Response.json({ status: "ok" });
    if (path === "/__test/reset-state") return Response.json({ success: true });
    return await fixture.route(request, auth) ?? auth.handler(request);
  } };
}
