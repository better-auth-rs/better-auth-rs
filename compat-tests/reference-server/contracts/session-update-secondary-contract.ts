import { expect, spyOn, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { getWithHooks } from "../node_modules/better-auth/dist/db/with-hooks.mjs";

type Fields = Record<string, unknown>;
const date = (offset: number) => new Date(4_102_444_800_000 + offset * 1000);

for (const backend of ["memory", "sqlite"] as const) {
  for (const writeDatabase of [false, true]) {
    for (const mode of ["values", "empty", "continue"] as const) {
      for (const nullish of !writeDatabase && mode === "values" ? [undefined, null] : [undefined]) {
        test(`${backend} secondary ${writeDatabase} ${mode} ${String(nullish)} preserves actual data, date defaults, keys, and TTL`, async () => {
          const memory: Record<string, Fields[]> = { user: [], session: [], account: [], verification: [] };
          const database = backend === "sqlite" ? new Database(":memory:") : undefined;
          const options = {
            database: database ?? memoryAdapter(memory),
            baseURL: "http://secondary-update.test", secret: "secondary-update-fields-at-least-32-characters",
            logger: { disabled: true }, telemetry: { enabled: false },
          };
          const entries = new Map<string, string>();
          const writes: [string, string, number | undefined][] = [];
          const observations: Fields[] = [];
          const originals: Fields[] = [];
          const after: unknown[] = [];
          const originalDate = date(1);
          const hooks = (first: boolean) => ({ session: { update: {
            before(original: Fields) {
              expect(original.updatedAt).toBe(originalDate);
              originals.push(original);
              observations.push(structuredClone(original));
              if (first) {
                original.token = "in-place";
                if (mode === "values") return { data: {
                  ipAddress: undefined, userAgent: 7, expiresAt: nullish, createdAt: date(4),
                  ...(!writeDatabase ? { updatedAt: nullish } : {}),
                } };
                if (mode === "empty") return { data: {} };
              } else {
                expect(original.ipAddress).toBe("requested");
                expect(original.userAgent).toBe("requested");
                Object.assign(original, { token: "late", ipAddress: "late", userAgent: "late", updatedAt: date(3) });
              }
            },
            after(value: unknown) { after.push(structuredClone(value)); },
          } } });
          let now: ReturnType<typeof spyOn> | undefined;
          try {
            if (database) await (await getMigrations(options)).runMigrations();
            const base = await betterAuth(options).$context;
            const user = await base.adapter.create({ model: "user", forceAllowId: true, data: {
              id: "owner", name: "Owner", email: "owner@secondary-update.test", emailVerified: true,
              createdAt: date(0), updatedAt: date(0),
            } });
            const before = await base.adapter.create<Fields>({ model: "session", forceAllowId: true, data: {
              id: "record", token: "original", userId: "owner", ipAddress: "stored", userAgent: "stored",
              expiresAt: date(100), createdAt: date(0), updatedAt: date(0),
            } });
            const storage = () => structuredClone(database ? database.query("SELECT * FROM session").all() : memory.session);
            const rawBefore = storage();
            entries.set("original", JSON.stringify({ session: before, user }));
            const context = await betterAuth({ ...options,
              secondaryStorage: {
                async get(key: string) { return entries.get(key) ?? null; },
                async set(key: string, value: string, ttl?: number) { writes.push([key, value, ttl]); entries.set(key, value); },
                async delete(key: string) { entries.delete(key); },
              },
              session: { storeSessionInDatabase: writeDatabase },
              plugins: [{ id: "secondary-update", init: () => ({ options: { databaseHooks: hooks(true) } }) }],
              databaseHooks: hooks(false),
            }).$context;
            now = spyOn(Date, "now").mockReturnValue(date(0).getTime());
            const result = await context.internalAdapter.updateSession("original", {
              ipAddress: "requested", userAgent: "requested", updatedAt: originalDate, expiresAt: date(50),
            });
            const cached: Fields = { ...before, token: mode === "continue" ? "late" : "in-place" };
            const expiration = mode === "values" ? 100 : 50;
            if (mode === "values") {
              Object.assign(cached, { ipAddress: undefined, userAgent: 7 });
              if (writeDatabase) cached.updatedAt = date(1);
            } else Object.assign(cached, {
              ipAddress: mode === "empty" ? "requested" : "late",
              userAgent: mode === "empty" ? "requested" : "late",
              updatedAt: date(mode === "empty" ? 1 : 3), expiresAt: date(50),
            });
            const stored: Fields = writeDatabase ? { ...cached } : { ...before };
            if (writeDatabase && mode === "values") Object.assign(stored, {
              ipAddress: "stored", userAgent: backend === "sqlite" ? "7" : 7, createdAt: date(4),
            });
            expect(result).toStrictEqual(writeDatabase ? stored : cached);
            expect(after).toStrictEqual([result, result]);
            expect(await base.adapter.findOne({ model: "session", where: [{ field: "id", value: "record" }] })).toStrictEqual(stored);
            const rawExpected = writeDatabase ? Object.fromEntries(Object.entries(stored).map(([key, value]) => [key, database && value instanceof Date ? value.toISOString() : value])) : rawBefore[0];
            expect(storage()).toStrictEqual([rawExpected]);
            expect([...entries.keys()]).toStrictEqual(["original", "active-sessions-owner"]);
            expect(entries.get("original")).toBe(JSON.stringify({ session: cached, user }));
            expect(entries.get("active-sessions-owner")).toBe(JSON.stringify([{ token: "original", expiresAt: date(expiration).getTime() }]));
            expect(writes).toStrictEqual([
              ["original", entries.get("original"), expiration],
              ["active-sessions-owner", entries.get("active-sessions-owner"), expiration],
            ]);
            expect(originals[0]).toBe(originals[1]);
            const original = { ipAddress: "requested", userAgent: "requested", updatedAt: date(1), expiresAt: date(50) };
            expect(observations).toStrictEqual([original, { ...original, token: "in-place" }]);
          } finally { now?.mockRestore(); database?.close(); }
        });
      }
    }
  }
}

test("Session custom writer receives native aliases and own undefined before serialization", async () => {
  const marker = { native: undefined };
  const context = await betterAuth({
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    baseURL: "http://writer-identity.test", secret: "session-update-writer-identity-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    databaseHooks: { session: { update: { before(data) {
      expect(data.ipAddress).toBe("requested");
      expect(data.userAgent).toBe("requested");
      return { data: { first: marker, second: marker, ipAddress: undefined, userAgent: 7 } };
    } } } },
  }).$context;
  const result = await getWithHooks(context.adapter, {
    options: context.options,
    hooks: [{ source: "user", hooks: context.options.databaseHooks }],
  }).updateWithHooks(
    { ipAddress: "requested", userAgent: "requested" }, [{ field: "token", value: "original" }], "session",
    { executeMainFn: false, async fn(data: Fields) {
      expect(data.first).toBe(marker);
      expect(data.second).toBe(marker);
      expect(Object.hasOwn(data, "ipAddress")).toBe(true);
      expect(data.ipAddress).toBeUndefined();
      expect(data.userAgent).toBe(7);
      expect(Object.keys(data).length).toBe(4);
      return { token: "unchanged" };
    } },
  );
  expect(result).toStrictEqual({ token: "unchanged" });
});
