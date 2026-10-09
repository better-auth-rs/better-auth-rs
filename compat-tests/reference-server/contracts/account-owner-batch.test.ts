import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

for (const backend of ["memory", "sqlite"] as const) {
  for (const asynchronous of [false, true]) {
    for (const reject of [false, true]) {
      test(`${backend} ordinary account join: async=${asynchronous}, reject=${reject}`, async () => {
        let armed = false;
        const events: string[] = [];
        const ownerB = Promise.withResolvers<void>();
        const phases = new Map(
          ["access:A", "access:B", "refresh:A", "refresh:B"].map(key => [key, {
            started: Promise.withResolvers<void>(),
            result: Promise.withResolvers<unknown>(),
          }]),
        );
        const phase = (key: string) => {
          const value = phases.get(key);
          if (!value) throw new Error(`Missing ordinary field phase ${key}`);
          return value;
        };
        const original = new Error("ordinary token output failed");
        const output = (name: string) => (value: unknown) => {
          if (!armed) return value;
          const key = `${name}:${value}`;
          events.push(key);
          if (asynchronous) {
            phase(key).started.resolve();
            return phase(key).result.promise;
          }
          if (reject && key === "access:A") throw original;
          return `${value}:${name}`;
        };
        const database = backend === "sqlite" ? new Database(":memory:") : undefined;
        const options = {
          database: database ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
          baseURL: "http://account-owner-batch.test",
          secret: "ordinary-account-field-fixture-secret-32-characters",
          logger: { disabled: true },
          user: { additionalFields: { name: { type: "string" as const, transform: {
            output(value: unknown) {
              if (armed) {
                events.push(`user:${value}`);
                if (value === "B") ownerB.resolve();
              }
              return value;
            },
          } } } },
          account: { additionalFields: {
            accessToken: { type: "string" as const, transform: { output: output("access") } },
            refreshToken: { type: "string" as const, transform: { output: output("refresh") } },
          } },
        };
        try {
          if (database) await (await getMigrations(options)).runMigrations();
          const { adapter } = await betterAuth(options).$context;
          for (const name of ["A", "B"]) {
            const user = await adapter.create({ model: "user", data: {
              name, email: `${name.toLowerCase()}@account-owner-batch.test`, emailVerified: true,
              createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
            } });
            await adapter.create({ model: "account", data: {
              userId: user.id, providerId: "ordinary", accountId: `ordinary-${name}`,
              accessToken: name, refreshToken: name,
              createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
            } });
          }
          armed = true;
          // Distinct accounts exercise the shared join projection without an identity collision.
          const pending = adapter.findMany({
            model: "account", sortBy: { field: "accountId", direction: "asc" }, join: { user: true },
          }).then(rows => ({ rows }), error => ({ error }));
          if (asynchronous) {
            await Promise.all([phase("access:A").started.promise, phase("access:B").started.promise]);
            if (reject) phase("access:A").result.reject(original);
            phase("access:B").result.resolve("B:access");
            await phase("refresh:B").started.promise;
            phase("refresh:B").result.resolve("B:refresh");
            await ownerB.promise;
            expect(events).toStrictEqual(["access:A", "access:B", "refresh:B", "user:B"]);
            if (!reject) {
              phase("access:A").result.resolve("A:access");
              await phase("refresh:A").started.promise;
              phase("refresh:A").result.resolve("A:refresh");
            }
          }
          const outcome = await pending;
          // Promise.all may reject before a successful peer finishes its owner projection.
          await ownerB.promise;
          if (reject) {
            expect("error" in outcome && outcome.error).toBe(original);
            expect(events).toStrictEqual(["access:A", "access:B", "refresh:B", "user:B"]);
          } else {
            if (!("rows" in outcome)) throw outcome.error;
            expect(outcome.rows.map((row: any) => ({
              access: row.accessToken, refresh: row.refreshToken, owner: row.user.name,
            }))).toStrictEqual([
              { access: "A:access", refresh: "A:refresh", owner: "A" },
              { access: "B:access", refresh: "B:refresh", owner: "B" },
            ]);
            expect(events).toStrictEqual(asynchronous
              ? ["access:A", "access:B", "refresh:B", "user:B", "refresh:A", "user:A"]
              : ["access:A", "access:B", "refresh:A", "refresh:B", "user:A", "user:B"]);
          }
        } finally {
          database?.close();
        }
      });
    }
  }
}

test("Memory Account owner number selectors match ordinary reads with native joins", async () => {
  const date = new Date("2030-01-01T00:00:00.000Z");
  const user = {
    id: "selector-owner", name: "Selector owner", email: "selector-owner@example.test",
    emailVerified: true, image: null, createdAt: date, updatedAt: date,
  };
  const account = {
    id: "numeric-provider", accountId: "shared-subject", providerId: 1, userId: user.id,
    accessToken: null, refreshToken: null, idToken: null, accessTokenExpiresAt: null,
    refreshTokenExpiresAt: null, scope: null, password: null, createdAt: date, updatedAt: date,
  };
  const data = {
    user: [user], session: [], verification: [],
    account: [account, { ...account, id: "string-decoy", providerId: "01" }],
  };
  const before = structuredClone(data);
  for (const joins of [false, true]) {
    const events: unknown[] = [];
    const context = await betterAuth({
      database: memoryAdapter(data),
      baseURL: "http://account-owner-selector.test",
      secret: "ordinary-account-selector-secret-32-characters",
      logger: { disabled: true },
      advanced: { database: { joins } },
      account: { additionalFields: { providerId: {
        type: "number", transform: { input(value) { events.push(["provider-input", value]); return value; } },
      } } },
    }).$context;
    const selector = { providerId: "01", accountId: "shared-subject" };
    expect(await context.internalAdapter.findAccountByKey(selector)).toStrictEqual(account);
    expect(await context.internalAdapter.findAccountOwnerByKey(selector)).toStrictEqual({
      kind: "owned", user, account,
    });
    expect(events).toStrictEqual([]);
    expect(data).toStrictEqual(before);
  }
});
