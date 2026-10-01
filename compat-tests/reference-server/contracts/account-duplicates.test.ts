import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

for (const sqlite of [false, true]) {
  test(`${sqlite ? "SQLite" : "Memory"} rejects duplicate account identities independently of default query limits`, async () => {
    for (const limit of [undefined, 0, 1]) {
      const database = sqlite ? new Database(":memory:") : undefined;
      const options = {
        database,
        secret: "account-duplicate-oracle-secret-at-least-32-characters",
        baseURL: "http://account.test",
        logger: { disabled: true },
        advanced: { database: { defaultFindManyLimit: limit } },
      };
      if (database) await (await getMigrations(options)).runMigrations();
      const context = await betterAuth(options).$context;
      const user = await context.internalAdapter.createUser({ name: "Owner", email: "owner@example.test", emailVerified: false });
      const providerId = 'provider"quoted';
      for (const token of ["first", "second"]) {
        await context.internalAdapter.createAccount({ providerId, accountId: "subject", userId: user.id, accessToken: token });
      }
      const message = `Multiple accounts match the same accountId for provider ${JSON.stringify(providerId)}. Resolve duplicate account identities before continuing.`;
      for (const method of ["findAccountByKey", "findAccountOwnerByKey"]) {
        await expect(context.internalAdapter[method]({ providerId, accountId: "subject" })).rejects.toThrow(message);
      }
      database?.close();
    }
  });
}

for (const sqlite of [false, true]) {
  test(`${sqlite ? "SQLite" : "Memory"} projects both account rows before duplicate detection or output errors`, async () => {
    const database = sqlite ? new Database(":memory:") : undefined;
    const calls: string[] = [];
    let mode = "ok";
    const options = {
      database,
      secret: "account-duplicate-oracle-secret-at-least-32-characters",
      baseURL: "http://account.test",
      logger: { disabled: true },
      account: { additionalFields: {
        accessToken: { type: "string" as const, transform: { output(value: string) {
          calls.push(value);
          if (mode === "both" || (mode === "second" && value === "second")) throw new Error(`${value} projection failed`);
          return value;
        } } },
      } },
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const context = await betterAuth(options).$context;
    const user = await context.internalAdapter.createUser({ name: "Owner", email: "project@example.test", emailVerified: false });
    for (const token of ["first", "second", "third"]) await context.internalAdapter.createAccount({ providerId: "provider", accountId: "subject", userId: user.id, accessToken: token });
    for (const [next, message] of [["ok", 'Multiple accounts match the same accountId for provider "provider". Resolve duplicate account identities before continuing.'], ["both", "first projection failed"], ["second", "second projection failed"]]) {
      mode = next;
      calls.length = 0;
      await expect(context.internalAdapter.findAccountByKey({ providerId: "provider", accountId: "subject" })).rejects.toThrow(message);
      expect(calls).toEqual(["first", "second"]);
    }
    database?.close();
  });
}
