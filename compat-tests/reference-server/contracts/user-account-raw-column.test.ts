import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import cases from "../../../tests/fixtures/user-account-raw-column-cases.json";
import { email, observe, owner, revive, secret } from "./user-runtime-contract";

for (const joins of [false, true]) {
  test(`SQLite User/Account raw columns reach callbacks before typed decoding, joins=${joins}`, async () => {
    const database = new Database(":memory:");
    const base = { database, secret, baseURL: "http://localhost:3000", logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } } };
    try {
      await (await getMigrations(base)).runMigrations();
      const writer = await betterAuth(base).$context;
      await writer.internalAdapter.createUser({ id: owner, name: "Owner", email, emailVerified: false });
      await writer.internalAdapter.createAccount({ id: "runtime-account", userId: owner, providerId: "provider", accountId: "subject", accessToken: "stored-token", password: "stored-password" });
      database.query('UPDATE "user" SET "emailVerified" = ?, "createdAt" = ?').run("stored-boolean", "not-a-date");
      database.query('UPDATE "account" SET "accessTokenExpiresAt" = ?').run("not-a-date");
      const storage = () => ({ user: database.query('SELECT * FROM "user"').all(), account: database.query('SELECT * FROM "account"').all() });
      const before = storage();
      for (const reject of [false, true]) {
        const events: unknown[] = [];
        const fields = (model: string) => Object.fromEntries(cases.fields.filter(field => field.model === model).map(field => [field.name, {
          type: field.type, required: false, transform: { output(value: unknown) {
            const label = `${model}.${field.name}`;
            events.push([label, observe(value)]);
            if (reject && label === "account.accessTokenExpiresAt") throw new Error("raw-column-stop");
            return "replacement" in field ? revive(field.replacement) : value;
          } },
        }]));
        const context = await betterAuth({ ...base, user: { additionalFields: fields("user") }, account: { additionalFields: fields("account") } }).$context;
        for (const operation of cases.operations) {
          events.length = 0;
          const expected: unknown[] = [];
          let failed = false;
          for (const model of operation.models) {
            for (const field of cases.fields.filter(field => field.model === model)) {
              const label = `${model}.${field.name}`;
              expected.push([label, field.raw]);
              if (reject && label === "account.accessTokenExpiresAt") { failed = true; break; }
            }
            if (failed) break;
          }
          const execute = async (): Promise<[string, any][]> => {
            if (operation.name === "user") return [["user", await context.internalAdapter.findUserById(owner)]];
            if (operation.name === "account") return [["account", await context.internalAdapter.findAccountByKey({ providerId: "provider", accountId: "subject" })]];
            if (operation.name === "owner") {
              const result = await context.internalAdapter.findAccountOwnerByKey({ providerId: "provider", accountId: "subject" });
              return [["account", result!.account], ["user", result!.user]];
            }
            const result = await context.internalAdapter.findUserByEmail(email, { includeAccounts: true });
            expect(result!.accounts.length).toBe(1);
            return [["user", result!.user], ["account", result!.accounts[0]]];
          };
          if (failed) {
            await expect(execute()).rejects.toThrow("raw-column-stop");
          } else {
            for (const [model, row] of await execute()) {
              for (const field of cases.fields.filter(field => field.model === model)) expect(observe(row[field.name])).toStrictEqual(field.expected);
            }
          }
          expect(events).toStrictEqual(expected);
          expect(storage()).toStrictEqual(before);
        }
      }
    } finally {
      database.close();
    }
  });
}
