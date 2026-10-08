import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import cases from "../../../tests/fixtures/user-account-raw-column-cases.json";
import { email, observe, owner, revive, secret } from "./user-runtime-contract";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

async function seedRows(options: any) {
  const writer = await betterAuth(options).$context;
  const createdAt = new Date(cases.seedDate);
  const updatedAt = new Date(cases.seedDate);
  await writer.internalAdapter.createUser({ id: owner, name: "Owner", email, emailVerified: false, createdAt, updatedAt });
  await writer.internalAdapter.createAccount({ id: "runtime-account", userId: owner, providerId: "provider", accountId: "subject", accessToken: "stored-token", password: "stored-password", createdAt, updatedAt });
}

function assertCompleteRecord(model: string, record: any, fields: any[]) {
  const expected = { ...cases.records[model] };
  for (const field of fields.filter(field => field.model === model)) expected[field.name] = field.expected;
  expect(observe(record)).toStrictEqual(expected);
  expect(Object.keys(record)).toStrictEqual(Object.keys(expected));
}

for (const joins of [false, true]) {
  test(`SQLite User/Account raw columns reach callbacks before typed decoding, joins=${joins}`, async () => {
    const database = new Database(":memory:");
    const base = { database, secret, baseURL: "http://localhost:3000", logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } } };
    try {
      await (await getMigrations(base)).runMigrations();
      await seedRows(base);
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
              assertCompleteRecord(model, row, cases.fields);
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

function serverDateExpected(row: any, backend: string): unknown {
  const expected = row.expectedDate?.[backend] ?? row.expectedDate;
  if (!expected?.localDate) return expected;
  const [year, month, day] = expected.localDate.split("-").map(Number);
  const date = new Date(year, month - 1, day);
  date.setFullYear(year);
  return observe(date);
}

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} User/Account raw numeric and DATE values preserve driver semantics`, async () => {
    await captureFreshServerCatalog(backend, ["user", "account", "session", "verification"], {}, async ({ options, query }: any) => {
      await seedRows(options);
      if (backend === "postgres") {
        await query('ALTER TABLE "user" ALTER COLUMN "name" DROP NOT NULL, ALTER COLUMN "name" TYPE NUMERIC USING NULL::NUMERIC, ALTER COLUMN "createdAt" DROP DEFAULT, ALTER COLUMN "createdAt" TYPE DATE USING "createdAt"::DATE, ALTER COLUMN "createdAt" DROP NOT NULL');
        await query('ALTER TABLE "account" ALTER COLUMN "accessToken" TYPE NUMERIC USING NULL::NUMERIC, ALTER COLUMN "accessTokenExpiresAt" TYPE DATE USING "accessTokenExpiresAt"::DATE');
      } else {
        await query("SET SESSION sql_mode = ''");
        await query('ALTER TABLE `user` MODIFY `name` DECIMAL(65, 30) NULL, MODIFY `createdAt` DATE NULL');
        await query('ALTER TABLE `account` MODIFY `accessToken` DECIMAL(65, 30) NULL, MODIFY `accessTokenExpiresAt` DATE NULL');
      }
      const quoted = (name: string) => backend === "postgres" ? `"${name}"` : `\`${name}\``;
      const snapshots = async () => {
        const cast = backend === "postgres" ? "TEXT" : "CHAR";
        const output = [];
        for (const [model, numeric, date] of [["user", "name", "createdAt"], ["account", "accessToken", "accessTokenExpiresAt"]]) {
          output.push(await query(`SELECT CAST(${quoted(numeric)} AS ${cast}) AS numeric_value, CAST(${quoted(date)} AS ${cast}) AS date_value FROM ${quoted(model)}`));
        }
        return {
          selected: output,
          complete: {
            user: observe(await query(`SELECT * FROM ${quoted("user")} ORDER BY id`)),
            account: observe(await query(`SELECT * FROM ${quoted("account")} ORDER BY id`)),
          },
        };
      };
      for (const row of cases.serverCases.filter(row => !("backend" in row) || row.backend === backend)) {
        const literal = (value: string | null) => value === null ? "NULL" : `'${value}'`;
        for (const [model, numeric, date] of [["user", "name", "createdAt"], ["account", "accessToken", "accessTokenExpiresAt"]]) {
          await query(`UPDATE ${quoted(model)} SET ${quoted(numeric)} = ${literal(row.numeric)}, ${quoted(date)} = ${literal(row.date)}`);
        }
        const before = await snapshots();
        const selected = cases.serverFields.map(field => {
          const raw = field.source === "numeric" ? row.expectedNumeric[backend] : serverDateExpected(row, backend);
          return { ...field, raw, expected: "expected" in field ? field.expected : raw };
        });
        for (const joins of [false, true]) {
          for (const reject of [false, true]) {
            const events: unknown[] = [];
            const fields = (model: string) => Object.fromEntries(selected.filter(field => field.model === model).map(field => [field.name, {
              type: field.type, required: false, transform: { output(value: unknown) {
                const label = `${model}.${field.name}`;
                events.push([label, observe(value)]);
                if (reject && label === "account.accessTokenExpiresAt") throw new Error("raw-column-stop");
                return "replacement" in field ? revive(field.replacement) : value;
              } },
            }]));
            const context = await betterAuth({ ...options, advanced: { database: { joins } }, user: { additionalFields: fields("user") }, account: { additionalFields: fields("account") } }).$context;
            for (const operation of cases.operations) {
              events.length = 0;
              const expected: unknown[] = [];
              let failed = false;
              for (const model of operation.models) {
                for (const field of selected.filter(field => field.model === model)) {
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
                for (const [model, record] of await execute()) {
                  assertCompleteRecord(model, record, selected);
                  for (const field of selected.filter(field => field.model === model)) expect(observe(record[field.name])).toStrictEqual(field.expected);
                }
              }
              expect(events).toStrictEqual(expected);
              expect(await snapshots()).toStrictEqual(before);
            }
          }
        }
      }
    });
  }, 120_000);
}
