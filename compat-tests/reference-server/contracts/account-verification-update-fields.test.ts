import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { getWithHooks } from "../node_modules/better-auth/dist/db/with-hooks.mjs";
import "./session-update-secondary-contract";

type Fields = Record<string, unknown>;
type Mode = "values" | "empty" | "continue";
const date = (offset: number) => new Date(4_102_444_800_000 + offset * 1000);

for (const backend of ["memory", "sqlite"] as const) {
  for (const operation of ["account", "accountMany", "verification", "session"] as const) {
    for (const mode of ["values", "empty", "continue"] as Mode[]) {
      test(`${backend} ${operation} ${mode} preserves original update fields and shallow detachment`, async () => {
        const model = operation === "accountMany" ? "account" : operation;
        const [target, replacement, mutation] = model === "account"
          ? ["accessToken", "scope", "accountId"] : model === "session"
            ? ["ipAddress", "userAgent", "token"] : ["identifier", "value", "expiresAt"];
        const mutate = (late: boolean) => model === "verification" ? date(late ? 3 : 2) : late ? "late" : "in-place";
        const originalDate = date(1);
        const observed: Fields[] = [];
        const references: Fields[] = [];
        const after: unknown[] = [];
        const hooks = (first: boolean) => ({ [model]: { update: {
          before(original: Fields) {
            expect(original.updatedAt).toBe(originalDate);
            observed.push(structuredClone(original));
            references.push(original);
            if (first) {
              original[mutation] = mutate(false);
              if (mode === "values") return { data: { [target]: undefined, [replacement]: 7 } };
              if (mode === "empty") return { data: {} };
            } else {
              expect(original[target]).toBe("requested");
              expect(original[replacement]).toBe("requested");
              Object.assign(original, { [mutation]: mutate(true), [target]: "late", [replacement]: "late", updatedAt: date(3) });
            }
          },
          after(value: unknown) { after.push(structuredClone(value)); },
        } } });
        const memory: Record<string, Fields[]> = { user: [], session: [], account: [], verification: [] };
        const database = backend === "sqlite" ? new Database(":memory:") : undefined;
        const pluginHooks = hooks(true);
        const userHooks = hooks(false);
        const options = {
          database: database ?? memoryAdapter(memory),
          baseURL: "http://update-fields.test", secret: "account-verification-update-fields-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          plugins: [{ id: "update-fields", init: () => ({ options: { databaseHooks: pluginHooks } }) }],
          databaseHooks: userHooks,
        };
        try {
          if (database) await (await getMigrations(options)).runMigrations();
          const context = await betterAuth(options).$context;
          const adapter = context.adapter;
          await adapter.create({ model: "user", forceAllowId: true, data: {
            id: "owner", name: "Owner", email: "owner@update-fields.test", emailVerified: true,
            createdAt: date(0), updatedAt: date(0),
          } });
          const created = await adapter.create<Fields>({ model, forceAllowId: true, data: {
            id: "record", createdAt: date(0), updatedAt: date(0),
            ...(model === "account" ? { accountId: "original", providerId: "credential", userId: "owner", accessToken: "stored", scope: "stored" }
              : model === "session" ? { token: "original", userId: "owner", ipAddress: "stored", userAgent: "stored", expiresAt: date(100) }
              : { identifier: "original", value: "stored", expiresAt: date(0) }),
          } });
          const storage = () => structuredClone(database ? database.query(`SELECT * FROM ${model}`).all() : memory[model]);
          const rawBefore = storage();
          const before = structuredClone(created);
          const input = { [target]: "requested", [replacement]: "requested", updatedAt: originalDate };
          const withHooks = getWithHooks(adapter, {
            options: context.options,
            hooks: [{ source: "plugin:update-fields", hooks: pluginHooks }, { source: "user", hooks: userHooks }],
          });
          const where = [{ field: "id", value: "record" }];
          const result = operation === "accountMany"
            ? await withHooks.updateManyWithHooks(input, where, model)
            : await withHooks.updateWithHooks(input, where, model);
          const changed: Fields = { [mutation]: mutate(mode === "continue"), updatedAt: date(mode === "continue" ? 3 : 1) };
          if (mode === "values") changed[replacement] = backend === "sqlite" ? "7" : 7;
          else Object.assign(changed, { [target]: mode === "empty" ? "requested" : "late", [replacement]: mode === "empty" ? "requested" : "late" });
          const expected = { ...before, ...changed };
          expect(result).toStrictEqual(operation === "accountMany" ? 1 : expected);
          expect(after).toStrictEqual([result, result]);
          expect(await adapter.findOne({ model, where })).toStrictEqual(expected);
          const rawChanges = Object.fromEntries(Object.entries(changed).map(([key, value]) => [key, database && value instanceof Date ? value.toISOString() : value]));
          expect(storage()).toStrictEqual(rawBefore.map(row => ({ ...row, ...rawChanges })));
          expect(references[0]).toBe(references[1]);
          expect(observed).toStrictEqual([
            { [target]: "requested", [replacement]: "requested", updatedAt: date(1) },
            { [target]: "requested", [replacement]: "requested", updatedAt: date(1), [mutation]: mutate(false) },
          ]);
        } finally { database?.close(); }
      });
    }
  }
}
