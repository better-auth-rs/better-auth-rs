import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization, twoFactor } from "better-auth/plugins";
import { withRestoredSchema } from "./schema-isolation.mjs";

const emptyUpdate = "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.";
const now = new Date("2030-01-02T03:04:05.000Z");

for (const backend of ["memory", "sqlite"] as const) {
  for (const model of ["apikey", "twoFactor", "deviceCode"] as const) {
    test(`${backend} ${model} rejects transformed empty atomic updates before lookup or mutation`, async () => {
      const plugin = model === "apikey" ? apiKey() : model === "twoFactor" ? twoFactor() : deviceAuthorization();
      await withRestoredSchema(plugin.schema, async () => {
        const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], [model]: [] };
        const database = backend === "sqlite" ? new Database(":memory:") : undefined;
        const names = model === "apikey" ? ["lastRefillAt", "remaining"] : model === "twoFactor" ? ["backupCodes"] : ["userId"];
        const types = model === "apikey" ? ["date", "number"] : ["string"];
        const trace: unknown[] = [];
        let discard = false;
        const fields = Object.fromEntries(names.map((name, index) => [name, {
          type: types[index], required: false,
          transform: {
            input(value: unknown) { trace.push(["input", name, value]); return discard ? undefined : value; },
            output(value: unknown) { trace.push(["output", name, value]); return value; },
          },
        }]));
        const options = {
          database: database ?? memoryAdapter(memory),
          baseURL: "http://native-atomic.test", secret: "native-atomic-update-contract-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          plugins: [plugin, { id: "native-atomic-fields", schema: { [model]: { fields } } }],
        };
        try {
          if (database) await (await getMigrations(options)).runMigrations();
          const { adapter } = await betterAuth(options).$context;
          await adapter.create({ model: "user", forceAllowId: true, data: {
            id: "owner", name: "Owner", email: "owner@native-atomic.test", emailVerified: true,
            createdAt: now, updatedAt: now,
          } });
          const seed = model === "apikey" ? {
            configId: "default", referenceId: "owner", key: "atomic-key", enabled: true,
            remaining: 8, lastRefillAt: null, requestCount: 0, createdAt: now, updatedAt: now,
          } : model === "twoFactor"
            ? { userId: "owner", secret: "secret", backupCodes: "original-codes", failedVerificationCount: 0, lockedUntil: null }
            : { deviceCode: "device-code", userCode: "ABCD2345", userId: null, expiresAt: now, status: "pending", pollingInterval: 5000, lastPolledAt: null };
          const created = await adapter.create<any>({ model, forceAllowId: true, data: { id: "record", ...seed } });
          const stored = () => database
            ? database.query(`SELECT * FROM "${model}" ORDER BY id`).all()
            : structuredClone(memory[model]);
          const before = stored();
          const set = model === "apikey" ? { remaining: 5, lastRefillAt: now }
            : model === "twoFactor" ? { backupCodes: "replacement-codes" } : { userId: "owner" };
          discard = true;
          for (const id of [created.id, "missing"]) {
            trace.length = 0;
            await expect(adapter.incrementOne({ model, where: [{ field: "id", value: id }], increment: {}, set })).rejects.toThrow(emptyUpdate);
            expect(trace).toStrictEqual(names.map(name => ["input", name, set[name as keyof typeof set]]));
            expect(stored()).toStrictEqual(before);
          }
          trace.length = 0;
          const counter = model === "apikey" ? "requestCount" : model === "twoFactor" ? "failedVerificationCount" : "pollingInterval";
          const incremented = created[counter] + 1;
          const result = await adapter.incrementOne<any>({ model, where: [{ field: "id", value: created.id }], increment: { [counter]: 1 }, set });
          expect(result).toStrictEqual({ ...created, [counter]: incremented });
          expect(trace).toStrictEqual([
            ...names.map(name => ["input", name, set[name as keyof typeof set]]),
            ...names.map(name => ["output", name, created[name]]),
          ]);
          expect(stored()).toStrictEqual(before.map(row => ({ ...row, [counter]: incremented })));
        } finally {
          database?.close();
        }
      });
    });
  }
}
