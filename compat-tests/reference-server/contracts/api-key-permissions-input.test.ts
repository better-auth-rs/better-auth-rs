import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const permissions = { machine: ["read"] };

for (const backend of ["memory", "sqlite"] as const) {
  for (const mode of ["database", "secondary", "fallback"] as const) {
    for (const declaration of [false, true]) {
      test(`${backend}/${mode}: omitted API Key permissions retain declaration default=${declaration} and complete cache records`, async () => {
        const database = backend === "sqlite" ? new Database(":memory:") : undefined;
        const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
        const cache = new Map<string, string>();
        const options = {
          baseURL: "http://permissions.test", secret: "permissions-input-contract-secret-at-least-32-characters",
          database: database ?? memoryAdapter(memory), logger: { disabled: true }, telemetry: { enabled: false },
          plugins: [apiKey({
            storage: mode === "database" ? "database" : "secondary-storage", fallbackToDatabase: mode === "fallback",
            disableKeyHashing: true, startingCharactersConfig: { shouldStore: false }, deferUpdates: false,
            customStorage: {
              get: async (key: string) => cache.get(key) ?? null,
              set: async (key: string, value: string) => { cache.set(key, value); },
              delete: async (key: string) => { cache.delete(key); },
            },
          }), ...(declaration ? [{ id: "permissions-default", schema: { apikey: { fields: {
            permissions: { type: "string" as const, required: false, defaultValue: JSON.stringify(permissions) },
          } } } }] : [])],
        };
        try {
          if (database) await (await getMigrations(options)).runMigrations();
          const auth = betterAuth(options);
          const created = await auth.api.createApiKey({ body: { userId: "permissions-owner" } });
          const appliedDefault = declaration && mode !== "secondary";
          const expected = {
            id: created.id, key: created.key, configId: "default", name: null, prefix: null, start: null,
            enabled: true, expiresAt: null, referenceId: "permissions-owner", lastRefillAt: null, lastRequest: null,
            metadata: null, rateLimitMax: 10, rateLimitTimeWindow: 86_400_000, remaining: null,
            refillAmount: null, refillInterval: null, rateLimitEnabled: true, requestCount: 0,
            createdAt: created.createdAt.toISOString(), updatedAt: created.updatedAt.toISOString(),
            permissions: appliedDefault ? permissions : null,
          };
          expect(JSON.parse(JSON.stringify(created))).toStrictEqual(expected);
          if (mode !== "database") {
            const stored: Record<string, unknown> = { ...expected };
            if (appliedDefault) stored.permissions = JSON.stringify(permissions);
            else if (mode === "secondary" || backend === "memory") delete stored.permissions;
            expect(JSON.parse(cache.get(`api-key:by-id:${created.id}`)!)).toStrictEqual(stored);
            if (mode === "fallback") expect(cache.has("api-key:by-ref:permissions-owner")).toBe(false);
            else expect(JSON.parse(cache.get("api-key:by-ref:permissions-owner")!)).toStrictEqual([created.id]);
          } else expect(cache.size).toBe(0);
          const { adapter } = await auth.$context;
          expect(await adapter.count({ model: "apikey" })).toBe(mode === "secondary" ? 0 : 1);
        } finally { database?.close(); }
      });
    }
  }
}
