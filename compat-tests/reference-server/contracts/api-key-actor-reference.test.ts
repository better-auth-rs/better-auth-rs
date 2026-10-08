import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { createHMAC } from "@better-auth/utils/hmac";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";

const cases = JSON.parse(readFileSync(new URL("../../../tests/fixtures/api-key-actor-reference-cases.json", import.meta.url), "utf8"));
const secret = "api-key-native-actor-contract-secret-at-least-32-characters";

function cache() {
  const values = new Map<string, string>();
  return {
    values,
    async get(key: string) { return values.get(key) ?? null; },
    async set(key: string, value: string) { values.set(key, value); },
    async delete(key: string) { values.delete(key); },
  };
}

async function harness(mode: "memory" | "sqlite" | "secondary", organizationKeys = false) {
  const database = mode === "sqlite" ? new Database(":memory:") : undefined;
  const memory = { user: [], session: [], account: [], verification: [], apikey: [], organization: [], member: [], invitation: [] };
  const sessions = cache();
  const keys = cache();
  const callbacks: unknown[] = [];
  const options = {
    database: database ?? memoryAdapter(memory),
    secondaryStorage: sessions,
    baseURL: "http://native-actor.test", secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    plugins: [apiKey({
      storage: mode === "secondary" ? "secondary-storage" : "database",
      references: organizationKeys ? "organization" : "user",
      customStorage: keys, enableMetadata: true, deferUpdates: false,
      permissions: { defaultPermissions: async (referenceId: any, ctx: any) => {
        const count = await ctx.context.adapter.count({ model: "apikey", where: [{ field: "referenceId", value: referenceId }] });
        callbacks.push([referenceId, ctx.body.metadata, count]);
        return cases.permissions;
      } },
    }), ...(organizationKeys ? [organization()] : [])],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const signature = await createHMAC("SHA-256", "base64").sign(secret, "actor-token");
  const headers = new Headers({ cookie: `better-auth.session_token=${encodeURIComponent(`actor-token.${signature}`)}` });
  const actor = (value: unknown) => {
    const now = new Date();
    sessions.values.set("actor-token", JSON.stringify({
      session: { id: "actor-session", userId: "session-owner", token: "actor-token", createdAt: now, updatedAt: now, expiresAt: new Date("2100-01-01T00:00:00.000Z") },
      user: { id: value, name: "Native actor", email: "actor@native-actor.test", emailVerified: true, createdAt: now, updatedAt: now },
    }));
  };
  return { auth, adapter: context.adapter, headers, actor, keys, callbacks, close: () => database?.close() };
}

for (const mode of ["memory", "sqlite", "secondary"] as const) {
  test(`${mode}: API Key lifecycle preserves native actors, permissions, metadata, and strict ownership`, async () => {
    const f = await harness(mode);
    try {
      for (const sample of cases.owners) {
        f.actor(sample.actor);
        f.callbacks.length = 0;
        const created = await f.auth.api.createApiKey({ headers: f.headers, body: { name: "Machine", metadata: cases.metadata } });
        const reference = mode === "sqlite" ? sample.sqliteReference : sample.actor;
        expect(created.referenceId).toBe(reference);
        expect(created.metadata).toStrictEqual(cases.metadata);
        expect(created.permissions).toStrictEqual(cases.permissions);
        expect(f.callbacks).toStrictEqual([[sample.actor, cases.metadata, 0]]);
        const where = [{ field: "referenceId", value: sample.actor }];
        if (mode === "secondary") {
          const stored = JSON.parse(f.keys.values.get(`api-key:by-id:${created.id}`)!);
          expect(stored.referenceId).toBe(sample.actor);
          expect(stored.metadata).toStrictEqual(cases.metadata);
          expect(JSON.parse(stored.permissions)).toStrictEqual(cases.permissions);
          expect(JSON.parse(f.keys.values.get(`api-key:by-ref:${sample.cacheReference}`)!)).toStrictEqual([created.id]);
          expect(await f.adapter.count({ model: "apikey", where })).toBe(0);
        } else {
          const rows = await f.adapter.findMany<any>({ model: "apikey", where });
          expect(rows.map(row => [row.id, row.referenceId, row.metadata])).toStrictEqual([[created.id, reference, cases.metadata]]);
          expect(await f.adapter.count({ model: "apikey", where })).toBe(1);
          expect(await f.adapter.count({ model: "apikey", where: [{ field: "referenceId", value: sample.other }] })).toBe(mode === "sqlite" && sample.name !== "boolean" ? 1 : 0);
        }
        f.actor(mode === "sqlite" && sample.actor !== reference ? sample.actor : sample.other);
        for (const action of [
          () => f.auth.api.getApiKey({ headers: f.headers, query: { id: created.id } }),
          () => f.auth.api.updateApiKey({ headers: f.headers, body: { keyId: created.id, name: "Unauthorized" } }),
          () => f.auth.api.deleteApiKey({ headers: f.headers, body: { keyId: created.id } }),
        ]) await expect(action()).rejects.toMatchObject({ statusCode: 404 });
        expect((await f.auth.api.listApiKeys({ headers: f.headers })).total).toBe(0);
        f.actor(reference);
        const found = await f.auth.api.getApiKey({ headers: f.headers, query: { id: created.id } });
        expect([found.referenceId, found.metadata, found.permissions]).toStrictEqual([reference, cases.metadata, cases.permissions]);
        expect((await f.auth.api.listApiKeys({ headers: f.headers })).apiKeys.map(key => key.id)).toStrictEqual([created.id]);
        const updated = await f.auth.api.updateApiKey({ headers: f.headers, body: { keyId: created.id, name: "Updated" } });
        expect([updated.referenceId, updated.name, updated.metadata]).toStrictEqual([reference, "Updated", cases.metadata]);
        expect(await f.auth.api.deleteApiKey({ headers: f.headers, body: { keyId: created.id } })).toStrictEqual({ success: true });
        expect((await f.auth.api.listApiKeys({ headers: f.headers })).total).toBe(0);
        expect(f.callbacks).toStrictEqual([[sample.actor, cases.metadata, 0]]);
      }
      f.callbacks.length = 0;
      for (const sample of cases.rejected) {
        f.actor(sample.actor);
        await expect(f.auth.api.createApiKey({ headers: f.headers, body: { name: "Rejected" } })).rejects.toMatchObject({ statusCode: 401, body: { code: "UNAUTHORIZED_SESSION" } });
        await expect(f.auth.api.updateApiKey({ headers: f.headers, body: { keyId: "missing", userId: "fallback", name: "Rejected" } })).rejects.toMatchObject({ statusCode: 401, body: { code: "UNAUTHORIZED_SESSION" } });
      }
      expect(f.callbacks).toStrictEqual([]);
      expect(await f.adapter.count({ model: "apikey" })).toBe(0);
    } finally { f.close(); }
  });
}

test("secondary: null and missing reference properties retain distinct strict owners", async () => {
  const f = await harness("secondary");
  try {
    for (const actor of [null, undefined]) {
      f.actor(actor);
      const reference = `api-key:by-ref:${actor}`;
      const at = new Date().toISOString();
      const records = [
        { id: "null-owner", referenceId: null },
        { id: "missing-owner" },
      ];
      for (const record of records) f.keys.values.set(`api-key:by-id:${record.id}`, JSON.stringify({
        ...record, configId: "default", key: `hash:${record.id}`, createdAt: at, updatedAt: at,
      }));
      f.keys.values.set(reference, JSON.stringify(records.map(record => record.id)));
      const expected = actor === null ? "null-owner" : "missing-owner";
      const list = await f.auth.api.listApiKeys({ headers: f.headers });
      expect([list.total, list.apiKeys.map(key => key.id)]).toStrictEqual([1, [expected]]);
      expect((await f.auth.api.getApiKey({ headers: f.headers, query: { id: expected } })).id).toBe(expected);
      const other = actor === null ? "missing-owner" : "null-owner";
      await expect(f.auth.api.getApiKey({ headers: f.headers, query: { id: other } })).rejects.toMatchObject({ statusCode: 404 });
    }
    expect(f.callbacks).toStrictEqual([]);
  } finally { f.close(); }
});

for (const mode of ["memory", "sqlite"] as const) {
  test(`${mode}: organization API Keys query membership with the native actor`, async () => {
    const f = await harness(mode, true);
    try {
      const at = new Date();
      await f.adapter.create({ model: "user", forceAllowId: true, data: {
        id: "7", name: "Member", email: "member@native-actor.test", emailVerified: true, createdAt: at, updatedAt: at,
      } });
      await f.adapter.create({ model: "organization", forceAllowId: true, data: {
        id: "machine-org", name: "Machines", slug: "machines", createdAt: at,
      } });
      await f.adapter.create({ model: "member", data: { organizationId: "machine-org", userId: 7, role: "owner", createdAt: at } });
      f.actor(7);
      const created = await f.auth.api.createApiKey({ headers: f.headers, body: { organizationId: "machine-org", metadata: cases.metadata } });
      expect(created.referenceId).toBe("machine-org");
      expect(f.callbacks).toStrictEqual([["machine-org", cases.metadata, 0]]);
      expect((await f.auth.api.getApiKey({ headers: f.headers, query: { id: created.id } })).id).toBe(created.id);
      expect((await f.auth.api.listApiKeys({ headers: f.headers, query: { organizationId: "machine-org" } })).apiKeys.map(key => key.id)).toStrictEqual([created.id]);
      f.actor(8);
      for (const action of [
        () => f.auth.api.getApiKey({ headers: f.headers, query: { id: created.id } }),
        () => f.auth.api.updateApiKey({ headers: f.headers, body: { keyId: created.id, name: "Unauthorized" } }),
        () => f.auth.api.deleteApiKey({ headers: f.headers, body: { keyId: created.id } }),
        () => f.auth.api.listApiKeys({ headers: f.headers, query: { organizationId: "machine-org" } }),
      ]) await expect(action()).rejects.toMatchObject({ statusCode: 403, body: { code: "USER_NOT_MEMBER_OF_ORGANIZATION" } });
      f.actor(7);
      expect((await f.auth.api.updateApiKey({ headers: f.headers, body: { keyId: created.id, name: "Updated" } })).name).toBe("Updated");
      expect(await f.auth.api.deleteApiKey({ headers: f.headers, body: { keyId: created.id } })).toStrictEqual({ success: true });
    } finally { f.close(); }
  });
}
