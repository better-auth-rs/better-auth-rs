import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

function fieldPlugin(trace: string[], inputError = new Error("ordinary input error"), outputError = new Error("ordinary output error")) {
  return { id: "ordinary-key-name", schema: { apikey: { fields: { name: {
    type: "string" as const, required: true, defaultValue: "Fallback", onUpdate: () => "Renewed",
    transform: {
      input(value: any) { trace.push(`input:${JSON.stringify(value)}`); if (value === "input-error") throw inputError; return value.trim(); },
      output(value: any) { trace.push(`output:${JSON.stringify(value)}`); if (value === "output-error") throw outputError; return `${value}:out`; },
    },
  } } } } };
}

async function fixture(backend: "memory" | "sqlite", mode: "database" | "secondary" | "fallback", trace: string[], plugin = fieldPlugin(trace)) {
  const memory: Record<string, any[]> = {user: [], session: [], account: [], verification: [], apikey: []};
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const cache = new Map<string, string>();
  const customStorage = {
    get: async (key: string) => cache.get(key) ?? null,
    set: async (key: string, value: string) => { cache.set(key, value); },
    delete: async (key: string) => { cache.delete(key); },
  };
  const options = {
    database: database ?? memoryAdapter(memory), baseURL: "http://key-fields.test",
    secret: "ordinary-api-key-fields-contract-at-least-32-characters", logger: { disabled: true },
    emailAndPassword: { enabled: true },
    plugins: [apiKey({ storage: mode === "database" ? "database" : "secondary-storage", fallbackToDatabase: mode === "fallback", customStorage, deferUpdates: false }), plugin],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const raw = (id: string) => database ? database.query<any, [string]>('SELECT name FROM apikey WHERE id=?').get(id) : memory.apikey.find(row => row.id === id);
  return { auth, adapter: context.adapter, raw, cache, close: () => database?.close() };
}

test("ordinary API Key names preserve adapter write phases and legal counter expressions", async () => {
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = []; const inputError = new Error("ordinary input error"); const outputError = new Error("ordinary output error");
    const f = await fixture(backend, "database", trace, fieldPlugin(trace, inputError, outputError));
    const create = (name: string | null, key: string) => f.adapter.create<any>({model: "apikey", data: {
      name, key, configId: "default", referenceId: "ordinary-owner", enabled: true, remaining: 10,
      rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3, requestCount: 0,
      lastRefillAt: null, lastRequest: null, createdAt: new Date(), updatedAt: new Date(),
    }});
    const created = await create("  Desk  ", "ordinary-first");
    expect(created.name).toBe("Desk:out"); expect(f.raw(created.id).name).toBe("Desk");
    expect(trace).toStrictEqual(['input:"  Desk  "', 'output:"Desk"']);
    expect((await create(null, "ordinary-default")).name).toBe("Fallback:out");
    const where = [{field: "id", value: created.id}];
    const updated: any = await f.adapter.update({model: "apikey", where, update: {name: "  Mobile  "}});
    expect(updated.name).toBe("Mobile:out");
    trace.length = 0;
    const list: any[] = await f.adapter.findMany({model: "apikey", sortBy: {field: "name", direction: "asc"}});
    expect(list.map(row => row.name)).toStrictEqual(["Fallback:out", "Mobile:out"]);
    expect(trace).toStrictEqual(['output:"Fallback"', 'output:"Mobile"']);
    const now = new Date();
    const writes = [
      {increment: {remaining: -1}},
      {increment: {}, set: {requestCount: 1, lastRequest: now}},
      {increment: {requestCount: 1}, set: {lastRequest: now}},
      {update: {lastRequest: now}}, {update: {updatedAt: now}},
      {increment: {}, set: {remaining: 8, lastRefillAt: now}},
    ];
    for (const [index, write] of writes.entries()) {
      trace.length = 0;
      const row: any = "update" in write
        ? await f.adapter.update({model: "apikey", where, update: write.update!})
        : await f.adapter.incrementOne({model: "apikey", where, increment: write.increment!, ...("set" in write ? {set: write.set} : {})});
      expect(row.remaining).toBe(index === 5 ? 8 : 9);
      expect(row.requestCount).toBe(index === 0 ? 0 : index === 1 ? 1 : 2);
      expect(row.name).toBe(index === 0 ? "Mobile:out" : "Renewed:out");
      expect(trace).toStrictEqual(index === 0 ? ['output:"Mobile"'] : ['input:"Renewed"', 'output:"Renewed"']);
      expect(f.raw(created.id).name).toBe(index === 0 ? "Mobile" : "Renewed");
    }
    await expect(create("input-error", "ordinary-input-error")).rejects.toBe(inputError);
    await expect(create("output-error", "ordinary-output-error")).rejects.toBe(outputError);
    f.close();
  }
});

test("ordinary API Key cache-only and fallback hits bypass adapter name policies", async () => {
  for (const backend of ["memory", "sqlite"] as const) for (const mode of ["database", "secondary", "fallback"] as const) {
    const trace: string[] = []; const f = await fixture(backend, mode, trace);
    const signup = await f.auth.api.signUpEmail({body: {name: "Owner", email: "owner@key-fields.test", password: "ordinary-fixture-password"}, returnHeaders: true});
    const headers = new Headers({cookie: signup.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ")});
    const created: any = await f.auth.api.createApiKey({headers, body: {name: "  Desk  "}});
    const expected = mode === "secondary" ? "  Desk  " : "Desk:out";
    expect(created.name).toBe(expected);
    expect(trace).toStrictEqual(mode === "secondary" ? [] : ['input:"  Desk  "', 'output:"Desk"']);
    expect(f.raw(created.id)?.name ?? null).toBe(mode === "secondary" ? null : "Desk");
    trace.length = 0;
    expect((await f.auth.api.getApiKey({headers, query: {id: created.id}})).name).toBe(expected);
    expect(trace).toStrictEqual(mode === "database" ? ['output:"Desk"'] : []);
    for (let turn = 0; turn < 2; turn++) {
      trace.length = 0;
      expect((await f.auth.api.listApiKeys({headers})).apiKeys[0].name).toBe(expected);
      expect(trace).toStrictEqual(mode === "database" || mode === "fallback" && turn === 0 ? ['output:"Desk"'] : []);
    }
    trace.length = 0;
    const updated: any = await f.auth.api.updateApiKey({headers, body: {keyId: created.id, name: "  Mobile  "}});
    expect(updated.name).toBe(mode === "secondary" ? "  Mobile  " : "Mobile:out");
    expect(trace).toStrictEqual(mode === "secondary" ? [] : [...(mode === "database" ? ['output:"Desk"'] : []), 'input:"  Mobile  "', 'output:"Mobile"']);
    if (mode === "fallback") {
      f.cache.delete(`api-key:by-id:${created.id}`);
      for (let turn = 0; turn < 2; turn++) {
        trace.length = 0;
        expect((await f.auth.api.getApiKey({headers, query: {id: created.id}})).name).toBe("Mobile:out");
        expect(trace).toStrictEqual(turn === 0 ? ['output:"Mobile"'] : []);
      }
    }
    f.close();
  }
});
