import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

type Backend = "memory" | "sqlite";
type Display = string | null | undefined;
const AAGUID = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4";
const baseURL = "http://display-presence.test";
const describe = (value: Display) => value === undefined ? "undefined" : JSON.stringify(value);

function expectDisplay(row: Record<string, unknown>, field: string, value: Display) {
  expect(row[field]).toBe(value);
  const serialized = JSON.parse(JSON.stringify(row));
  expect(Object.hasOwn(serialized, field)).toBe(value !== undefined);
  if (value !== undefined) expect(serialized[field]).toBe(value);
}

async function fixture(backend: Backend, plugins: any[]) {
  const memory: Record<string, any[]> = {user: [], session: [], account: [], verification: [], passkey: [], apikey: []};
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = {
    database: database ?? memoryAdapter(memory), baseURL,
    secret: "ordinary-display-presence-contract-at-least-32-characters",
    logger: {disabled: true}, emailAndPassword: {enabled: true}, plugins,
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const signup = await auth.api.signUpEmail({
    body: {name: "Display Owner", email: "owner@display-presence.test", password: "ordinary-fixture-password"},
    returnHeaders: true,
  });
  const headers = new Headers({cookie: signup.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ")});
  const {adapter} = await auth.$context;
  return {auth, adapter, headers, owner: signup.response.user.id, memory, database, close: () => database?.close()};
}

test("display presence contracts use pinned Better Auth plugins 1.7.6", async () => {
  for (const name of ["better-auth", "@better-auth/core", "@better-auth/passkey", "@better-auth/api-key"]) {
    expect((await Bun.file(`${import.meta.dir}/../node_modules/${name}/package.json`).json()).version).toBe("1.7.6");
  }
});

for (const backend of ["memory", "sqlite"] as const) {
  test(`Passkey display outputs and omitted/null create inputs retain presence (${backend})`, async () => {
    const trace: string[] = [];
    let output: "identity" | "string" | "empty" | "null" | "undefined" = "identity";
    const field = (name: "name" | "aaguid") => ({
      type: "string" as const, required: false,
      transform: {
        input(value: Display) { trace.push(`input:${name}:${describe(value)}`); return value; },
        output(value: Display) {
          trace.push(`output:${name}:${describe(value)}`);
          if (output === "string") return name === "name" ? "Desk label" : AAGUID.toUpperCase();
          if (output === "empty") return "";
          if (output === "null") return null;
          if (output === "undefined") return undefined;
          return value;
        },
      },
    });
    const f = await fixture(backend, [passkey(), {id: "ordinary-display-fields", schema: {passkey: {fields: {
      name: field("name"), aaguid: field("aaguid"),
    }}}}]);
    try {
      const create = (label: string, display: {name?: Display; aaguid?: Display}) => f.adapter.create<any>({model: "passkey", data: {
        ...display, userId: f.owner, credentialID: `ordinary-credential:${label}`, publicKey: "ordinary-public-key",
        counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: new Date(),
      }});
      const created = await create("desk", {name: "Desk", aaguid: AAGUID});
      expect(trace.splice(0)).toStrictEqual([
        'input:name:"Desk"', `input:aaguid:${JSON.stringify(AAGUID)}`,
        'output:name:"Desk"', `output:aaguid:${JSON.stringify(AAGUID)}`,
      ]);
      for (const mode of ["string", "empty", "null", "undefined"] as const) {
        output = mode;
        const expected = (name: "name" | "aaguid"): Display => mode === "string"
          ? name === "name" ? "Desk label" : AAGUID.toUpperCase()
          : mode === "empty" ? "" : mode === "null" ? null : undefined;
        const rows = await f.adapter.findMany<any>({model: "passkey", where: [{field: "userId", value: f.owner}]});
        expect(rows.length).toBe(1);
        for (const name of ["name", "aaguid"] as const) expectDisplay(rows[0], name, expected(name));
        expect(trace.splice(0)).toStrictEqual(['output:name:"Desk"', `output:aaguid:${JSON.stringify(AAGUID)}`]);
        const response = await f.auth.handler(new Request(`${baseURL}/api/auth/passkey/list-user-passkeys`, {headers: f.headers}));
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.length).toBe(1);
        for (const name of ["name", "aaguid"] as const) expectDisplay(body[0], name, expected(name));
        expect(trace.splice(0)).toStrictEqual(['output:name:"Desk"', `output:aaguid:${JSON.stringify(AAGUID)}`]);
      }
      const raw = f.database
        ? f.database.query<any, [string]>('SELECT name,aaguid FROM passkey WHERE id=?').get(created.id)
        : f.memory.passkey.find(row => row.id === created.id);
      expect(raw.name).toBe("Desk"); expect(raw.aaguid).toBe(AAGUID);
      output = "identity";
      for (const mode of ["omitted", "null"] as const) {
        const row = await create(mode, mode === "omitted" ? {} : {name: null, aaguid: null});
        const inputValue = mode === "omitted" ? undefined : null;
        const storedValue = mode === "omitted" && backend === "memory" ? undefined : null;
        expect(trace.splice(0)).toStrictEqual([
          `input:name:${describe(inputValue)}`, `input:aaguid:${describe(inputValue)}`,
          `output:name:${describe(storedValue)}`, `output:aaguid:${describe(storedValue)}`,
        ]);
        for (const name of ["name", "aaguid"] as const) expectDisplay(row, name, storedValue);
      }
    } finally { f.close(); }
  });
}

function storage() {
  const cache = new Map<string, string>();
  const customStorage = {
    get: async (key: string) => cache.get(key) ?? null,
    set: async (key: string, value: string) => { cache.set(key, value); },
    delete: async (key: string) => { cache.delete(key); },
  };
  return {cache, customStorage};
}

function keyFields(trace: string[], output: Display) {
  return {id: "ordinary-key-display", schema: {apikey: {fields: {name: {
    type: "string" as const, required: false,
    transform: {
      input(value: Display) { trace.push(`input:name:${describe(value)}`); return value; },
      output(value: Display) { trace.push(`output:name:${describe(value)}`); return output; },
    },
  }}}}};
}

for (const backend of ["memory", "sqlite"] as const) for (const mode of ["database", "fallback"] as const) {
  for (const presence of ["null", "undefined"] as const) {
    test(`API Key name ${presence} survives ${mode === "database" ? "database reads" : "fallback refill and cache hits"} (${backend})`, async () => {
      const expected = presence === "null" ? null : undefined;
      const trace: string[] = [];
      const {cache, customStorage} = storage();
      const f = await fixture(backend, [apiKey({
        storage: mode === "database" ? "database" : "secondary-storage",
        fallbackToDatabase: mode === "fallback", customStorage, deferUpdates: false,
      }), keyFields(trace, expected)]);
      try {
        const created = await f.auth.api.createApiKey({headers: f.headers, body: {name: "Desk"}});
        expectDisplay(created, "name", expected);
        expect(trace.splice(0)).toStrictEqual(['input:name:"Desk"', 'output:name:"Desk"']);
        const byId = `api-key:by-id:${created.id}`;
        const reference = `api-key:by-ref:${f.owner}`;
        const read = async (events: string[]) => {
          expectDisplay(await f.auth.api.getApiKey({headers: f.headers, query: {id: created.id}}), "name", expected);
          expect(trace.splice(0)).toStrictEqual(events);
        };
        const list = async (events: string[]) => {
          const result = await f.auth.api.listApiKeys({headers: f.headers});
          expect(result.total).toBe(1); expect(result.apiKeys.length).toBe(1);
          expectDisplay(result.apiKeys[0], "name", expected);
          expect(trace.splice(0)).toStrictEqual(events);
        };
        await read(mode === "database" ? ['output:name:"Desk"'] : []);
        if (mode === "fallback") {
          expectDisplay(JSON.parse(cache.get(byId)!), "name", expected);
          cache.clear();
          await read(['output:name:"Desk"']);
          expectDisplay(JSON.parse(cache.get(byId)!), "name", expected);
          await read([]);
          cache.clear();
          await list(['output:name:"Desk"']);
          expectDisplay(JSON.parse(cache.get(byId)!), "name", expected);
          expect(JSON.parse(cache.get(reference)!)).toStrictEqual([created.id]);
          await list([]);
        } else {
          await list(['output:name:"Desk"']);
          expect(cache.size).toBe(0);
        }
        const raw = f.database
          ? f.database.query<any, [string]>('SELECT name FROM apikey WHERE id=?').get(created.id)
          : f.memory.apikey.find(row => row.id === created.id);
        expect(raw.name).toBe("Desk");
      } finally { f.close(); }
    });
  }
}

test("pure secondary API Key creation without a name keeps null and bypasses field callbacks", async () => {
  const trace: string[] = [];
  const {cache, customStorage} = storage();
  const f = await fixture("memory", [apiKey({storage: "secondary-storage", customStorage, deferUpdates: false}), keyFields(trace, "Projected name")]);
  try {
    const created = await f.auth.api.createApiKey({headers: f.headers, body: {}});
    expectDisplay(created, "name", null);
    expectDisplay(JSON.parse(cache.get(`api-key:by-id:${created.id}`)!), "name", null);
    expectDisplay(await f.auth.api.getApiKey({headers: f.headers, query: {id: created.id}}), "name", null);
    const result = await f.auth.api.listApiKeys({headers: f.headers});
    expect(result.total).toBe(1); expect(result.apiKeys.length).toBe(1);
    expectDisplay(result.apiKeys[0], "name", null);
    expect(trace).toStrictEqual([]);
    expect(f.memory.apikey).toStrictEqual([]);
  } finally { f.close(); }
});
