import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { testUtils } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const origin = "http://api-key-number-name.test";

function observeError(error) {
  if (error instanceof Error) return {
    name: error.name, message: error.message, keys: Object.keys(error),
    properties: Object.fromEntries(Object.entries(error).map(([key, value]) => [key, observeError(value)])),
  };
  if (Array.isArray(error)) return error.map(observeError);
  if (error !== null && typeof error === "object" && !(error instanceof Date)) {
    return Object.fromEntries(Object.entries(error).map(([key, value]) => [key, observeError(value)]));
  }
  return observeValue(error);
}

async function captureCase(backend, required, plan) {
  const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const sequences = new Map();
  const windows = new Map();
  let keySequence = 0;
  const record = event => events.push(observeValue(event));
  const configuration = {
    database: sqlite ?? memoryAdapter(memory), baseURL: origin,
    secret: "ordinary-api-key-number-name-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    advanced: { database: { generateId({ model }) {
      const sequence = (sequences.get(model) ?? 0) + 1;
      sequences.set(model, sequence);
      const value = `number-name-${model}-${sequence}`;
      record({ kind: "generate-id", model, value });
      return value;
    } } },
    onAPIError: { onError(error) { events.push({ kind: "api-error", error: observeError(error) }); } },
    plugins: [testUtils(), apiKey({
      customKeyGenerator(input) {
        const value = `ordinary-number-name-key-${++keySequence}-abcdefghijklmnopqrstuvwxyz`;
        record({ kind: "generate-key", input, value });
        return value;
      },
    }), { id: "ordinary-api-key-number-name", schema: { apikey: { fields: { name: {
      type: "number", required, defaultValue: 7,
      transform: {
        input(value) { record({ kind: "input", field: "name", value }); return plan ? plan.input(value) : value; },
        output(value) { record({ kind: "output", field: "name", value }); return value; },
      },
    } } } } }],
  };
  const stored = () => structuredClone(sqlite ? sqlite.query("SELECT * FROM apikey ORDER BY id").all() : memory.apikey);
  const normalize = value => {
    if (Array.isArray(value)) return value.map(normalize);
    if (value !== null && typeof value === "object" && !(value instanceof Date)) {
      return Object.fromEntries(Object.entries(value).map(([key, child]) => {
        if (windows.has(value.id) && ["createdAt", "updatedAt"].includes(key)) {
          const time = child instanceof Date ? child.getTime() : Date.parse(child);
          const window = windows.get(value.id);
          assert.ok(Number.isFinite(time) && time >= window.start && time <= window.end);
          assert.equal(time, window.timestamps[key], "Response dates must match the stored API Key");
          const normalized = `<${value.id}.${key}>`;
          return [key, child instanceof Date ? { type: "date", value: normalized } : normalized];
        }
        return [key, normalize(child)];
      }));
    }
    return observeValue(value);
  };
  try {
    if (sqlite) await (await getMigrations(configuration)).runMigrations();
    const catalog = sqlite ? observeSqliteCatalog(sqlite, "apikey", "The API Key table must exist") : null;
    const auth = betterAuth(configuration);
    const context = await auth.$context;
    const owner = await context.test.saveUser(context.test.createUser({
      name: "Number name owner", email: "owner@api-key-number-name.test",
    }));
    const login = await context.test.login({ userId: owner.id });
    const cookie = login.headers.get("cookie");
    assert.ok(cookie);
    const cookieName = context.authCookies.sessionToken.name;
    assert.ok(cookie.startsWith(`${cookieName}=`));
    const headersValue = headers => [...headers].map(([name, value]) => {
      if (name !== "cookie") return [name, value];
      assert.equal(value, cookie);
      return [name, `${cookieName}=<owner-session-cookie>`];
    });
    events.length = 0;

    async function call(name, method, path, body, query) {
      assert.equal(events.length, 0);
      const before = stored();
      const headers = new Headers(login.headers);
      headers.set("origin", origin);
      headers.set("accept", "application/json");
      if (body !== undefined) headers.set("content-type", "application/json");
      const url = new URL(`/api/auth${path}`, origin);
      if (query) url.search = new URLSearchParams(query).toString();
      const requestBody = body === undefined ? null : JSON.stringify(body);
      const request = new Request(url, { method, headers, body: requestBody });
      const window = { start: Date.now() };
      let response;
      let thrown = null;
      try { response = await auth.handler(request); }
      catch (error) {
        if (error instanceof assert.AssertionError) throw error;
        thrown = observeError(error);
      } finally { window.end = Date.now(); }
      const text = response ? await response.text() : null;
      const after = stored();
      for (const row of after) if (!windows.has(row.id)) windows.set(row.id, {
        ...window, timestamps: Object.fromEntries(["createdAt", "updatedAt"].map(field => [field,
          row[field] instanceof Date ? row[field].getTime() : Date.parse(row[field])])),
      });
      const json = response?.headers.get("content-type")?.includes("application/json") ? JSON.parse(text) : undefined;
      if (json !== undefined) assert.equal(text, JSON.stringify(json), "Retain the complete JSON response and property order");
      const observation = {
        name, request: { url: request.url, method, headers: headersValue(headers), body: requestBody },
        before: normalize(before), events: events.splice(0),
        response: response ? { status: response.status, statusText: response.statusText,
          headers: [...response.headers], cookies: response.headers.getSetCookie(),
          body: json === undefined ? text : JSON.stringify(normalize(json)) } : null,
        thrown, after: normalize(after),
      };
      if (method === "GET" || name === "reject-number-input") assert.deepEqual(after, before);
      return { observation, json, raw: after };
    }

    const operations = [];
    if (plan) {
      await plan.run({ call, operations, required, ownerId: owner.id });
    } else {
      const expected = required ? 7 : null;
      const createdIds = [];
      for (const name of ["create-first", "create-second"]) {
        const result = await call(name, "POST", "/api-key/create", {});
        operations.push(result.observation);
        assert.equal(result.observation.response?.status, 200);
        assert.equal(result.json.name, expected);
        assert.equal(result.json.referenceId, owner.id);
        const row = result.raw.find(row => row.id === result.json.id);
        assert.ok(row);
        assert.equal(row.name, expected);
        assert.deepEqual(result.observation.events.filter(event => event.field === "name"), [
          { kind: "input", field: "name", value: expected },
          { kind: "output", field: "name", value: expected },
        ]);
        createdIds.push(result.json.id);
      }
      for (const [name, path, query] of [
        ["get", "/api-key/get", { id: createdIds[0] }],
        ["list", "/api-key/list", undefined],
        ["list-name-ascending", "/api-key/list", { sortBy: "name", sortDirection: "asc" }],
      ]) {
        const result = await call(name, "GET", path, undefined, query);
        operations.push(result.observation);
        if (name === "get") {
          assert.equal(result.observation.response?.status, 200);
          assert.equal(result.json.id, createdIds[0]);
          assert.equal(result.json.name, expected);
        } else if (name === "list") {
          assert.equal(result.observation.response?.status, 200);
          assert.equal(result.json.total, 2);
          assert.equal(result.json.apiKeys.length, 2);
          assert.deepEqual(result.json.apiKeys.map(row => row.id).sort(), [...createdIds].sort());
          for (const row of result.json.apiKeys) assert.equal(row.name, expected);
        }
      }
      const rejected = await call("reject-number-input", "POST", "/api-key/create", { name: 7 });
      assert.equal(rejected.observation.response?.status, 400);
      assert.deepEqual(rejected.observation.events.filter(event => event.field === "name"), []);
      operations.push(rejected.observation);
    }
    return { backend, required, declaration: { type: "number", required, defaultValue: 7 },
      ownerId: owner.id, catalog, operations };
  } finally { sqlite?.close(); }
}

export async function captureApiKeyNumberName(plan) {
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const required of [true, false]) cases.push(await captureCase(backend, required, plan));
  }
  return { version, cases };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureApiKeyNumberName(), null, 2)}\n`);
}
