import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Database } from "bun:sqlite";
import { withSpan } from "@better-auth/core/instrumentation";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { observeValue } from "./device-where-capture.mjs";

const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const origin = "http://email-verification-payload.test";
const secret = "email-verification-payload-contract-secret-at-least-32-characters";
const email = "owner@verify-payload.test";
const dates = { iat: 1_700_000_000, exp: 4_102_444_800 };
const date = new Date("2030-01-02T03:04:05.000Z");
const tables = ["user", "session", "account", "verification"];
const callback = "/verified?source=mail#done";
const scenarios = [
  { name: "missing-email", payload: JSON.stringify(dates), invalidField: "email" },
  { name: "non-string-email", payload: JSON.stringify({ email: 7, ...dates }), invalidField: "email" },
  { name: "non-string-update-to", payload: JSON.stringify({ email, updateTo: 7, ...dates }), invalidField: "updateTo" },
  { name: "bad-json", payload: "{" },
  { name: "bad-signature", payload: JSON.stringify({ email, ...dates }), badSignature: true },
];

function sign(payload, key) {
  const message = `${Buffer.from('{"alg":"HS256"}').toString("base64url")}.${Buffer.from(payload).toString("base64url")}`;
  return `${message}.${createHmac("sha256", key).update(message).digest("base64url")}`;
}

function native(value, raw = false) {
  if (value instanceof Error) return {
    name: value.name, message: value.message, keys: Object.keys(value),
    properties: native(Object.fromEntries(Object.entries(value)), raw),
    ...(Array.isArray(value.issues) ? { issues: native(value.issues, raw) } : {}),
    ...(raw ? { ownProperties: native(Object.fromEntries(Object.getOwnPropertyNames(value).map(key => [key, value[key]]))) } : {}),
  };
  if (value instanceof Headers) return [...value];
  if (Array.isArray(value)) return value.map(child => native(child, raw));
  if (value !== null && typeof value === "object" && !(value instanceof Date)) {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, native(child, raw)]));
  }
  return observeValue(value);
}

async function captureCase(backend, scenario, callbackURL, recorder, diagnostics) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  let enabled = false;
  const record = value => { if (enabled) events.push(native(value)); };
  const options = {
    database: sqlite ?? memoryAdapter(memory), baseURL: origin, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { cookieCache: { enabled: false } },
    emailVerification: {
      beforeEmailVerification(user) { record({ kind: "verification.before", user }); },
      afterEmailVerification(user) { record({ kind: "verification.after", user }); },
    },
    databaseHooks: Object.fromEntries(tables.map(model => [model, Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
      before(data) { record({ kind: "hook", model, operation, phase: "before", data }); },
      after(data) { record({ kind: "hook", model, operation, phase: "after", data }); },
    }]))])),
    onAPIError: { onError(error) {
      record({ kind: "api-error", error });
      diagnostics.push({ backend, scenario: scenario.name, callbackURL, source: "onAPIError", error: native(error, true) });
    } },
  };
  const stored = () => Object.fromEntries(tables.map(model => [model, observeValue(sqlite
    ? sqlite.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model]) ]));
  try {
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const { adapter } = await auth.$context;
    await adapter.create({ model: "user", forceAllowId: true, data: {
      id: "payload-owner", name: "Payload Owner", email, emailVerified: false,
      image: null, createdAt: date, updatedAt: date,
    } });
    const before = stored();
    const token = sign(scenario.payload, scenario.badSignature ? "wrong-signing-secret" : secret);
    const url = new URL("/api/auth/verify-email", origin);
    url.searchParams.set("token", token);
    if (callbackURL !== null) url.searchParams.set("callbackURL", callbackURL);
    const request = new Request(url, { headers: { origin } });
    enabled = true;
    recorder.events = events;
    recorder.context = { backend, scenario: scenario.name, callbackURL };
    let response;
    try {
      const result = await auth.handler(request);
      response = { status: result.status, statusText: result.statusText, headers: [...result.headers],
        cookies: result.headers.getSetCookie(), body: await result.text() };
    } finally { enabled = false; recorder.events = null; recorder.context = null; }
    const after = stored();
    try {
      assert.deepEqual(after, before, "Malformed verification input must preserve every stored table");
      assert.deepEqual(response.cookies, []);
      const errors = events.filter(event => event.kind === "api-error");
      const consoleErrors = events.filter(event => event.kind === "console.error");
      assert.deepEqual(events.filter(event => !["api-error", "console.error"].includes(event.kind)), [],
        "Malformed verification input must precede database queries and callbacks");
      if (scenario.invalidField) {
        assert.equal(response.status, 500);
        assert.equal(response.body, "");
        assert.equal(response.headers.some(([name]) => name === "location"), false);
        assert.equal(errors.length, 1);
        assert.equal(errors[0].error.name, "ZodError");
        assert.equal(errors[0].error.issues.length, 1);
        assert.deepEqual(errors[0].error.issues[0].path, [scenario.invalidField]);
        assert.equal(errors[0].error.issues[0].code, "invalid_type");
        assert.equal(consoleErrors.length, 1);
        assert.deepEqual(events.map(event => event.kind), ["api-error", "console.error"]);
      } else if (callbackURL !== null) {
        assert.equal(response.status, 302);
        assert.equal(response.body, "");
        assert.equal(new Headers(response.headers).get("location"), "/verified?source=mail&error=INVALID_TOKEN#done");
        assert.deepEqual(events, []);
      } else {
        assert.equal(response.status, 401);
        assert.deepEqual(JSON.parse(response.body), { code: "INVALID_TOKEN", message: "Invalid token" });
        assert.equal(errors.length, 1);
        assert.deepEqual(errors[0].error.properties.body, { code: "INVALID_TOKEN", message: "Invalid token" });
        assert.deepEqual(consoleErrors, []);
        assert.deepEqual(events.map(event => event.kind), ["api-error"]);
      }
    } catch (error) {
      diagnostics.push({ backend, scenario: scenario.name, callbackURL, before, events, response, after, assertion: native(error, true) });
      throw error;
    }
    return { backend, scenario: scenario.name, callbackURL, token, payload: scenario.payload,
      request: { method: request.method, url: request.url, headers: [...request.headers] }, before, events, response, after };
  } finally { recorder.events = null; recorder.context = null; sqlite?.close(); }
}

export async function captureEmailVerificationPayload({ diagnostics = [] } = {}) {
  const recorder = { events: null, context: null };
  const originalConsoleError = console.error;
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "email-verification-payload-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        recorder.events?.push({ kind: "query", operation: attributes["db.operation.name"], model: attributes["db.collection.name"] });
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  console.error = (...args) => {
    assert.ok(recorder.events, "A console error outside the measured request must fail the capture");
    recorder.events.push({ kind: "console.error", args: native(args) });
    diagnostics.push({ ...recorder.context, source: "console.error", args: native(args, true) });
  };
  try {
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("email-verification-payload-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const cases = [];
    for (const backend of ["memory", "sqlite"]) for (const scenario of scenarios) for (const callbackURL of [null, callback]) {
      cases.push(await captureCase(backend, scenario, callbackURL, recorder, diagnostics));
    }
    assert.equal(cases.length, 20);
    return { version, scenarios, cases };
  } finally { console.error = originalConsoleError; trace.disable(); }
}

if (import.meta.main) {
  const diagnostics = [];
  try {
    const serialized = `${JSON.stringify(await captureEmailVerificationPayload({ diagnostics }), null, 2)}\n`;
    if (process.argv[2]) writeFileSync(process.argv[2], serialized);
    else process.stdout.write(serialized);
  } finally {
    if (process.argv[2]) writeFileSync(`${process.argv[2]}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
