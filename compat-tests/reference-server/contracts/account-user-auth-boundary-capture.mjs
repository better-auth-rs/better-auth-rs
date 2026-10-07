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
import { selectedRelationScenarios } from "./account-user-selected-relations-capture.mjs";
import { overrideScenarios, prepareCallbackOverride, verifyCallbackOverride } from "./account-user-auth-boundary-override.mjs";

const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

const origin = "http://account-user-auth-boundary.test";
const secret = "account-user-auth-boundary-fixture-secret-at-least-32-characters";
const date = new Date("2030-01-02T03:04:05.000Z");
const idToken = "account-user-auth-fixture-id-token";
const nonce = "account-user-auth-fixture-nonce";
const password = "account-user-auth-fixture-password";
const passwordHash = "account-user-auth-fixture-password-hash";
const expiresIn = 3600;
const tables = ["user", "session", "account", "verification"];
const requestHeaders = {
  origin, "content-type": "application/json", "user-agent": "account-user-auth-contract", "x-forwarded-for": "203.0.113.8",
};
const scenarios = [
  { name: "social-alternate-owner", route: "social", relation: "alternate-account-reference" },
  { name: "social-owner-many", route: "social", relation: "reverse-user-reference-many", many: true },
  { name: "social-accounts-one", route: "social", relation: "unique-account-reference", accountsOne: true },
  { name: "email-accounts-one", route: "email", relation: "unique-account-reference", accountsOne: true },
  ...overrideScenarios,
];

function native(value) {
  if (value instanceof Error) return {
    name: value.name, message: value.message,
    properties: Object.fromEntries(Object.entries(value).map(([key, child]) => [key, native(child)])),
    keys: Object.keys(value),
  };
  if (Array.isArray(value)) return value.map(native);
  if (value !== null && typeof value === "object" && !(value instanceof Date)) {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, native(child)]));
  }
  return structuredClone(value);
}

function rowsFor(scenario) {
  return {
    user: ["a", "b", "c"].map(suffix => ({
      id: `user-${suffix}`, name: `User ${suffix}`, email: `${suffix}@account-user-auth-boundary.test`,
      emailVerified: true, image: scenario.many ? suffix === "a" ? "account-b" : "account-a" : `image-${suffix}`,
      createdAt: date, updatedAt: date,
    })),
    account: ["a", "b"].map(suffix => ({
      id: `account-${suffix}`, accountId: scenario.accountsOne ? `user-${suffix}` : suffix === "a" ? "external-owner" : "external-decoy",
      providerId: scenario.accountsOne ? "credential" : "google", userId: `user-${suffix}`,
      accessToken: suffix === "a" ? "user-b" : "user-a", refreshToken: null, idToken: null,
      accessTokenExpiresAt: null, refreshTokenExpiresAt: null, scope: null,
      password: scenario.accountsOne ? passwordHash : null, createdAt: date, updatedAt: date,
    })),
  };
}

function optionsFor(scenario, joins, state) {
  const relation = selectedRelationScenarios.find(value => value.name === scenario.relation);
  assert.ok(relation);
  const record = event => { if (state.enabled) state.events.push(native(event)); };
  const field = (model, declarations, configured) => Object.fromEntries(Object.entries({ ...declarations, ...configured })
    .map(([name, declaration]) => [name, {
      type: "string", required: false, ...declaration,
      transform: { output(value) { record({ kind: "output", model, field: name, value }); return value; } },
    }]));
  const profile = {
    sub: scenario.accountsOne ? "external-unlinked" : "external-owner",
    name: "Provider User", email: "a@account-user-auth-boundary.test",
    email_verified: true, picture: "provider-image",
  };
  return {
    baseURL: origin, secret, logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    advanced: { database: { joins } },
    session: { expiresIn, cookieCache: { enabled: false } },
    user: {
      additionalFields: field("user", { image: {}, name: {} }, relation.userFields),
      validateUserInfo(data, context) {
        record({ kind: "admission", data, request: { url: context.request.url, method: context.request.method, headers: [...context.request.headers] } });
      },
    },
    account: { ...(scenario.callback ? { storeStateStrategy: "cookie" } : {}), additionalFields: field("account", {
      accessToken: {}, accountId: {}, userId: { references: { model: "user", field: "id" } },
    }, relation.accountFields) },
    emailAndPassword: {
      enabled: true,
      password: {
        hash(value) { record({ kind: "password.hash", value }); return Promise.resolve(passwordHash); },
        verify(value) { record({ kind: "password.verify", value }); return Promise.resolve(value.hash === passwordHash && value.password === password); },
      },
    },
    socialProviders: { google: {
      clientId: "fixture-client", clientSecret: "fixture-client-secret",
      ...(scenario.overrideUserInfo ? { overrideUserInfoOnSignIn: true } : {}),
      verifyIdToken(token, receivedNonce) {
        record({ kind: "provider.verify", token, nonce: receivedNonce });
        return Promise.resolve(token === idToken && receivedNonce === nonce);
      },
      getUserInfo(tokens) {
        record({ kind: "provider.userInfo", tokens });
        return Promise.resolve({
          user: { name: profile.name, email: profile.email, emailVerified: profile.email_verified, image: profile.picture },
          data: { ...profile },
        });
      },
    } },
    databaseHooks: Object.fromEntries(tables.map(model => [model, Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
      before(data) { record({ kind: "hook", model, operation, phase: "before", data }); },
      after(data) { record({ kind: "hook", model, operation, phase: "after", data }); },
    }]))])),
    onAPIError: { onError(error) { record({ kind: "api-error", error }); } },
  };
}

function milliseconds(value) {
  assert.ok(value instanceof Date || typeof value === "string");
  const result = value instanceof Date ? value.getTime() : Date.parse(value);
  assert.ok(Number.isFinite(result));
  return result;
}

function normalizeRecord(model, row, dynamic, replacements) {
  if (row === null) return row;
  return Object.fromEntries(Object.entries(row).map(([key, value]) => {
    const anchor = model === "session" && ["createdAt", "updatedAt", "expiresAt"].includes(key)
      ? dynamic.session?.[key] : model === "account" && row.id === "account-a" && key === "updatedAt" ? dynamic.accountUpdatedAt : undefined;
    if (anchor !== undefined && (value instanceof Date || typeof value === "string") && milliseconds(value) === anchor) {
      const label = `<${model}.${key}>`;
      return [key, value instanceof Date ? { type: "date", value: label } : label];
    }
    return [key, normalize(value, replacements)];
  }));
}

function normalize(value, replacements, embedded = false) {
  if (embedded && typeof value === "string") return [...replacements].reduce((text, [from, to]) => text.replaceAll(from, to), value);
  if (typeof value === "string" && replacements.has(value)) return replacements.get(value);
  if (value instanceof Date || value === undefined) return observeValue(value);
  if (Array.isArray(value)) return value.map(child => normalize(child, replacements, embedded));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value)
    .map(([key, child]) => [key, normalize(child, replacements, embedded)]));
  return value;
}

function verifyResult(backend, scenario, joins, before, after, response, body, events, requestWindow) {
  const admissions = events.filter(event => event.kind === "admission");
  const hooks = events.filter(event => event.kind === "hook");
  const errors = events.filter(event => event.kind === "api-error");
  const queries = events.filter(event => event.kind === "query").map(({ operation, model }) => [operation, model]);
  const dynamic = {};
  const replacements = new Map();
  assert.deepEqual(after.user, before.user, "Relation consumption must not rewrite any User field");
  assert.deepEqual(after.verification, before.verification);
  assert.equal(events.filter(event => event.kind.startsWith("password.")).length, 0, "The single Account shape fails before password work");
  if (scenario.route === "social") {
    assert.deepEqual(events.filter(event => event.kind.startsWith("provider.")), [
      { kind: "provider.verify", token: idToken, nonce },
      { kind: "provider.userInfo", tokens: { idToken, accessToken: undefined, refreshToken: undefined, user: undefined } },
    ]);
  } else assert.equal(events.filter(event => event.kind.startsWith("provider.")).length, 0);
  if (scenario.accountsOne) {
    assert.equal(response.status, 500);
    assert.equal(body, "");
    assert.equal(errors.length, 1);
    assert.equal(errors[0].error.name, "TypeError");
    assert.match(errors[0].error.message, /accounts\.find/);
    assert.deepEqual(admissions, []);
    assert.deepEqual(hooks, []);
    assert.deepEqual(after, before, "Both .find failures must precede every write and session issuance");
    assert.deepEqual(queries, [
      ...(scenario.route === "social" ? [["findMany", "account"]] : []),
      ["findOne", "user"], ...(!joins ? [["findOne", "account"]] : []),
    ]);
    assert.deepEqual(response.headers.getSetCookie(), []);
    return { dynamic, replacements, cookie: null };
  }
  assert.equal(admissions.length, 1);
  assert.equal(admissions[0].data.user.id, scenario.many ? undefined : "user-b");
  assert.equal(Object.hasOwn(admissions[0].data.user, "id"), true);
  assert.equal(admissions[0].data.source.action, "sign-in");
  assert.equal(admissions[0].data.source.method, "oauth");
  assert.equal(admissions[0].data.source.oauth.providerId, "google");
  const sessionBefore = hooks.find(event => event.model === "session" && event.phase === "before");
  assert.ok(sessionBefore);
  assert.equal(Object.hasOwn(sessionBefore.data, "userId"), true);
  assert.equal(sessionBefore.data.userId, admissions[0].data.user.id, "Admission and session issuance use the same selected User ID, including undefined");
  assert.deepEqual(queries, [
    ["findMany", "account"], ...(!joins ? [[scenario.many ? "findMany" : "findOne", "user"]] : []),
    ["update", "account"], ["create", "session"],
  ]);
  const failedSession = scenario.many && backend === "sqlite";
  assert.deepEqual(hooks.map(({ model, operation, phase }) => [model, operation, phase]), [
    ["account", "update", "before"], ["account", "update", "after"], ["session", "create", "before"],
    ...(!failedSession ? [["session", "create", "after"]] : []),
  ]);
  const updatedAccount = after.account.find(row => row.id === "account-a");
  assert.ok(updatedAccount);
  assert.deepEqual(after.account, before.account.map(row => row.id === "account-a"
    ? { ...row, idToken, updatedAt: updatedAccount.updatedAt } : row));
  assert.equal(updatedAccount.userId, "user-a", "The canonical Account owner remains distinct from the alternate selected User");
  dynamic.accountUpdatedAt = milliseconds(updatedAccount.updatedAt);
  assert.ok(dynamic.accountUpdatedAt >= requestWindow.start && dynamic.accountUpdatedAt <= requestWindow.end);
  const accountAfter = hooks.find(event => event.model === "account" && event.phase === "after").data;
  assert.equal(milliseconds(accountAfter.updatedAt), dynamic.accountUpdatedAt);
  const issued = sessionBefore.data;
  assert.equal(typeof issued.token, "string");
  assert.equal(issued.token.length, 32);
  assert.ok(!before.session.some(row => row.token === issued.token));
  replacements.set(issued.token, "<session-token>");
  dynamic.session = Object.fromEntries(["createdAt", "updatedAt", "expiresAt"].map(key => [key, milliseconds(issued[key])]));
  assert.ok(dynamic.session.createdAt >= requestWindow.start && dynamic.session.createdAt <= requestWindow.end);
  assert.ok(dynamic.session.updatedAt >= dynamic.session.createdAt && dynamic.session.updatedAt <= requestWindow.end);
  assert.ok(dynamic.accountUpdatedAt <= dynamic.session.createdAt);
  const expiryOrigin = dynamic.session.expiresAt - expiresIn * 1000;
  assert.ok(expiryOrigin >= requestWindow.start && expiryOrigin <= dynamic.session.createdAt);
  if (failedSession) {
    assert.equal(response.status, 500);
    assert.equal(body, "");
    assert.deepEqual(after.session, []);
    assert.equal(errors.length, 1);
    assert.match(errors[0].error.message, /NOT NULL constraint failed: session\.userId/);
    assert.deepEqual(response.headers.getSetCookie(), []);
    return { dynamic, replacements, cookie: null };
  }
  assert.equal(response.status, 200);
  assert.deepEqual(errors, []);
  assert.equal(after.session.length, 1);
  const stored = after.session[0];
  const completed = hooks.find(event => event.model === "session" && event.phase === "after").data;
  assert.equal(typeof stored.id, "string");
  assert.ok(stored.id.length > 0);
  assert.equal(completed.id, stored.id);
  assert.equal(stored.token, issued.token);
  assert.equal(completed.token, issued.token);
  assert.equal(stored.userId, admissions[0].data.user.id);
  assert.equal(Object.hasOwn(stored, "userId"), !scenario.many);
  assert.equal(completed.userId, stored.userId);
  assert.equal(stored.ipAddress, requestHeaders["x-forwarded-for"]);
  assert.equal(stored.userAgent, requestHeaders["user-agent"]);
  for (const key of ["createdAt", "updatedAt", "expiresAt"]) {
    assert.equal(milliseconds(stored[key]), dynamic.session[key]);
    assert.equal(milliseconds(completed[key]), dynamic.session[key]);
  }
  replacements.set(stored.id, "<session-id>");
  const json = JSON.parse(body);
  assert.equal(json.token, stored.token);
  assert.equal(json.redirect, false);
  const seededUsers = rowsFor(scenario).user;
  const expectedUser = scenario.many
    ? Object.fromEntries(seededUsers.slice(1).map((user, index) => [index, user])) : seededUsers[1];
  assert.deepEqual(json, { redirect: false, token: stored.token, user: JSON.parse(JSON.stringify(expectedUser)) });
  const cookies = response.headers.getSetCookie();
  assert.equal(cookies.length, 1);
  const separator = cookies[0].indexOf(";");
  assert.ok(separator > 0);
  const cookieValue = cookies[0].slice(0, separator);
  const expectedSignature = createHmac("sha256", secret).update(stored.token).digest("base64");
  assert.equal(cookieValue, `better-auth.session_token=${encodeURIComponent(`${stored.token}.${expectedSignature}`)}`);
  assert.equal(cookies[0].slice(separator), `; Max-Age=${expiresIn}; Path=/; HttpOnly; SameSite=Lax`);
  return { dynamic, replacements, cookie: { raw: cookies[0], normalized: `better-auth.session_token=<verified-signed-session-token>${cookies[0].slice(separator)}` } };
}

async function captureCase(backend, scenario, joins, recorder) {
  const state = { enabled: false, events: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = sqlite ?? memoryAdapter(memory);
  const options = { ...optionsFor(scenario, joins, state), database };
  const stored = () => structuredClone(Object.fromEntries(tables.map(model => [model, sqlite
    ? sqlite.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model]])));
  try {
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const seedAdapter = (await auth.$context).adapter;
    const seed = rowsFor(scenario);
    // The HTTP router validates the physical schema; seed in the selected foreign-key direction.
    for (const model of scenario.many ? ["account", "user"] : ["user", "account"]) for (const data of seed[model]) {
      await seedAdapter.create({ model, forceAllowId: true, data });
    }
    const before = stored();
    const callback = scenario.callback ? await prepareCallbackOverride(auth, recorder, { origin, requestHeaders, idToken }) : null;
    if (callback) assert.deepEqual(stored(), before, "Cookie state setup must not change database rows");
    const input = scenario.route === "social" ? { provider: "google", idToken: { token: idToken, nonce } }
      : { email: "a@account-user-auth-boundary.test", password };
    const request = callback?.request ?? new Request(`${origin}/api/auth/sign-in/${scenario.route}`, {
      method: "POST", headers: requestHeaders, body: JSON.stringify(input),
    });
    state.enabled = true;
    recorder.events = state.events;
    const requestWindow = { start: Date.now() };
    let response;
    try { response = await auth.handler(request); }
    finally { requestWindow.end = Date.now(); state.enabled = false; recorder.events = null; }
    const body = await response.text();
    const after = stored();
    let verified;
    try { verified = callback
      ? verifyCallbackOverride({ backend, joins, before, after, response, body, events: state.events, requestWindow, callback,
        requestHeaders, idToken, secret, expiresIn, milliseconds })
      : verifyResult(backend, scenario, joins, before, after, response, body, state.events, requestWindow); }
    catch (error) {
      const evidence = `${JSON.stringify(observeValue({ backend, scenario, joins, requestWindow, before, after, events: state.events,
        response: { status: response.status, statusText: response.statusText, headers: [...response.headers], cookies: response.headers.getSetCookie(), body }, error: native(error) }), null, 2)}\n`;
      if (process.argv[2]) writeFileSync(`${process.argv[2]}.failure.json`, evidence);
      else process.stderr.write(evidence);
      throw error;
    }
    const { dynamic, replacements, cookie } = verified;
    const headers = [...response.headers].map(([name, value]) => {
      if (name !== "set-cookie" || !cookie) return [name, value];
      if (callback) return [name, value.replaceAll(cookie.raw, cookie.normalized)];
      assert.equal(value, cookie.raw);
      return [name, cookie.normalized];
    });
    const cookies = response.headers.getSetCookie().map(value => cookie && value === cookie.raw ? cookie.normalized : value);
    const normalizedBody = [...replacements].reduce((text, [from, to]) => text.replaceAll(from, to), body);
    return {
      backend, scenario: scenario.name, joins,
      ...(callback ? { setup: normalize(callback.setup, replacements, true) } : {}),
      request: callback
        ? normalize({ url: request.url, method: request.method, headers: [...request.headers], body: null }, replacements, true)
        : { url: request.url, method: request.method, headers: [...request.headers], body: input },
      before: observeValue(before),
      events: state.events.map(event => event.kind === "hook"
        ? { ...event, data: normalizeRecord(event.model, event.data, dynamic, replacements) } : normalize(event, replacements, Boolean(callback))),
      response: { status: response.status, statusText: response.statusText, headers, cookies, body: normalizedBody },
      after: Object.fromEntries(tables.map(model => [model, after[model].map(row => normalizeRecord(model, row, dynamic, replacements))])),
      checked: { noNetwork: true, completeStorage: true, admissionMatchesSessionInput: !scenario.accountsOne && (!callback || Boolean(dynamic.session)),
        preservedCanonicalAccountOwner: !scenario.accountsOne, sessionDatesWithinRequest: Boolean(dynamic.session),
        sessionCookieMatchesStoredToken: cookie !== null,
        ...(callback ? { userProfileOverrideReached: true, oauthStateAndCodeVerifierVerified: true } : {}) },
    };
  } finally { state.enabled = false; recorder.events = null; recorder.exchange = null; sqlite?.close(); }
}

export async function captureAccountUserAuthBoundary() {
  const recorder = { events: null, exchange: null };
  const originalFetch = globalThis.fetch;
  const originalConsoleError = console.error;
  const networkCalls = [];
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "account-user-auth-boundary-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        recorder.events?.push({ kind: "query", operation: attributes["db.operation.name"], model: attributes["db.collection.name"] });
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    if (recorder.exchange) return recorder.exchange(request);
    networkCalls.push({ url: request.url, method: request.method });
    throw new Error("The account relation auth capture must not use network requests");
  };
  // Keep router errors without host-specific stacks; preserve all other error properties and console arguments.
  console.error = (...args) => {
    assert.ok(recorder.events, "A console error outside the measured request must fail the capture");
    recorder.events.push({ kind: "console.error", args: native(args) });
  };
  try {
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("account-user-auth-boundary-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const cases = [];
    for (const scenario of scenarios) for (const backend of ["memory", "sqlite"]) for (const joins of [false, true]) {
      cases.push(await captureCase(backend, scenario, joins, recorder));
      assert.deepEqual(networkCalls, []);
    }
    assert.equal(cases.length, 24);
    return { version, scenarios, cases };
  } finally { globalThis.fetch = originalFetch; console.error = originalConsoleError; trace.disable(); }
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureAccountUserAuthBoundary(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
