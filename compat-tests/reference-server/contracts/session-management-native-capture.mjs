import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { createAuthMiddleware, isAPIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { kAPIErrorHeaderSymbol, serializeSignedCookie } from "better-call";
import { observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
const now = 2_000_000_000_000;
const origin = "http://session-management-native.test";
const secret = "session-management-native-contract-secret-at-least-32-characters";
const tables = ["user", "session", "account", "verification"];
const routes = [
  ["list", "/list-sessions", "listSessions"],
  ["revoke", "/revoke-session", "revokeSession"],
  ["revoke-all", "/revoke-sessions", "revokeSessions"],
  ["revoke-other", "/revoke-other-sessions", "revokeOtherSessions"],
];
const userKinds = [
  "owner", "foreign", "missing-id", "undefined-id", "null-id", "number-id",
  "false-user", "null-user", "undefined-user", "array-user",
];

function nativeUser(kind) {
  const marker = { label: "native", at: new Date(now - 2000), absent: undefined };
  switch (kind) {
    case "owner": return { id: "7", marker };
    case "foreign": return { id: "foreign", marker };
    case "missing-id": return { marker };
    case "undefined-id": return { id: undefined, marker };
    case "null-id": return { id: null, marker };
    case "number-id": return { id: 7, marker };
    case "false-user": return false;
    case "null-user": return null;
    case "undefined-user": return undefined;
    case "array-user": return [{ id: "7", marker }];
    default: throw new Error(`Unknown native user kind: ${kind}`);
  }
}

function injectedSession(scenario) {
  const session = {
    id: "injected-session", userId: "untrusted-session-owner", token: "7",
    expiresAt: new Date(now + 3_600_000), createdAt: new Date(now - 1000), updatedAt: new Date(now - 1000),
  };
  switch (scenario.tokenKind) {
    case "missing": delete session.token; break;
    case "undefined": session.token = undefined; break;
    case "null": session.token = null; break;
    case "number": session.token = 7; break;
    case "object": session.token = { token: "7" }; break;
  }
  return { session, user: nativeUser(scenario.userKind ?? "owner") };
}

export function sessionManagementScenarios() {
  const cases = [];
  for (const [operation] of routes) for (const userKind of userKinds) {
    cases.push({ name: `stateless-${operation}-${userKind}`, operation, deployment: "stateless", source: "hook", userKind });
  }
  for (const tokenKind of ["missing", "undefined", "null", "number", "object"]) {
    cases.push({ name: `stateless-revoke-other-token-${tokenKind}`, operation: "revoke-other", deployment: "stateless", source: "hook", tokenKind });
  }
  for (const [name, target, userKind] of [
    ["expired-owned", "owner-expired-token", "owner"],
    ["expired-foreign", "foreign-expired-token", "owner"],
    ["missing-target-missing-id", "missing-token", "missing-id"],
  ]) cases.push({ name: `stateless-revoke-${name}`, operation: "revoke", deployment: "stateless", source: "hook", target, userKind });
  for (const [operation] of routes.slice(1)) for (const revoked of [false, true]) {
    cases.push({ name: `stateful-${operation}-${revoked ? "revoked" : "live"}`, operation, deployment: "stateful", source: "hook", userKind: "foreign", revoked });
  }
  for (const [name, revoked, stale] of [["fresh-live", false, false], ["fresh-revoked", true, false], ["stale", false, true]]) {
    cases.push({ name: `cached-list-${name}`, operation: "list", deployment: "stateful", source: "cookie", revoked, stale });
  }
  for (const [operation] of routes.slice(1)) {
    cases.push({ name: `cached-${operation}-revoked`, operation, deployment: "stateful", source: "cookie", revoked: true });
  }
  assert.equal(cases.length, 60);
  assert.equal(new Set(cases.map(value => value.name)).size, cases.length);
  return cases;
}

function headerValues(headers) {
  const values = new Headers(headers);
  return { entries: [...values], cookies: values.getSetCookie() };
}

function returned(value) {
  return isAPIError(value)
    ? { kind: "api-error", name: value.name, message: value.message, status: value.statusCode, body: observeValue(value.body) }
    : { kind: "value", value: observeValue(value) };
}

async function captureCase(scenario) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const events = [];
  const injected = scenario.source === "hook" ? injectedSession(scenario) : undefined;
  const [, path, api] = routes.find(([operation]) => operation === scenario.operation);
  let recording = false;
  const record = event => { if (recording) events.push(observeValue(event)); };
  const auth = betterAuth({
    ...(scenario.deployment === "stateful" ? { database: memoryAdapter(memory) } : {}),
    baseURL: origin, secret, logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { freshAge: 60, disableSessionRefresh: true, cookieCache: { enabled: true, strategy: "compact", refreshCache: false, maxAge: 300 } },
    hooks: {
      before: createAuthMiddleware(async context => {
        if (!recording) return;
        if (scenario.source === "hook") context.context.session = injected;
        record({ phase: "before", path: context.path, session: context.context.session });
      }),
      after: createAuthMiddleware(async context => {
        record({ phase: "after", path: context.path, session: context.context.session, returned: returned(context.context.returned) });
        if (recording && scenario.source === "hook" && scenario.deployment === "stateless") {
          assert.equal(context.context.session, injected, "Stateless middleware must retain the trusted native snapshot");
          assert.equal(context.context.session.user, injected.user, "Native user identity must survive the dispatcher");
        }
      }),
    },
    databaseHooks: { session: { delete: {
      before(data) { record({ phase: "delete.before", data }); },
      after(data) { record({ phase: "delete.after", data }); },
    } } },
  });
  const context = await auth.$context;
  assert.equal(Boolean(context.options.database || context.options.secondaryStorage), scenario.deployment === "stateful");
  for (const [id, name] of [["7", "Owner"], ["foreign", "Foreign"]]) {
    await context.adapter.create({ model: "user", forceAllowId: true, data: {
      id, name, email: `${id}@session-management-native.test`, emailVerified: false, image: null,
      createdAt: new Date(now - 86_400_000), updatedAt: new Date(now - 86_400_000),
    } });
  }
  for (const [id, userId, token, expired] of [
    ["current", "7", "7", false],
    ["owner-other", "7", "owner-other-token", false],
    ["owner-expired", "7", "owner-expired-token", true],
    ["foreign-other", "foreign", "foreign-other-token", false],
    ["foreign-expired", "foreign", "foreign-expired-token", true],
  ]) {
    await context.adapter.create({ model: "session", forceAllowId: true, data: {
      id, userId, token, ipAddress: "192.0.2.1", userAgent: "session-management-contract",
      createdAt: new Date(now - (scenario.stale && id === "current" ? 120_000 : 1000)),
      updatedAt: new Date(now - 1000), expiresAt: new Date(now + (expired ? -1 : 3_600_000)),
    } });
  }
  const storage = async () => {
    // DB-less deployments own a private Memory map; compare the complete adapter view without field transforms.
    const value = observeValue(Object.fromEntries(await Promise.all(tables.map(async model => [model,
      await context.adapter.findMany({ model }),
    ]))));
    if (scenario.deployment === "stateful") assert.deepEqual(value, observeValue(memory));
    return value;
  };
  const headers = new Headers({ origin });
  let cacheSetup;
  if (scenario.deployment === "stateful") {
    const signed = (await serializeSignedCookie(context.authCookies.sessionToken.name, "7", secret)).split(";", 1)[0];
    headers.set("cookie", signed);
    if (scenario.source === "cookie") {
      const seeded = await auth.api.getSession({ headers, returnHeaders: true, returnStatus: true });
      assert.equal(seeded.status, 200);
      assert.equal(seeded.response.session.token, "7");
      const cookies = seeded.headers.getSetCookie();
      assert.ok(cookies.some(value => value.startsWith(`${context.authCookies.sessionData.name}=`)));
      cacheSetup = { response: observeValue(seeded.response), headers: headerValues(seeded.headers) };
      headers.set("cookie", [signed, ...cookies.map(value => value.split(";", 1)[0])].join("; "));
    }
    if (scenario.revoked) await context.adapter.delete({ model: "session", where: [{ field: "token", value: "7" }] });
  }
  const body = scenario.operation === "revoke" ? { token: scenario.target ?? "owner-other-token" } : undefined;
  const before = await storage();
  recording = true;
  let result;
  try {
    const response = await auth.api[api]({ headers, ...(body === undefined ? {} : { body }), returnHeaders: true, returnStatus: true });
    result = { ...returned(response.response), status: response.status, headers: headerValues(response.headers) };
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    assert.ok(error instanceof Error);
    result = isAPIError(error)
      ? { ...returned(error), headers: headerValues(error[kAPIErrorHeaderSymbol] ?? error.headers) }
      : { kind: "error", name: error.name, message: error.message, headers: headerValues() };
  }
  recording = false;
  const after = await storage();
  for (const table of ["user", "account", "verification"]) assert.deepEqual(after[table], before[table]);
  assert.equal(events.filter(event => event.phase === "before").length, 1);
  if (scenario.operation === "list") assert.deepEqual(after, before);
  if (scenario.deployment === "stateful" && scenario.operation !== "list" && scenario.revoked) {
    assert.equal(result.kind, "api-error");
    assert.equal(result.status, 401);
    assert.deepEqual(result.body, { message: "Unauthorized", code: "UNAUTHORIZED" });
    assert.deepEqual(after, before);
    assert.deepEqual(events.map(event => event.phase), ["before", "after"]);
    assert.equal(events.at(-1).session, null);
  }
  if (scenario.deployment === "stateful" && scenario.source === "hook" && !scenario.revoked) {
    assert.equal(result.kind, "value");
    assert.deepEqual(result.value, { status: true });
    assert.equal(events.at(-1).session.user.id, "7");
    assert.equal(events.at(-1).session.session.token, "7");
    assert.deepEqual(after.session.filter(value => value.userId === "foreign"), before.session.filter(value => value.userId === "foreign"));
  }
  if (scenario.name === "stateless-revoke-expired-owned") {
    assert.deepEqual(result.value, { status: true });
    assert.deepEqual(after.session, before.session.filter(value => value.token !== "owner-expired-token"));
    assert.deepEqual(events.filter(event => event.phase.startsWith("delete.")).map(event => event.phase), ["delete.before", "delete.after"]);
  }
  if (["stateless-revoke-expired-foreign", "stateless-revoke-missing-target-missing-id"].includes(scenario.name)) {
    assert.deepEqual(result.value, { status: true });
    assert.deepEqual(after, before);
    assert.deepEqual(events.map(event => event.phase), ["before", "after"]);
  }
  if (scenario.source === "cookie" && scenario.operation === "list") {
    if (scenario.stale) {
      assert.equal(result.kind, "api-error");
      assert.equal(result.status, 403);
      assert.equal(result.body.code, "SESSION_NOT_FRESH");
    } else {
      assert.equal(result.kind, "value");
      assert.deepEqual(result.value, before.session.filter(value => value.userId === "7" && value.expiresAt.value > new Date(now).toISOString()));
    }
  }
  return {
    ...scenario, path, input: { headers: [...headers], body: observeValue(body), injected: observeValue(injected) },
    ...(cacheSetup ? { cacheSetup } : {}), before, events, result, after,
  };
}

export async function captureSessionManagementNative() {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  const OriginalDate = globalThis.Date;
  class FixedDate extends OriginalDate {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
    static [Symbol.hasInstance](value) { return value instanceof OriginalDate; }
  }
  globalThis.Date = FixedDate;
  try {
    const cases = [];
    for (const scenario of sessionManagementScenarios()) cases.push(await captureCase(scenario));
    return { version, now, storageSurface: "complete-adapter-view", cases };
  } finally { globalThis.Date = OriginalDate; }
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureSessionManagementNative(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
