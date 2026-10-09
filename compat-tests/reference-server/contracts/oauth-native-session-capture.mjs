import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { serializeSignedCookie } from "better-call";
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { symmetricDecrypt } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { getOAuthState } from "../node_modules/better-auth/dist/api/state/oauth.mjs";
import { native } from "./user-verification-cleanup-support.mjs";

const version = "1.7.6";
const origin = "http://oauth-native-session.test";
const secret = "oauth-native-session-contract-secret-at-least-32-characters";
const timestamp = Date.parse("2030-01-02T03:04:05.000Z");
const token = "native-oauth-owner-session";
const email = "Owner@oauth-native-session.test";
const profile = { id: "provider-owner", name: "Provider Owner", email, emailVerified: true };
const models = ["user", "session", "account", "verification"];

const selectors = [
  { name: "owner", id: "owner" },
  { name: "number", id: 7 },
  { name: "string-number", id: "7" },
  { name: "zero", id: 0 },
  { name: "false", id: false },
  { name: "null", id: null },
  { name: "undefined", id: undefined },
  { name: "empty", id: "" },
  { name: "object", id: { owner: 7 } },
  { name: "array", id: [7] },
  { name: "surrogate", id: "\ud800" },
  { name: "email-undefined", id: "owner", email: undefined },
  { name: "email-null", id: "owner", email: null },
  { name: "email-number", id: "owner", email: 7 },
  { name: "email-undefined-different-allowed", id: "owner", email: undefined, allowDifferentEmails: true },
  { name: "email-null-different-allowed", id: "owner", email: null, allowDifferentEmails: true },
  { name: "email-number-different-allowed", id: "owner", email: 7, allowDifferentEmails: true },
  { name: "profile-update-owner", id: "owner", updateUserInfoOnLink: true },
  { name: "profile-update-number", id: 7, updateUserInfoOnLink: true },
  { name: "profile-update-undefined", id: undefined, updateUserInfoOnLink: true },
  { name: "many", many: true },
  { name: "many-empty", many: true, empty: true },
  { name: "missing-session", missing: true },
];

function cookiePairs(response) {
  return response.headers.getSetCookie().map(value => value.split(";", 1)[0]);
}

function normalize(value, replacements) {
  if (typeof value === "string") return replacements.get(value) ?? value;
  if (Array.isArray(value)) return value.map(item => normalize(item, replacements));
  if (value && typeof value === "object") return Object.fromEntries(
    Object.entries(value).map(([name, item]) => [name, normalize(item, replacements)]),
  );
  return value;
}

function cookies(response) {
  return response.headers.getSetCookie().map(value => {
    const [pair, ...attributes] = value.split(";");
    const split = pair.indexOf("=");
    return { name: pair.slice(0, split), value: pair.slice(split + 1) ? "<set>" : "", attributes };
  });
}

async function responseValue(response, replacements) {
  const text = await response.text();
  let body = text === "" ? { empty: true }
    : response.headers.get("content-type")?.includes("application/json") ? JSON.parse(text) : { text };
  if (typeof body?.url === "string" && body.url) {
    const url = new URL(body.url);
    for (const name of ["state", "code_challenge", "nonce"]) {
      const value = url.searchParams.get(name);
      if (value !== null) {
        assert.ok(value.length > 0);
        replacements.set(value, `<${name}>`);
        url.searchParams.set(name, `<${name}>`);
      }
    }
    body = { ...body, url: url.toString() };
  }
  const location = response.headers.get("location");
  return { status: response.status, body: native(body), location, cookies: cookies(response) };
}

async function captureCase(backend, operation, strategy, scenario, existing = false) {
  const events = [];
  const memory = Object.fromEntries(models.map(model => [model, []]));
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const cache = new Map();
  const replacements = new Map();
  const record = value => events.push(native(value));
  const options = {
    database: sqlite ?? memoryAdapter(memory), baseURL: origin, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    account: { storeStateStrategy: strategy, accountLinking: {
      allowDifferentEmails: Boolean(scenario.allowDifferentEmails),
      updateUserInfoOnLink: Boolean(scenario.updateUserInfoOnLink),
    } },
    session: { storeSessionInDatabase: true },
    ...(scenario.many ? {
      user: { additionalFields: { image: { type: "string", required: false,
        references: { model: "session", field: "id" } } } },
    } : { secondaryStorage: {
      async get(key) { record({ kind: "cache", operation: "get", key }); return cache.get(key) ?? null; },
      async set(key, value, ttl) { record({ kind: "cache", operation: "set", key, value: JSON.parse(value), ttl }); cache.set(key, value); },
      async delete(key) { record({ kind: "cache", operation: "delete", key }); cache.delete(key); },
    } }),
    socialProviders: { google: {
      clientId: "client", clientSecret: "secret",
      async verifyIdToken(value, nonce, context) {
        record({ kind: "verify", token: value, nonce, path: context.path,
          hasRequest: Boolean(context.request), session: context.context.session });
        return true;
      },
      async getUserInfo(tokens) {
        record({ kind: "profile", tokens });
        return { user: profile, data: { ...profile, sub: profile.id } };
      },
    } },
    hooks: { after: createAuthMiddleware(async context => {
      record({ kind: "after", path: context.path, session: context.context.session, state: await getOAuthState() });
    }) },
    onAPIError: { onError(error) { record({ kind: "api-error", error }); } },
  };
  if (sqlite) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const createdAt = new Date(timestamp);
  const owner = { id: "owner", name: "Owner", email, emailVerified: true,
    image: null, createdAt, updatedAt: createdAt };
  const session = { id: "owner-session", token, userId: "owner", expiresAt: new Date("2100-01-01T00:00:00.000Z"),
    ipAddress: "127.0.0.1", userAgent: "native-oauth-contract", createdAt, updatedAt: createdAt };
  try {
    for (const [model, data] of [["user", owner], ["session", session]]) {
      await context.adapter.create({ model, forceAllowId: true, data });
    }
    if (scenario.many && !scenario.empty) {
      await context.adapter.update({ model: "user", where: [{ field: "id", value: owner.id }], update: { image: session.id } });
      await context.adapter.create({ model: "user", forceAllowId: true, data: {
        ...owner, id: "other", name: "Other", email: "other@oauth-native-session.test", image: session.id,
      } });
    }
    if (existing) await context.adapter.create({ model: "account", forceAllowId: true, data: {
      id: "linked-account", userId: "owner", accountId: profile.id, providerId: "google",
      createdAt, updatedAt: createdAt,
    } });
    if (!scenario.many) cache.set(token, JSON.stringify({ session, user: {
      ...owner, id: scenario.id, email: Object.hasOwn(scenario, "email") ? scenario.email : email,
    } }));
    const inspectOne = context.adapter.findOne.bind(context.adapter);
    const inspectMany = context.adapter.findMany.bind(context.adapter);
    for (const method of ["findOne", "findMany", "create", "update", "delete", "deleteMany"]) {
      const original = context.adapter[method].bind(context.adapter);
      context.adapter[method] = async input => {
        record({ kind: "adapter", operation: method, phase: "before", input });
        try {
          const result = await original(input);
          record({ kind: "adapter", operation: method, phase: "after", result });
          return result;
        } catch (error) {
          record({ kind: "adapter", operation: method, phase: "error", error });
          throw error;
        }
      };
    }
    const ownerCookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, token, secret)).split(";", 1)[0];
    const body = { provider: "google", callbackURL: `${origin}/complete`,
      errorCallbackURL: `${origin}/failed`, disableRedirect: true,
      ...(operation === "id-token" ? { idToken: { token: "native-id-token", nonce: "native-nonce" } } : {}),
    };
    const response = await auth.handler(new Request(`${origin}/api/auth/link-social`, {
      method: "POST", headers: { origin, "content-type": "application/json",
        ...(!scenario.missing ? { cookie: ownerCookie } : {}) }, body: JSON.stringify(body),
    }));
    const responseClone = response.clone();
    const result = await responseValue(response, replacements);
    let pending = null;
    let callback = null;
    if (operation === "redirect" && result.status === 200) {
      const { url } = await responseClone.json();
      const state = new URL(url).searchParams.get("state");
      assert.ok(state);
      replacements.set(state, "<state>");
      let serializedState;
      if (strategy === "database") {
        const row = scenario.many
          ? await inspectOne({ model: "verification", where: [{ field: "identifier", value: state }] })
          : JSON.parse(cache.get(`verification:${state}`));
        assert.ok(row);
        serializedState = row.value;
        pending = JSON.parse(serializedState);
        if (row.id !== undefined) replacements.set(row.id, "<verification-id>");
        replacements.set(`verification:${state}`, "verification:<state>");
        const stateCookie = (await serializeSignedCookie(context.createAuthCookie("state").name, state, secret)).split(";", 1)[0];
        assert.ok(cookiePairs(responseClone).includes(stateCookie), "The state cookie must contain the signed state identifier");
      } else {
        const pair = cookiePairs(responseClone).find(value => value.startsWith(`${context.createAuthCookie("oauth_state").name}=`));
        assert.ok(pair);
        const encrypted = decodeURIComponent(pair.slice(pair.indexOf("=") + 1));
        serializedState = await symmetricDecrypt({ key: context.secretConfig, data: encrypted });
        pending = JSON.parse(serializedState);
      }
      assert.equal(pending.oauthState, state);
      assert.equal(pending.callbackURL, `${origin}/complete`);
      assert.equal(pending.expiresAt, timestamp + 600_000);
      assert.ok(pending.codeVerifier.length > 0);
      replacements.set(pending.codeVerifier, "<code-verifier>");
      if (pending.idTokenNonce) replacements.set(pending.idTokenNonce, "<nonce>");
      replacements.set(serializedState, JSON.stringify(normalize(pending, replacements)));
      callback = await responseValue(await auth.handler(new Request(
        `${origin}/api/auth/callback/google?state=${encodeURIComponent(state)}&error=access_denied`,
        { headers: { origin, cookie: cookiePairs(responseClone).join("; ") } },
      )), replacements);
    }
    const observed = events.splice(0);
    const registeredModels = Object.keys(context.tables);
    assert.deepEqual([...registeredModels].sort(), models.filter(model => scenario.many || model !== "verification").sort());
    const stored = {};
    for (const model of models) {
      if (Object.hasOwn(context.tables, model)) {
        stored[model] = await inspectMany({ model });
      } else if (sqlite) {
        const tableExists = Boolean(sqlite.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(model));
        assert.equal(tableExists, false, "An unregistered verification model must not create a database table");
        stored[model] = { modelRegistered: false, tableExists };
      } else {
        assert.deepEqual(memory[model], [], "An unregistered verification model must not write to the Memory bucket");
        stored[model] = { modelRegistered: false, rows: memory[model] };
      }
    }
    for (const model of ["account", "verification"]) {
      if (!Object.hasOwn(context.tables, model)) continue;
      for (const row of stored[model]) {
        if (!row.id.startsWith("linked-")) replacements.set(row.id, `<${model}-id>`);
      }
    }
    return normalize({ backend, operation, strategy, scenario: scenario.name, existing,
      result, pending: native(pending), callback, events: observed, registeredModels, stored: native(stored),
      cache: [...cache].map(([key, value]) => ({ key, value: JSON.parse(value) })) }, replacements);
  } finally { sqlite?.close(); }
}

export async function captureOAuthNativeSession() {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  const OriginalDate = globalThis.Date;
  class FixedDate extends OriginalDate {
    constructor(...args) { super(...(args.length ? args : [timestamp])); }
    static now() { return timestamp; }
    static [Symbol.hasInstance](value) { return value instanceof OriginalDate; }
  }
  globalThis.Date = FixedDate;
  try {
    const cases = [];
    for (const backend of ["memory", "sqlite"]) {
      for (const strategy of ["database", "cookie"]) for (const scenario of selectors) {
        cases.push(await captureCase(backend, "redirect", strategy, scenario));
      }
      for (const scenario of selectors.filter(value => !["object", "array", "surrogate"].includes(value.name))) {
        for (const existing of [false, true]) cases.push(await captureCase(backend, "id-token", "database", scenario, existing));
      }
    }
    assert.equal(cases.length, 172);
    return { version, cases };
  } finally { globalThis.Date = OriginalDate; }
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass the OAuth native Session fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureOAuthNativeSession(), null, 2)}\n`);
}
