import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { observeValue } from "./device-where-capture.mjs";

export const origin = "http://user-verification-cleanup.test";
export const secret = "user-verification-cleanup-contract-secret-at-least-32-characters";
export const email = "owner@user-verification-cleanup.test";
export const tables = ["user", "account", "session", "verification"];
export const expiresIn = 604800;
export const date = new Date("2030-01-02T03:04:05.000Z");
export const expiry = new Date("2100-01-02T03:04:05.000Z");
export const otp = "123456";
export const token = "cleanup-magic-proof";

export function native(value) {
  if (value instanceof Error) return {
    name: value.name, message: value.message, keys: Object.keys(value),
    properties: native(Object.fromEntries(Object.entries(value))),
  };
  if (Array.isArray(value)) return value.map(native);
  if (value !== null && typeof value === "object" && !(value instanceof Date)) {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, native(child)]));
  }
  return observeValue(value);
}

export function scenarios() {
  const ids = [
    ["number", 7, "7"], ["zero", 0, "0"], ["true", true, "true"],
    ["false", false, "false"], ["null", null, "owner"],
    ["undefined", undefined, "owner"], ["object", { owner: "native" }, "owner"],
    ["string-zero", "0", "0"], ["string-false", "false", "false"],
  ];
  return [
    ...ids.map(([name, id, storageId]) => ({ name: `native-${name}`, id, storageId, inject: true })),
    ...ids.filter(([name]) => ["number", "undefined"].includes(name))
      .map(([name, id, storageId]) => ({ name: `verified-${name}`, id, storageId, inject: true, verified: true })),
    ...["account-before", "account-after", "user-before", "user-after", "user-not-null"]
      .map(failure => ({ name: failure, failure, storageId: "owner" })),
  ];
}

export async function seed(adapter, route, scenario, memory) {
  for (const [id, ownerEmail, verified] of [
    [scenario.storageId, email, Boolean(scenario.verified)],
    ["other", "other@user-verification-cleanup.test", false],
  ]) {
    await adapter.create({ model: "user", forceAllowId: true, data: {
      id, name: id === "other" ? "Other" : "Owner", email: ownerEmail,
      emailVerified: verified, image: null, createdAt: date, updatedAt: date,
    } });
  }
  for (const [id, userId, providerId] of [
    ["account-a", scenario.storageId, "credential"],
    ["account-b", scenario.storageId, "google"], ["account-other", "other", "credential"],
  ]) {
    await adapter.create({ model: "account", forceAllowId: true, data: {
      id, userId, providerId, accountId: `${id}-external`,
      password: providerId === "credential" ? "unproven-password" : null,
      createdAt: date, updatedAt: date,
    } });
  }
  for (const [id, userId] of [
    ["session-a", scenario.storageId], ["session-b", scenario.storageId], ["session-other", "other"],
  ]) {
    await adapter.create({ model: "session", forceAllowId: true, data: {
      id, userId, token: `${id}-token`, expiresAt: expiry,
      ipAddress: "127.0.0.1", userAgent: "seeded-cleanup-contract", createdAt: date, updatedAt: date,
    } });
  }
  await adapter.create({ model: "verification", forceAllowId: true, data: {
    id: "proof", identifier: route === "email-otp" ? `sign-in-otp-${email}` : token,
    value: route === "email-otp" ? `${otp}:0` : JSON.stringify({ email }),
    expiresAt: expiry, createdAt: date, updatedAt: date,
  } });
  // Scalar native IDs keep Memory transaction reconciliation independent of object identity.
  if (memory && scenario.inject && ["number", "boolean"].includes(typeof scenario.id)) {
    memory.user.find(row => row.id === scenario.storageId).id = scenario.id;
    for (const model of ["account", "session"]) for (const row of memory[model]) {
      if (row.userId === scenario.storageId) row.userId = scenario.id;
    }
  }
}

export function request(route) {
  return route === "email-otp"
    ? new Request(`${origin}/api/auth/sign-in/email-otp`, {
      method: "POST", headers: { origin, "content-type": "application/json" },
      body: JSON.stringify({ email, otp }),
    })
    : new Request(`${origin}/api/auth/magic-link/verify?token=${token}`, { headers: { origin } });
}

export function hooks(state, scenario, record) {
  let accountDeletes = 0;
  const failed = phase => { throw new Error(`cleanup-${phase}-failure`); };
  return Object.fromEntries(tables.map(model => [model, Object.fromEntries(
    ["create", "update", "delete"].map(operation => [operation, {
      before(data) {
        record({ kind: "hook", model, operation, phase: "before", data });
        if (!state.enabled) return;
        if (model === "account" && operation === "delete") {
          accountDeletes++;
          if (accountDeletes === 2 && scenario.failure === "account-before") failed("account-before");
        }
        if (model === "user" && operation === "update") {
          if (scenario.failure === "user-before") failed("user-before");
          if (scenario.failure === "user-not-null") return { data: { name: null } };
        }
      },
      after(data) {
        record({ kind: "hook", model, operation, phase: "after", data });
        if (!state.enabled) return;
        if (model === "account" && operation === "delete" && accountDeletes === 2 && scenario.failure === "account-after") failed("account-after");
        if (model === "user" && operation === "update" && scenario.failure === "user-after") failed("user-after");
      },
    }]),
  )]));
}

export function decorate(adapter, scenario, state, record, snapshot, seen = new WeakSet()) {
  if (seen.has(adapter)) return adapter;
  seen.add(adapter);
  for (const operation of ["create", "findOne", "findMany", "update", "delete", "deleteMany", "consumeOne"]) {
    const original = adapter[operation].bind(adapter);
    adapter[operation] = async input => {
      record({ kind: "adapter", operation, phase: "before", input });
      let result;
      try {
        result = await original(input);
      } catch (error) {
        record({ kind: "adapter", operation, phase: "error", error });
        throw error;
      }
      if (state.enabled && scenario.inject && input.model === "user" && result && ["findOne", "update"].includes(operation)) {
        record({ kind: "native-id", operation, original: result.id, replacement: scenario.id });
        result = { ...result, id: scenario.id };
      }
      record({ kind: "adapter", operation, phase: "after", result,
        ...(state.enabled && input.model === "verification" && ["create", "delete", "deleteMany", "consumeOne"].includes(operation)
          ? { verification: snapshot().verification } : {}),
      });
      return result;
    };
  }
  const transaction = adapter.transaction.bind(adapter);
  adapter.transaction = async callback => {
    record({ kind: "transaction", phase: "before" });
    let result;
    try {
      result = await transaction(current => callback(decorate(current, scenario, state, record, snapshot, seen)));
    } catch (error) {
      record({ kind: "transaction", phase: "error", error, verification: snapshot().verification });
      throw error;
    }
    record({ kind: "transaction", phase: "after", result, verification: snapshot().verification });
    return result;
  };
  return adapter;
}

export function assertOutcome(scenario, before, after, events, response) {
  for (const model of ["user", "account", "session"]) {
    const control = rows => rows.filter(row => row.id === "other" || row.id === `${model}-other`);
    assert.deepEqual(control(after[model]), control(before[model]), "Cleanup must preserve unrelated rows");
  }
  assert.deepEqual(after.verification, [], "The proof and cleanup lock must not survive the request");
  assert.equal(events.some(event => event.kind.startsWith("verification.")), false,
    "Plugin cleanup must not call email-verification callbacks");
  const hooks = events.filter(event => event.kind === "hook");
  if (scenario.verified) {
    assert.equal(hooks.some(event => event.model === "account" || event.model === "user"), false);
    assert.deepEqual(after.account, before.account);
    assert.equal(events.some(event => event.kind === "adapter" && event.phase === "before"
      && event.input.model === "verification" && event.input.data?.identifier?.startsWith("revoke-unproven-account-access:")), false);
  }
  if (!scenario.failure) return;
  assert.equal(response.status, 500);
  assert.deepEqual(response.cookies, []);
  const deleted = hooks.filter(event => event.model === "account" && event.operation === "delete" && event.phase === "after");
  assert.equal(deleted.length, scenario.failure === "account-before" ? 1 : 2);
  for (const event of deleted) assert.equal(after.account.some(row => row.id === event.data.id), false);
  if (scenario.failure.startsWith("account-")) {
    assert.deepEqual(after.session, before.session);
    assert.deepEqual(after.user, before.user);
    assert.equal(hooks.some(event => event.model === "user"), false);
  } else {
    assert.deepEqual(after.account.map(row => row.id), ["account-other"]);
    assert.deepEqual(after.session.map(row => row.id), ["session-other"]);
    const owner = after.user.find(row => row.email === email);
    assert.equal(Boolean(owner.emailVerified), scenario.failure === "user-after");
    assert.equal(owner.name, "Owner");
    const updateHooks = hooks.filter(event => event.model === "user" && event.operation === "update");
    assert.deepEqual(updateHooks.map(event => event.phase), scenario.failure === "user-after" ? ["before", "after"] : ["before"]);
  }
  const errors = events.filter(event => event.kind === "api-error");
  assert.equal(errors.length, 1);
  if (scenario.failure === "user-not-null") assert.match(errors[0].error.message, /NOT NULL/);
  else assert.equal(errors[0].error.message, `cleanup-${scenario.failure}-failure`);
}

export function normalizeCapture(observation, window) {
  const replacements = new Map();
  const checkout = fileURLToPath(new URL("../../../", import.meta.url));
  const issued = observation.events.find(event => event.kind === "hook" && event.model === "session"
    && event.operation === "create" && event.phase === "before");
  if (issued) {
    assert.equal(typeof issued.data.token, "string");
    replacements.set(issued.data.token, "<session-token>");
  }
  const dateLabel = value => {
    const milliseconds = Date.parse(value);
    if (milliseconds >= window.start && milliseconds <= window.end) return "<request-time>";
    if (milliseconds - 5000 >= window.start && milliseconds - 5000 <= window.end) return "<lock-expiry>";
    if (milliseconds - expiresIn * 1000 >= window.start && milliseconds - expiresIn * 1000 <= window.end) return "<session-expiry>";
    assert.ok([date.getTime(), expiry.getTime()].includes(milliseconds), `Unexpected date: ${value}`);
    return value;
  };
  const visit = value => {
    if (typeof value === "string" && replacements.has(value)) return replacements.get(value);
    if (typeof value === "string") return value.replaceAll(checkout, "<checkout>/");
    if (Array.isArray(value)) return value.map(visit);
    if (value !== null && typeof value === "object") {
      if (value.type === "date") return { ...value, value: dateLabel(value.value) };
      return Object.fromEntries(Object.entries(value).map(([key, child]) => [key,
        ["createdAt", "updatedAt", "expiresAt"].includes(key) && typeof child === "string"
          ? dateLabel(child) : visit(child),
      ]));
    }
    return value;
  };
  const normalizeResponse = response => {
    const cookieReplacements = new Map();
    for (const cookie of response.cookies) {
      assert.ok(issued, "A Session cookie requires Session creation");
      const separator = cookie.indexOf(";");
      const signature = createHmac("sha256", secret).update(issued.data.token).digest("base64");
      assert.equal(cookie.slice(0, separator), `better-auth.session_token=${encodeURIComponent(`${issued.data.token}.${signature}`)}`);
      assert.equal(cookie.slice(separator), `; Max-Age=${expiresIn}; Path=/; HttpOnly; SameSite=Lax`);
      cookieReplacements.set(cookie, `better-auth.session_token=<verified-signed-session-token>${cookie.slice(separator)}`);
    }
    const headers = response.headers.map(([name, value]) => [name, cookieReplacements.get(value) ?? value]);
    return { ...response, headers, cookies: response.cookies.map(cookie => cookieReplacements.get(cookie)),
      body: response.body ? JSON.stringify(visit(JSON.parse(response.body))) : "" };
  };
  return { ...visit(observation), response: normalizeResponse(observation.response),
    replay: { ...visit(observation.replay), response: normalizeResponse(observation.replay.response) } };
}
