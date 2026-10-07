import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { oAuthProxy } from "better-auth/plugins/oauth-proxy";
import { observeValue } from "./device-where-capture.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";

const version = "1.7.6";
const now = 2_000_000_000_123;
const origin = "http://oauth-proxy-max-age.test";
const authSecret = "oauth-proxy-max-age-contract-secret-at-least-thirty-two-characters";
const callbackURL = `${origin}/return`;
const errorURL = `${origin}/failure`;
const state = "proxy-max-age-state";
const tables = ["user", "session", "account", "verification"];
const ageMilliseconds = [60_000, 60_001, -10_000, -10_001];
const scenarios = [
  { name: "sixty", maxAge: 60, accepted: [true, false, true, false] },
  { name: "nan", maxAge: NaN, accepted: [true, true, true, false] },
  { name: "positive-infinity", maxAge: Infinity, accepted: [true, true, true, false] },
  { name: "negative-infinity", maxAge: -Infinity, accepted: [false, false, false, false] },
];

function errorObservation(error) {
  assert.ok(error instanceof Error);
  const keys = Object.getOwnPropertyNames(error).filter(key => key !== "stack");
  return {
    name: error.name, message: error.message, keys,
    properties: Object.fromEntries(keys.map(key => [key,
      error[key] instanceof Error ? errorObservation(error[key]) : observeValue(error[key]),
    ])),
  };
}

async function outcome(operation, diagnostics, label) {
  try { return { kind: "returned", value: observeValue(await operation()) }; }
  catch (error) {
    const observed = errorObservation(error);
    diagnostics.push({ ...label, error: { ...observed, stack: error.stack } });
    return { kind: "thrown", error: observed };
  }
}

function returned(observation) {
  assert.equal(observation.kind, "returned", JSON.stringify(observation));
  return observation.value;
}

function normalize(value, replacements) {
  if (typeof value === "string") {
    for (const [source, replacement] of replacements) value = value.replaceAll(source, replacement);
    return value;
  }
  if (Array.isArray(value)) return value.map(child => normalize(child, replacements));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalize(child, replacements)]));
  return value;
}

const signedValue = value => `${value}.${createHmac("sha256", authSecret).update(value).digest("base64")}`;

async function responseObservation(response) {
  return {
    status: response.status, statusText: response.statusText,
    headers: [...response.headers], cookies: response.headers.getSetCookie(), body: await response.text(),
  };
}

function seedRows() {
  const createdAt = new Date(now - 120_000);
  const stateData = {
    callbackURL, codeVerifier: "proxy-max-age-verifier", errorURL,
    expiresAt: now + 600_000, oauthState: state,
  };
  return {
    stateData,
    user: {
      id: "proxy-owner", name: "Proxy Owner", email: "owner@oauth-proxy-max-age.test",
      emailVerified: true, image: null, createdAt, updatedAt: createdAt,
    },
    account: {
      id: "proxy-account", accountId: "proxy-subject", providerId: "fixture", userId: "proxy-owner",
      accessToken: "proxy-old-access", refreshToken: "proxy-old-refresh", idToken: "proxy-old-id",
      accessTokenExpiresAt: null, refreshTokenExpiresAt: null, scope: "openid email", password: null,
      createdAt, updatedAt: createdAt,
    },
    verification: {
      id: "proxy-verification", identifier: state, value: JSON.stringify(stateData),
      expiresAt: new Date(now + 600_000), createdAt, updatedAt: createdAt,
    },
  };
}

function assertSuccess(response, before, after, events, seed) {
  assert.deepEqual(after.user, before.user);
  assert.deepEqual(after.verification, []);
  const account = {
    ...seed.account, accessToken: "proxy-new-access", refreshToken: "proxy-new-refresh", idToken: "proxy-new-id",
    updatedAt: new Date(now),
  };
  assert.deepEqual(after.account, [observeValue(account)]);
  assert.equal(after.session.length, 1);
  const token = after.session[0].token;
  assert.match(token, /^[a-zA-Z0-9]{32}$/);
  const session = {
    expiresAt: new Date(now + 3_600_000), token, createdAt: new Date(now), updatedAt: new Date(now),
    ipAddress: "203.0.113.8", userAgent: "oauth-proxy-max-age", userId: seed.user.id, id: "proxy-session-1",
  };
  assert.deepEqual(after.session, [observeValue(session)]);
  const hook = (model, operation, phase, data) => observeValue({ kind: "hook", model, operation, phase, data });
  const { id: _id, ...sessionInput } = session;
  assert.deepEqual(events, [
    hook("verification", "delete", "before", seed.verification),
    hook("verification", "delete", "after", seed.verification),
    hook("account", "update", "before", {
      providerId: "fixture", idToken: "proxy-new-id", accessToken: "proxy-new-access", refreshToken: "proxy-new-refresh",
    }),
    hook("account", "update", "after", account),
    hook("session", "create", "before", sessionInput),
    { kind: "generate-id", input: { model: "session" }, id: session.id },
    hook("session", "create", "after", session),
  ], "Compare every lifecycle callback, complete callback data, and generated database ID in order");
  const signature = signedValue(token);
  const encodedSignature = encodeURIComponent(signature);
  assert.deepEqual(response.cookies, [
    "better-auth.state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
    `better-auth.session_token=${encodedSignature}; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax`,
  ]);
  const sessionCookie = response.cookies[1].split(";", 1)[0].slice("better-auth.session_token=".length);
  assert.equal(decodeURIComponent(sessionCookie), signature);
  assert.equal(new Headers(response.headers).get("location"), callbackURL);
  return [[encodedSignature, "<session-token>.<session-hmac>"], [token, "<session-token>"]];
}

async function captureCase(scenario, ageMillis, accepted, diagnostics) {
  const label = { scenario: scenario.name, maxAge: observeValue(scenario.maxAge), ageMillis, accepted };
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const snapshot = () => observeValue(memory);
  const events = [];
  let recording = false;
  let generated = 0;
  const record = event => { if (recording) events.push(observeValue(event)); };
  const auth = betterAuth({
    database: memoryAdapter(memory), baseURL: origin, secret: authSecret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    account: { storeStateStrategy: "database" },
    session: { expiresIn: 3600, disableSessionRefresh: true, cookieCache: { enabled: false } },
    advanced: { database: { generateId(input) {
      const id = `proxy-${input.model}-${++generated}`;
      record({ kind: "generate-id", input, id });
      return id;
    } } },
    plugins: [oAuthProxy({ maxAge: scenario.maxAge })],
    databaseHooks: Object.fromEntries(tables.map(model => [model,
      Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
        before(data) { record({ kind: "hook", model, operation, phase: "before", data }); },
        after(data) { record({ kind: "hook", model, operation, phase: "after", data }); },
      }])),
    ])),
  });
  let context;
  const empty = snapshot();
  const initialization = await outcome(async () => { context = await auth.$context; }, diagnostics,
    { ...label, stage: "initialization-error" });
  diagnostics.push({ ...label, stage: "initialization", input: { maxAge: observeValue(scenario.maxAge) },
    before: empty, outcome: initialization, after: snapshot(), events: [...events] });
  returned(initialization);
  assert.deepEqual(snapshot(), Object.fromEntries(tables.map(model => [model, []])));
  assert.equal(generated, 0);
  const seed = seedRows();
  const seeding = await outcome(async () => {
    for (const model of ["user", "account", "verification"]) {
      await context.adapter.create({ model, forceAllowId: true, data: seed[model] });
    }
  }, diagnostics, { ...label, stage: "seed-error" });
  const before = snapshot();
  diagnostics.push({ ...label, stage: "seed", input: observeValue(seed), before: empty,
    outcome: seeding, after: before, events: [...events] });
  returned(seeding);
  assert.deepEqual(before, observeValue({ user: [seed.user], session: [], account: [seed.account], verification: [seed.verification] }));
  assert.equal(generated, 0);
  assert.deepEqual(events, []);
  const payload = {
    userInfo: { id: "proxy-subject", name: seed.user.name, email: seed.user.email, emailVerified: true, image: null },
    account: { accountId: "proxy-subject", providerId: "fixture", accessToken: "proxy-new-access",
      refreshToken: "proxy-new-refresh", idToken: "proxy-new-id", scope: "openid email" },
    state, callbackURL, errorURL, disableSignUp: true, timestamp: now - ageMillis,
  };
  const plaintext = JSON.stringify(payload);
  const preparationBefore = snapshot();
  let encrypted;
  let decrypted;
  let url;
  let request;
  let input;
  const preparation = await outcome(async () => {
    encrypted = await symmetricEncrypt({ key: context.secretConfig, data: plaintext });
    decrypted = await symmetricDecrypt({ key: context.secretConfig, data: encrypted });
    url = new URL(`${origin}/api/auth/callback/fixture/oauth-proxy`);
    url.search = new URLSearchParams({ callbackURL, profile: encrypted }).toString();
    request = new Request(url, {
      method: "GET", headers: {
        origin, cookie: `better-auth.state=${encodeURIComponent(signedValue(state))}`,
        "user-agent": "oauth-proxy-max-age", "x-forwarded-for": "203.0.113.8",
      },
    });
    input = { url: request.url, method: request.method, headers: [...request.headers], body: await request.clone().text() };
    return { encrypted, decrypted, url: url.toString(), input };
  }, diagnostics, { ...label, stage: "preparation-error" });
  diagnostics.push({ ...label, stage: "preparation", input: { payload, plaintext }, outcome: preparation,
    values: observeValue({ encrypted, decrypted, url: url?.toString(), input }),
    before: preparationBefore, after: snapshot(), events: [...events] });
  returned(preparation);
  assert.equal(decrypted, plaintext);
  assert.equal(url.searchParams.get("profile"), encrypted);
  recording = true;
  let completion;
  try {
    completion = await outcome(async () => responseObservation(await auth.handler(request)), diagnostics,
      { ...label, stage: "http-error" });
  }
  finally { recording = false; }
  const after = snapshot();
  diagnostics.push({ ...label, stage: "http", input, payload, stateData: seed.stateData,
    before, outcome: completion, after, events: [...events] });
  const response = returned(completion);
  assert.equal(response.status, 302, JSON.stringify(response));
  assert.equal(response.body, "");
  const replacements = [[encodeURIComponent(encrypted), "<encrypted-profile>"], [encrypted, "<encrypted-profile>"]];
  if (accepted) {
    replacements.push(...assertSuccess(response, before, after, events, seed));
    assert.equal(generated, 1);
  } else {
    assert.equal(new Headers(response.headers).get("location"), `${errorURL}?error=payload_expired`);
    assert.deepEqual(response.cookies, []);
    assert.deepEqual(events, [], "Payload age validation must precede state deletion, account updates, and session creation");
    assert.deepEqual(after, before, "An expired payload must preserve the complete OAuth state and every stored table");
    assert.equal(generated, 0);
  }
  return normalize({
    scenario: scenario.name, maxAge: observeValue(scenario.maxAge), ageMillis, ageSeconds: ageMillis / 1000, accepted,
    initialization, stateData: seed.stateData, payload, input, before, completion, events, after,
  }, replacements);
}

export async function captureOAuthProxyMaxAge({ diagnostics = [] } = {}) {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of scenarios) for (const [index, ageMillis] of ageMilliseconds.entries()) {
      try {
        cases.push(await captureCase(scenario, ageMillis, scenario.accepted[index], diagnostics));
      } catch (error) {
        diagnostics.push({ scenario: scenario.name, maxAge: observeValue(scenario.maxAge), ageMillis,
          accepted: scenario.accepted[index], stage: "case-error", error: { ...errorObservation(error), stack: error.stack } });
        throw error;
      }
    }
    assert.equal(cases.length, 16);
    assert.equal(cases.filter(value => value.accepted).length, 8);
    return { version, now, backend: "memory", stateStrategy: "database", scope: {
      route: "GET /callback/:id/oauth-proxy uses the actual HTTP handler with a valid encrypted profile and database state",
      boundaries: "Compare 60 seconds and one millisecond beyond; compare ten seconds in the future and one millisecond beyond",
      state: "Expired payloads preserve every table and emit no lifecycle callback; successful payloads consume state and create a signed session",
      normalization: "Replace profile ciphertext after complete decryption checks; replace session randomness after full row, callback, and cookie HMAC checks",
      observation: "Retain complete Request and Response fields, every core lifecycle callback, and all four Memory tables before and after",
    }, cases };
  });
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the OAuth Proxy maxAge fixture output path");
  const diagnostics = [];
  try {
    writeFileSync(output, `${JSON.stringify(await captureOAuthProxyMaxAge({ diagnostics }), null, 2)}\n`);
  } catch (error) {
    diagnostics.push({ stage: "capture-error", error: { ...errorObservation(error), stack: error.stack } });
    throw error;
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
