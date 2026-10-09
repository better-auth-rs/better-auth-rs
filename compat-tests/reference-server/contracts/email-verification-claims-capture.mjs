import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { compactVerify, decodeJwt, decodeProtectedHeader } from "jose";
import { observeValue } from "./device-where-capture.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { observePayloadValue, signVerificationPayload, withPayloadRecorder } from "./email-verification-payload-capture.mjs";

const version = "1.7.6";
const origin = "http://email-verification-claims.test";
const secret = "email-verification-claims-contract-secret-at-least-32-characters";
const email = "owner@verify-claims.test";
const issuedAt = 2_000_000_000_123;
const now = Math.floor(issuedAt / 1000);
const tables = ["user", "session", "account", "verification"];
const headers = { origin, "user-agent": "email-claims-contract", "x-forwarded-for": "203.0.113.8" };
const callback = "/verified?source=mail#done";
const nativeEmail = "NEW\ud800@EXAMPLE.TEST";
const payload = claims => JSON.stringify({ email, ...claims });
const change = (requestType, updateTo = nativeEmail) => payload({ updateTo, requestType });
const scenarios = [
  { name: "missing-dates", payload: payload({}), result: "verified" },
  { name: "future-fractional-iat", payload: payload({ iat: now + 1000.5 }), result: "verified" },
  { name: "future-nbf-before-expired-exp", payload: payload({ nbf: now + 0.5, exp: now - 1 }), error: "INVALID_TOKEN" },
  { name: "invalid-email-format", payload: payload({ email: "not-an-email" }), invalidField: "email", invalidIssue: "invalid_format" },
  { name: "null-update-to", payload: payload({ updateTo: null }), invalidField: "updateTo", invalidIssue: "invalid_type" },
  { name: "null-request-type", payload: payload({ requestType: null }), invalidField: "requestType", invalidIssue: "invalid_type" },
  {
    name: "duplicate-reserved-and-unknown-utf16",
    payload: String.raw`{"email":7,"email":"owner@verify-claims.test","iat":null,"iat":1e400,"nbf":true,"nbf":-1e400,"exp":-1,"exp":1e400,"aud":false,"aud":{"arbitrary":true},"iss":false,"sub":[],"updateTo":7,"updateTo":"","requestType":null,"requestType":"ignored\udc00","\ud800":{"\udc00":"unknown\ud800"}}`,
    result: "verified",
  },
  { name: "overflow-nbf", payload: String.raw`{"email":"owner@verify-claims.test","nbf":1e400}`, error: "INVALID_TOKEN" },
  { name: "overflow-exp", payload: String.raw`{"email":"owner@verify-claims.test","exp":-1e400}`, error: "TOKEN_EXPIRED" },
  { name: "uppercase-email", payload: payload({ email: email.toUpperCase() }), result: "verified" },
  {
    name: "uppercase-change-no-session",
    payload: payload({ email: email.toUpperCase(), updateTo: "NEW@EXAMPLE.TEST", requestType: "change-email-verification" }),
    result: "change",
  },
  {
    name: "uppercase-change-own-session",
    payload: payload({ email: email.toUpperCase(), updateTo: "NEW@EXAMPLE.TEST", requestType: "change-email-verification" }),
    existingSession: true, error: "INVALID_USER",
  },
  { name: "native-update-confirmation", payload: change("change-email-confirmation"), result: "confirmation" },
  { name: "native-update-verification", payload: change("change-email-verification"), result: "change" },
  { name: "native-update-legacy", payload: change("legacy\udc00"), result: "legacy" },
];

async function inspectToken(token, expectedPayload) {
  const protectedHeader = decodeProtectedHeader(token);
  assert.deepEqual(protectedHeader, { alg: "HS256" });
  const verified = await compactVerify(token, new TextEncoder().encode(secret), { algorithms: ["HS256"] });
  const rawPayload = new TextDecoder().decode(verified.payload);
  assert.equal(rawPayload, expectedPayload, "Preserve the complete signed JSON payload bytes");
  assert.equal(token, signVerificationPayload(expectedPayload, secret));
  const claims = decodeJwt(token);
  assert.deepEqual(claims, JSON.parse(expectedPayload));
  return { token, protectedHeader, payload: rawPayload, claims: observeValue(claims), signatureVerified: true };
}

async function describeRequest(value) {
  return value === undefined ? undefined : {
    method: value.method, url: value.url, headers: [...value.headers], body: await value.clone().text(),
  };
}

function signedSessionCookie(token) {
  const signature = createHmac("sha256", secret).update(token).digest("base64");
  return `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}`;
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

function assertBusinessFailure(observation, field, issue) {
  assert.equal(observation.response.status, 500);
  assert.equal(observation.response.body, "");
  assert.equal(new Headers(observation.response.headers).has("location"), false);
  assert.deepEqual(observation.response.cookies, []);
  assert.deepEqual(observation.after, observation.before);
  assert.deepEqual(observation.events.map(event => event.kind), ["api-error", "console.error"]);
  const error = observation.events[0].error;
  assert.equal(error.name, "ZodError");
  assert.equal(error.issues.length, 1);
  assert.deepEqual(error.issues[0].path, [field]);
  assert.equal(error.issues[0].code, issue);
}

async function captureCase(backend, scenario, callbackURL, recorder, diagnostics) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  let enabled = false;
  let generated = 0;
  const events = [];
  const messages = [];
  const record = value => { if (enabled) events.push(observePayloadValue(value)); };
  const options = {
    database: database ?? memoryAdapter(memory), baseURL: origin, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { expiresIn: 3600, updateAge: 600, cookieCache: { enabled: false } },
    advanced: { database: { generateId(input) {
      const id = `${input.model}-${++generated}`;
      record({ kind: "generate-id", input, id });
      return id;
    } } },
    emailVerification: {
      async sendVerificationEmail(data, incoming) {
        messages.push(data);
        record({ kind: "sender", data, request: await describeRequest(incoming) });
      },
      async beforeEmailVerification(user, incoming) {
        record({ kind: "verification.before", user, request: await describeRequest(incoming) });
      },
      async afterEmailVerification(user, incoming) {
        record({ kind: "verification.after", user, request: await describeRequest(incoming) });
      },
    },
    databaseHooks: Object.fromEntries(tables.map(model => [model, Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
      before(data) { record({ kind: "hook", model, operation, phase: "before", data }); },
      after(data) { record({ kind: "hook", model, operation, phase: "after", data }); },
    }]))])),
    onAPIError: { onError(error) {
      record({ kind: "api-error", error });
      diagnostics.push({ backend, scenario: scenario.name, callbackURL, source: "onAPIError", error: observePayloadValue(error, true) });
    } },
  };
  const snapshot = () => observeValue(Object.fromEntries(tables.map(model => [model,
    database ? database.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model],
  ])));
  const context = { backend, scenario: scenario.name, callbackURL };
  const replacements = new Map();
  const observations = [];
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    return await withClock(async () => {
      const auth = betterAuth(options);
      const { adapter } = await auth.$context;
      await adapter.create({ model: "user", forceAllowId: true, data: {
        id: "claims-owner", name: "Claims Owner", email, emailVerified: false, image: null,
        createdAt: new Date(issuedAt), updatedAt: new Date(issuedAt),
      } });
      const existingToken = "existing-claims-session-token";
      if (scenario.existingSession) await adapter.create({ model: "session", forceAllowId: true, data: {
        id: "claims-existing-session", userId: "claims-owner", token: existingToken,
        ipAddress: "203.0.113.8", userAgent: "email-claims-contract",
        createdAt: new Date(issuedAt), updatedAt: new Date(issuedAt), expiresAt: new Date(issuedAt + 3_600_000),
      } });
      const perform = async (token, phase) => {
        const url = new URL("/api/auth/verify-email", origin);
        url.searchParams.set("token", token);
        if (callbackURL !== null) url.searchParams.set("callbackURL", callbackURL);
        const request = new Request(url, { headers: { ...headers, ...(scenario.existingSession ? { cookie: signedSessionCookie(existingToken) } : {}) } });
        const before = snapshot();
        const requestDescription = await describeRequest(request);
        enabled = true;
        recorder.events = events;
        recorder.context = { ...context, phase };
        let response;
        try {
          const result = await auth.handler(request);
          response = { status: result.status, statusText: result.statusText, headers: [...result.headers],
            cookies: result.headers.getSetCookie(), body: await result.text() };
        } finally { enabled = false; recorder.events = null; recorder.context = null; }
        const observation = { phase, request: requestDescription, before, events: events.splice(0), response, after: snapshot() };
        observations.push(observation);
        return observation;
      };
      const token = signVerificationPayload(scenario.payload, secret);
      const jwt = await inspectToken(token, scenario.payload);
      const verification = await perform(token, "verify");
      const { before, after, response, events: observedEvents } = verification;
      const claims = JSON.parse(scenario.payload);
      const followUpTokens = [];
      if (scenario.invalidField) {
        assertBusinessFailure(verification, scenario.invalidField, scenario.invalidIssue);
      } else if (scenario.error) {
        assert.deepEqual(after, before);
        assert.deepEqual(response.cookies, []);
        assert.equal(messages.length, 0);
        assert.ok(observedEvents.every(event => scenario.existingSession && event.kind === "query"));
        if (callbackURL !== null) {
          assert.equal(response.status, 302);
          assert.equal(response.body, "");
          assert.equal(new Headers(response.headers).get("location"), `/verified?source=mail&error=${scenario.error}#done`);
        } else {
          assert.equal(response.status, 401);
          const errorMessages = { INVALID_TOKEN: "Invalid token", TOKEN_EXPIRED: "Token expired", INVALID_USER: "Invalid user" };
          assert.deepEqual(JSON.parse(response.body), { code: scenario.error, message: errorMessages[scenario.error] });
        }
      } else {
        assert.equal(response.status, callbackURL === null ? 200 : 302);
        assert.equal(observedEvents.some(event => ["api-error", "console.error"].includes(event.kind)), false);
        assert.deepEqual(after.account, before.account);
        assert.deepEqual(after.verification, before.verification);
        assert.equal(after.user.length, 1);
        assert.equal(after.user[0].id, "claims-owner");
        if (callbackURL !== null) {
          assert.equal(response.body, "");
          assert.equal(new Headers(response.headers).get("location"), callbackURL);
        } else if (scenario.result === "verified") assert.deepEqual(JSON.parse(response.body), { status: true, user: null });
        else if (scenario.result === "confirmation") assert.deepEqual(JSON.parse(response.body), { status: true });
        else {
          const body = JSON.parse(response.body);
          assert.equal(body.status, true);
          assert.equal(body.user.id, "claims-owner");
          assert.equal(body.user.email, after.user[0].email);
          assert.equal(body.user.emailVerified, scenario.result === "change");
        }
        const creatingSession = ["change", "legacy"].includes(scenario.result);
        assert.equal(after.session.length, creatingSession ? 1 : 0);
        assert.equal(observedEvents.filter(event => event.kind === "verification.before").length, scenario.result === "verified" ? 1 : 0);
        assert.equal(observedEvents.filter(event => event.kind === "verification.after").length, ["verified", "change"].includes(scenario.result) ? 1 : 0);
        if (scenario.result === "confirmation") assert.deepEqual(after, before);
        else {
          const updates = observedEvents.filter(event => event.kind === "hook" && event.model === "user" && event.operation === "update");
          assert.deepEqual(updates.map(event => event.phase), ["before", "after"]);
          assert.equal(updates[0].data.emailVerified, scenario.result !== "legacy");
          if (claims.updateTo) assert.equal(updates[0].data.email, claims.updateTo.toLowerCase());
          else assert.equal(after.user[0].email, email);
          assert.equal(Boolean(after.user[0].emailVerified), scenario.result !== "legacy");
          // SQLite observations retain the backend's actual UTF-16 binding result.
          if (backend === "memory" && claims.updateTo) assert.equal(after.user[0].email, claims.updateTo.toLowerCase());
        }
        if (creatingSession) {
          const session = after.session[0];
          assert.equal(session.userId, "claims-owner");
          assert.equal(typeof session.token, "string");
          assert.equal(session.token.length, 32);
          assert.equal(response.cookies.length, 1);
          const cookie = response.cookies[0].split(";", 1)[0];
          assert.equal(cookie, signedSessionCookie(session.token));
          replacements.set(cookie, "better-auth.session_token=<verified-signed-session-token>");
          replacements.set(session.token, "<session-token>");
        } else assert.deepEqual(response.cookies, []);
        const deliversToken = ["confirmation", "legacy"].includes(scenario.result);
        assert.equal(messages.length, deliversToken ? 1 : 0);
        if (deliversToken) {
          const expectedClaims = scenario.result === "confirmation"
            ? { email: claims.email.toLowerCase(), updateTo: claims.updateTo.toLowerCase(), requestType: "change-email-verification", iat: now, exp: now + 3600 }
            : { email: claims.updateTo.toLowerCase(), iat: now, exp: now + 3600 };
          const message = messages[0];
          followUpTokens.push(await inspectToken(message.token, JSON.stringify(expectedClaims)));
          const url = new URL(message.url);
          assert.equal(url.origin, origin);
          assert.equal(url.pathname, "/api/auth/verify-email");
          assert.deepEqual([...url.searchParams], [["token", message.token], ["callbackURL", callbackURL ?? "/"]]);
          assert.equal(message.user.email, scenario.result === "confirmation" ? claims.updateTo : after.user[0].email);
          if (scenario.result === "legacy") {
            const followUp = await perform(message.token, "follow-up");
            assertBusinessFailure(followUp, "email", "invalid_format");
            assert.equal(messages.length, 1);
          }
        }
      }
      return normalize({ ...context, issuedAt, jwt, observations, followUpTokens }, replacements);
    });
  } catch (error) {
    diagnostics.push({ ...context, observations, assertion: observePayloadValue(error, true) });
    throw error;
  } finally { recorder.events = null; recorder.context = null; database?.close(); }
}

export async function captureEmailVerificationClaims({ diagnostics = [] } = {}) {
  assert.equal(new Set(scenarios.map(scenario => scenario.name)).size, scenarios.length);
  return withPayloadRecorder(async recorder => {
    const cases = [];
    for (const backend of ["memory", "sqlite"]) for (const scenario of scenarios) for (const callbackURL of [null, callback]) {
      cases.push(await captureCase(backend, scenario, callbackURL, recorder, diagnostics));
    }
    assert.equal(cases.length, 60);
    return { version, issuedAt, scenarios, cases };
  }, { diagnostics });
}

if (import.meta.main) {
  const diagnostics = [];
  try {
    const serialized = `${JSON.stringify(await captureEmailVerificationClaims({ diagnostics }), null, 2)}\n`;
    if (process.argv[2]) writeFileSync(process.argv[2], serialized);
    else process.stdout.write(serialized);
  } finally {
    if (process.argv[2]) writeFileSync(`${process.argv[2]}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
