import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { compactVerify, decodeJwt, decodeProtectedHeader } from "jose";
import { observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
const origin = "http://email-verification-duration.test";
const secret = "email-verification-duration-contract-secret-at-least-32-characters";
const email = "owner@email-verification-duration.test";
const epoch = 2_000_000_000_000;
const issuedAt = epoch + 123;
const tables = ["user", "session", "account", "verification"];
const headers = { origin, "content-type": "application/json", "user-agent": "email-duration-contract", "x-forwarded-for": "203.0.113.8" };
const scenarios = [
  { name: "fractional-before-claim", expiresIn: 1.5, readOffset: 1499, accepted: true },
  { name: "fractional-at-claim", expiresIn: 1.5, readOffset: 1500, accepted: true },
  { name: "fractional-before-next-second", expiresIn: 1.5, readOffset: 1999, accepted: true },
  { name: "fractional-at-next-second", expiresIn: 1.5, readOffset: 2000, accepted: false },
  { name: "integer-before-claim", expiresIn: 2, readOffset: 1999, accepted: true },
  { name: "integer-at-claim", expiresIn: 2, readOffset: 2000, accepted: false },
  { name: "zero-immediate", expiresIn: 0, readOffset: 123, accepted: false },
];

export async function withClock(operation) {
  const OriginalDate = globalThis.Date;
  let milliseconds = issuedAt;
  // jose reads new Date() for iat and verification; Date.now alone cannot fix those clocks.
  globalThis.Date = new Proxy(OriginalDate, {
    construct(target, args, newTarget) {
      return Reflect.construct(target, args.length === 0 ? [milliseconds] : args, newTarget);
    },
    apply() { return new OriginalDate(milliseconds).toString(); },
    get(target, key, receiver) {
      return key === "now" ? () => milliseconds : Reflect.get(target, key, receiver);
    },
  });
  const setClock = value => {
    milliseconds = value;
    assert.equal(Date.now(), value);
    assert.equal(new Date().getTime(), value);
    assert.ok(new OriginalDate(value) instanceof Date);
    assert.equal(new Date(0).getTime(), 0);
  };
  try {
    setClock(issuedAt);
    return await operation(setClock);
  } finally { globalThis.Date = OriginalDate; }
}

async function response(value) {
  return { status: value.status, statusText: value.statusText, headers: [...value.headers], cookies: value.headers.getSetCookie(), body: await value.text() };
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

async function captureCase(backend, scenario) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  let recording = false;
  let generated = 0;
  let deliveredToken;
  let senderCalls = 0;
  const record = value => { if (recording) events.push(observeValue(value)); };
  const request = async value => value === undefined ? undefined : {
    method: value.method, url: value.url, headers: [...value.headers], body: await value.clone().text(),
  };
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
      expiresIn: scenario.expiresIn, autoSignInAfterVerification: true,
      async sendVerificationEmail(data, incoming) {
        senderCalls++;
        deliveredToken = data.token;
        record({ kind: "sender", data, request: await request(incoming) });
      },
      async beforeEmailVerification(user, incoming) {
        record({ kind: "before-verification", user, request: await request(incoming) });
      },
      async afterEmailVerification(user, incoming) {
        record({ kind: "after-verification", user, request: await request(incoming) });
      },
    },
    databaseHooks: Object.fromEntries(tables.map(model => [model, Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
      before(data) { record({ kind: "hook", model, operation, phase: "before", data }); },
      after(data) { record({ kind: "hook", model, operation, phase: "after", data }); },
    }]))])),
  };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    return await withClock(async setClock => {
      const auth = betterAuth(options);
      const context = await auth.$context;
      await context.adapter.create({ model: "user", forceAllowId: true, data: {
        id: "owner", name: "Email Duration", email, emailVerified: false, image: null,
        createdAt: new Date(issuedAt), updatedAt: new Date(issuedAt),
      } });
      const snapshot = () => observeValue(Object.fromEntries(tables.map(model => [model,
        database ? database.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model],
      ])));
      const before = snapshot();
      recording = true;
      const sendInput = { method: "POST", url: `${origin}/api/auth/send-verification-email`, headers, body: { email } };
      const sent = await response(await auth.handler(new Request(sendInput.url, {
        method: sendInput.method, headers, body: JSON.stringify(sendInput.body),
      })));
      assert.equal(sent.status, 200);
      assert.deepEqual(JSON.parse(sent.body), { status: true });
      assert.deepEqual(sent.cookies, []);
      assert.equal(senderCalls, 1);
      assert.equal(typeof deliveredToken, "string");
      const claims = decodeJwt(deliveredToken);
      const protectedHeader = decodeProtectedHeader(deliveredToken);
      assert.deepEqual(claims, { email, iat: epoch / 1000, exp: epoch / 1000 + scenario.expiresIn });
      assert.deepEqual(protectedHeader, { alg: "HS256" });
      const verified = await compactVerify(deliveredToken, new TextEncoder().encode(secret), { algorithms: ["HS256"] });
      assert.deepEqual(JSON.parse(new TextDecoder().decode(verified.payload)), claims);
      const senderEvents = events.filter(event => event.kind === "sender");
      assert.equal(senderEvents.length, 1);
      assert.equal(new URL(senderEvents[0].data.url).searchParams.get("token"), deliveredToken);
      const afterSend = snapshot();
      assert.deepEqual(afterSend, before);
      const sendEvents = events.splice(0);

      const readAt = epoch + scenario.readOffset;
      setClock(readAt);
      const verifyInput = { method: "GET", url: `${origin}/api/auth/verify-email?${new URLSearchParams({ token: deliveredToken })}`, headers };
      const verification = await response(await auth.handler(new Request(verifyInput.url, { method: verifyInput.method, headers })));
      const afterVerify = snapshot();
      const verifyEvents = events.splice(0);
      assert.equal(verification.status, scenario.accepted ? 200 : 401);
      assert.deepEqual(JSON.parse(verification.body), scenario.accepted
        ? { status: true, user: null } : { code: "TOKEN_EXPIRED", message: "Token expired" });
      assert.equal(senderCalls, 1);
      assert.equal(afterVerify.session.length, scenario.accepted ? 1 : 0);
      assert.deepEqual(afterVerify.account, before.account);
      assert.deepEqual(afterVerify.verification, before.verification);
      const storedUser = await context.adapter.findOne({ model: "user", where: [{ field: "id", value: "owner" }] });
      assert.equal(storedUser.emailVerified, scenario.accepted);
      const replacements = new Map();
      let sessionCookie;
      if (scenario.accepted) {
        const stored = afterVerify.session[0];
        assert.equal(stored.userId, "owner");
        assert.equal(typeof stored.token, "string");
        assert.equal(stored.token.length, 32);
        const cookies = verification.cookies.filter(value => value.startsWith("better-auth.session_token="));
        assert.equal(cookies.length, 1);
        const separator = cookies[0].indexOf(";");
        assert.ok(separator > 0);
        sessionCookie = cookies[0].slice(0, separator);
        const signature = createHmac("sha256", secret).update(stored.token).digest("base64");
        assert.equal(sessionCookie, `better-auth.session_token=${encodeURIComponent(`${stored.token}.${signature}`)}`);
        replacements.set(sessionCookie, "better-auth.session_token=<verified-signed-session-token>");
        replacements.set(stored.token, "<session-token>");
        assert.equal(verifyEvents.filter(event => event.kind === "before-verification").length, 1);
        assert.equal(verifyEvents.filter(event => event.kind === "after-verification").length, 1);
      } else {
        assert.deepEqual(verification.cookies, []);
        assert.deepEqual(afterVerify, before);
        assert.deepEqual(verifyEvents, []);
      }
      const sessionInput = { method: "GET", url: `${origin}/api/auth/get-session`, headers: { ...headers, ...(sessionCookie ? { cookie: sessionCookie } : {}) } };
      const sessionRead = await response(await auth.handler(new Request(sessionInput.url, { method: sessionInput.method, headers: sessionInput.headers })));
      assert.equal(sessionRead.status, 200);
      const sessionBody = JSON.parse(sessionRead.body);
      if (scenario.accepted) {
        assert.equal(sessionBody.session.token, afterVerify.session[0].token);
        assert.equal(sessionBody.session.userId, "owner");
        assert.equal(sessionBody.user.emailVerified, true);
      } else assert.equal(sessionBody, null);
      const afterRead = snapshot();
      assert.deepEqual(afterRead, afterVerify);
      assert.equal(senderCalls, 1);
      return normalize({ backend, scenario, issuedAt, readAt,
        before, send: { request: sendInput, response: sent, events: sendEvents, after: afterSend },
        jwt: { token: deliveredToken, protectedHeader, claims, signatureVerified: true },
        verify: { request: verifyInput, response: verification, events: verifyEvents, after: afterVerify },
        session: { request: sessionInput, response: sessionRead, events: events.splice(0), after: afterRead }, senderCalls,
      }, replacements);
    });
  } finally { database?.close(); }
}

export async function captureEmailVerificationDuration() {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const scenario of scenarios) cases.push(await captureCase(backend, scenario));
  }
  return { version, issuedAt, scenarios, cases };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureEmailVerificationDuration(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
