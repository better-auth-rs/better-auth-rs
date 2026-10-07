import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { oneTimeToken } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";

const version = "1.7.6";
const origin = "http://one-time-token-expiry.test";
const secret = "one-time-token-expiry-contract-secret-at-least-32-characters";
const issuedAt = 2_000_000_000_123;
const expiresIn = 0.025;
const lifetimeMillis = 1500;
const hashDurationMillis = 2000;
const token = "fixed-one-time-token";
const storedToken = `hashed:${token}`;
const fixedSessionToken = "fixed-owner-session-token";
const password = "one-time-token-expiry-password";
const passwordHash = "one-time-token-expiry-password-hash";
const tables = ["user", "session", "account", "verification"];
const headers = { origin, "content-type": "application/json", "user-agent": "one-time-token-expiry-contract", "x-forwarded-for": "203.0.113.8" };

function sessionCookie(token) {
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

async function captureCase(backend, entrypoint, diagnostics) {
  const label = { backend, entrypoint };
  diagnostics.push({ ...label, stage: "case-start", issuedAt, expiresIn, lifetimeMillis, hashDurationMillis });
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const snapshot = () => observeValue(Object.fromEntries(tables.map(model => [model,
    database ? database.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model],
  ])));
  const events = [];
  const record = value => events.push(observeValue(value));
  let generated = 0;
  let hashCalls = 0;
  try {
    return await withClock(async setClock => {
      setClock(issuedAt);
      const options = {
        database: database ?? memoryAdapter(memory), baseURL: origin, secret,
        logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
        session: { expiresIn: 3600, disableSessionRefresh: true, cookieCache: { enabled: false } },
        advanced: { database: { generateId(input) {
          const id = `${input.model}-${++generated}`;
          record({ kind: "generate-id", input, id });
          return id;
        } } },
        emailAndPassword: { enabled: true, password: {
          async hash(value) { record({ kind: "password.hash", value }); return passwordHash; },
          async verify(value) {
            record({ kind: "password.verify", value });
            return value.hash === passwordHash && value.password === password;
          },
        } },
        plugins: [oneTimeToken({
          expiresIn, setOttHeaderOnNewSession: entrypoint === "set-ott",
          async generateToken(session, context) {
            record({ kind: "token.generate", timestampMillis: Date.now(), session, path: context.path });
            return token;
          },
          storeToken: { type: "custom-hasher", async hash(value) {
            const invocation = ++hashCalls;
            record({ kind: "token.hash.start", invocation, token: value, timestampMillis: Date.now() });
            if (invocation === 1) setClock(Date.now() + hashDurationMillis);
            const result = `hashed:${value}`;
            record({ kind: "token.hash.end", invocation, token: value, result, timestampMillis: Date.now() });
            return result;
          } },
        })],
        databaseHooks: Object.fromEntries(tables.map(model => [model, Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
          before(data) { record({ kind: "hook", model, operation, phase: "before", data }); },
          after(data) { record({ kind: "hook", model, operation, phase: "after", data }); },
        }]))])),
      };
      if (database) await (await getMigrations(options)).runMigrations();
      const auth = betterAuth(options);
      const context = await auth.$context;
      const date = new Date(issuedAt);
      const ownerInput = { model: "user", forceAllowId: true, data: {
        id: "owner", name: "One Time Token Owner", email: "owner@one-time-token-expiry.test", emailVerified: true,
        image: null, createdAt: date, updatedAt: date,
      } };
      const credentialInput = entrypoint === "generate" ? { model: "session", forceAllowId: true, data: {
        id: "owner-session", userId: "owner", token: fixedSessionToken,
        expiresAt: new Date(issuedAt + 3_600_000), createdAt: date, updatedAt: date,
        ipAddress: "203.0.113.8", userAgent: headers["user-agent"],
      } } : { model: "account", forceAllowId: true, data: {
        id: "owner-account", userId: "owner", accountId: "owner", providerId: "credential", password: passwordHash,
        accessToken: null, refreshToken: null, idToken: null, accessTokenExpiresAt: null, refreshTokenExpiresAt: null,
        scope: null, createdAt: date, updatedAt: date,
      } };
      const seed = { input: observeValue([ownerInput, credentialInput]), before: snapshot() };
      diagnostics.push({ ...label, stage: "seed", observation: seed });
      let owner;
      try {
        owner = await context.adapter.create(ownerInput);
        await context.adapter.create(credentialInput);
      } finally {
        seed.after = snapshot();
        seed.events = events.splice(0);
      }

      async function request(name, path, body, cookie) {
        const incoming = new Request(`${origin}/api/auth${path}`, {
          method: body === undefined ? "GET" : "POST", headers: { ...headers, ...(cookie ? { cookie } : {}) },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        const observation = { name, timestampMillis: Date.now(), request: {
          url: incoming.url, method: incoming.method, headers: [...incoming.headers], body: await incoming.clone().text(),
        }, before: snapshot() };
        diagnostics.push({ ...label, stage: "request", observation });
        try {
          const response = await auth.handler(incoming);
          observation.response = { status: response.status, statusText: response.statusText,
            headers: [...response.headers], cookies: response.headers.getSetCookie(), body: await response.text() };
        } finally {
          observation.after = snapshot();
          observation.events = events.splice(0);
          observation.completedAt = Date.now();
        }
        return observation;
      }

      const generation = entrypoint === "generate"
        ? await request("generate", "/one-time-token/generate", undefined, sessionCookie(fixedSessionToken))
        : await request("set-ott", "/sign-in/email", { email: owner.email, password });
      const verify = await request("verify", "/one-time-token/verify", { token });
      const replay = await request("replay", "/one-time-token/verify", { token });

      assert.equal(generation.response.status, 200);
      assert.equal(generation.before.verification.length, 0);
      assert.equal(generation.after.verification.length, 1);
      assert.equal(generation.after.session.length, 1);
      const session = generation.after.session[0];
      assert.equal(session.userId, owner.id);
      const proof = generation.after.verification[0];
      assert.equal(proof.identifier, `one-time-token:${storedToken}`);
      assert.equal(proof.value, session.token);
      const deadline = backend === "memory" ? proof.expiresAt.value : proof.expiresAt;
      assert.equal(deadline, new Date(issuedAt + lifetimeMillis).toISOString());
      assert.equal(generation.completedAt, issuedAt + hashDurationMillis);
      assert.deepEqual(generation.after.user, generation.before.user);
      assert.deepEqual(generation.after.account, generation.before.account);
      const generationEvents = generation.events.filter(event => event.kind === "token.generate");
      assert.equal(generationEvents.length, 1);
      assert.equal(generationEvents[0].timestampMillis, issuedAt);
      assert.equal(generationEvents[0].session.session.token, session.token);
      assert.equal(generationEvents[0].session.user.id, owner.id);
      const hashEvents = [generation, verify, replay].flatMap(operation => operation.events.filter(event => event.kind.startsWith("token.hash.")));
      assert.deepEqual(hashEvents, [1, 2, 3].flatMap(invocation => [
        { kind: "token.hash.start", invocation, token, timestampMillis: issuedAt + (invocation === 1 ? 0 : hashDurationMillis) },
        { kind: "token.hash.end", invocation, token, result: storedToken, timestampMillis: issuedAt + hashDurationMillis },
      ]));
      assert.equal(hashCalls, 3);
      const replacements = [];
      const cookie = sessionCookie(session.token);
      if (entrypoint === "generate") {
        assert.deepEqual(JSON.parse(generation.response.body), { token });
        assert.deepEqual(generation.response.cookies, []);
        assert.deepEqual(generation.after.session, generation.before.session);
      } else {
        assert.match(session.token, /^[a-zA-Z0-9]{32}$/);
        assert.deepEqual(JSON.parse(generation.response.body), { redirect: false, token: session.token, user: JSON.parse(JSON.stringify(owner)) });
        assert.equal(new Headers(generation.response.headers).get("set-ott"), token);
        assert.ok(new Headers(generation.response.headers).get("access-control-expose-headers").split(",").map(value => value.trim()).includes("set-ott"));
        assert.equal(generation.response.cookies.length, 1);
        assert.equal(generation.response.cookies[0].split(";")[0], cookie);
        assert.deepEqual(generation.events.filter(event => event.kind.startsWith("password.")), [
          { kind: "password.verify", value: { hash: passwordHash, password } },
        ]);
        replacements.push([cookie, "better-auth.session_token=<verified-signed-session-token>"], [session.token, "<session-token>"]);
      }
      for (const operation of [verify, replay]) {
        assert.equal(operation.response.status, 400);
        assert.deepEqual(JSON.parse(operation.response.body), { message: "Invalid token" });
        assert.deepEqual(operation.response.cookies, []);
        assert.deepEqual(operation.after, { ...generation.after, verification: [] });
      }
      assert.deepEqual(verify.before, generation.after);
      assert.deepEqual(replay.before, verify.after);
      const read = await request("session", "/get-session", undefined, cookie);
      assert.equal(read.response.status, 200);
      const readBody = JSON.parse(read.response.body);
      assert.equal(readBody.session.token, session.token);
      assert.equal(readBody.session.userId, owner.id);
      assert.deepEqual(readBody.user, JSON.parse(JSON.stringify(owner)));
      assert.deepEqual(read.response.cookies, []);
      assert.deepEqual(read.after, replay.after);
      assert.deepEqual(read.events, []);
      assert.equal(hashCalls, 3);
      return normalize({ ...label, seed, generation, verify, replay, session: read, hashCalls }, replacements);
    });
  } finally { database?.close(); }
}

export async function captureOneTimeTokenExpiry({ diagnostics = [] } = {}) {
  for (const name of ["better-auth", "@better-auth/core"]) {
    const actual = JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version;
    diagnostics.push({ stage: "version", name, actual });
    assert.equal(actual, version);
  }
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const entrypoint of ["generate", "set-ott"]) cases.push(await captureCase(backend, entrypoint, diagnostics));
  }
  return { version, issuedAt, expiresIn, lifetimeMillis, hashDurationMillis, scope: {
    expiry: "The deadline precedes custom hashing; expired proof consumption removes the proof before replay",
    entrypoints: "Authenticated HTTP generation and the set-ott hook after email sign-in",
    signIn: "A deterministic configured password verifier admits the seeded credential account",
    normalization: "Replace the generated session token after checking its shape, storage references, and signed cookie",
    storage: "Capture every Memory or SQLite table and core lifecycle hook around generation, verification, replay, and session lookup",
  }, cases };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the One Time Token expiry fixture output path");
  const diagnostics = [];
  try {
    writeFileSync(output, `${JSON.stringify(await captureOneTimeTokenExpiry({ diagnostics }), null, 2)}\n`);
  } catch (error) {
    diagnostics.push({ stage: "capture-error", error: { name: error.name, message: error.message, stack: error.stack } });
    throw error;
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
