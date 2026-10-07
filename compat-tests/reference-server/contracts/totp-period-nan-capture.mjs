import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { twoFactor } from "better-auth/plugins";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { observeValue } from "./device-where-capture.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { account, issuer, secret } from "./totp-period.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
const utilsVersion = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/utils/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
assert.equal(utilsVersion, "0.4.2");
const legacy = JSON.parse(readFileSync(new URL("../../../tests/fixtures/totp-period-1.7.6.json", import.meta.url), "utf8"));
const timestampMillis = 1_700_000_025_125;
const origin = "http://totp-period-nan.test";
const authSecret = "totp-period-nan-contract-secret-longer-than-32-characters";
const tables = ["user", "session", "account", "verification", "twoFactor"];
const backupCodes = ["ordinary-backup-one", "ordinary-backup-two"];

function errorObservation(error) {
  assert.ok(error instanceof Error);
  const keys = Object.getOwnPropertyNames(error).filter(key => key !== "stack");
  return {
    name: error.name, message: error.message, keys,
    properties: Object.fromEntries(keys.map(key => [key, observeValue(error[key])])),
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

function assertURI(value, plaintext, digits, period) {
  const encoded = base32.encode(plaintext, { padding: false });
  const query = new URLSearchParams({ secret: encoded, issuer, digits: String(digits), period: String(period) });
  assert.equal(value, `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?${query}`);
  assert.equal(new TextDecoder().decode(base32.decode(new URL(value).searchParams.get("secret"))), plaintext);
  return encoded;
}

async function rawHelper(options, code, diagnostics) {
  const label = { digits: options.digits, surface: "helper" };
  const observe = async (name, input, operation) => {
    const result = await outcome(operation, diagnostics, { ...label, name });
    diagnostics.push({ ...label, name, input: observeValue(input), outcome: result, before: null, after: null, events: [] });
    return result;
  };
  let otp;
  const initialization = await observe("initialization", { secret, options }, () => { otp = createOTP(secret, options); });
  returned(initialization);
  const uri = await observe("uri", { issuer, account }, () => otp.url(issuer, account));
  assertURI(returned(uri), secret, options.digits, NaN);
  const generation = await observe("generation", {}, () => otp.totp());
  const verification = await observe("verification", { code }, () => otp.verify(code));
  for (const result of [generation, verification]) {
    assert.equal(result.kind, "thrown", JSON.stringify(result));
    assert.equal(result.error.name, "RangeError");
  }
  return { initialization, uri, generation, verification };
}

async function runtime(digits, name, enabled, diagnostics) {
  const label = { digits, surface: name };
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const events = [];
  let recording = false;
  let generated = 0;
  const record = event => { if (recording) events.push(observeValue(event)); };
  const snapshot = () => observeValue(memory);
  const auth = betterAuth({
    database: memoryAdapter(memory), baseURL: origin, secret: authSecret, appName: issuer,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { expiresIn: 3600, disableSessionRefresh: true, cookieCache: { enabled: false } },
    advanced: { database: { generateId(input) {
      const id = `nan-${digits}-${name}-${input.model}-${++generated}`;
      record({ kind: "generate-id", input, id });
      return id;
    } } },
    plugins: [twoFactor({
      allowPasswordless: true, totpOptions: { period: NaN, digits },
      backupCodeOptions: { customBackupCodesGenerate() {
        record({ kind: "backup-codes", codes: backupCodes });
        return [...backupCodes];
      } },
    })],
    databaseHooks: Object.fromEntries(tables.filter(model => model !== "twoFactor").map(model => [model,
      Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
        before(data) { record({ kind: "hook", model, operation, phase: "before", data }); },
        after(data) { record({ kind: "hook", model, operation, phase: "after", data }); },
      }])),
    ])),
  });
  let context;
  const empty = snapshot();
  const initialization = await outcome(async () => { context = await auth.$context; }, diagnostics,
    { ...label, name: "initialization" });
  diagnostics.push({ ...label, name: "initialization", input: observeValue({ period: NaN, digits, enabled }),
    before: empty, outcome: initialization, after: snapshot(), events: [...events] });
  returned(initialization);
  assert.deepEqual(snapshot(), Object.fromEntries(tables.map(model => [model, []])));
  const date = new Date(timestampMillis);
  const ownerInput = { model: "user", forceAllowId: true, data: {
    id: "nan-owner", name: "NaN TOTP Owner", email: account, emailVerified: true, image: null,
    twoFactorEnabled: enabled, createdAt: date, updatedAt: date,
  } };
  let owner;
  let session;
  const sessionToken = "nan-owner-session-token";
  const sessionInput = { model: "session", forceAllowId: true, data: {
    id: "nan-session", userId: ownerInput.data.id, token: sessionToken,
    expiresAt: new Date(timestampMillis + 3_600_000), createdAt: date, updatedAt: date,
    ipAddress: null, userAgent: null,
  } };
  const seeding = await observe("seed", { owner: ownerInput, session: sessionInput, sessionToken }, async () => {
    owner = await context.adapter.create(ownerInput);
    sessionInput.data.userId = owner.id;
    await context.adapter.create(sessionInput);
    session = await context.internalAdapter.findSession(sessionToken);
    return { owner, session };
  });
  returned(seeding.outcome);
  assert.ok(session);
  assert.equal(session.user.id, owner.id);
  const signature = createHmac("sha256", authSecret).update(sessionToken).digest("base64");
  const cookie = `better-auth.session_token=${encodeURIComponent(`${sessionToken}.${signature}`)}`;

  async function observe(name, input, operation) {
    assert.deepEqual(events, []);
    const before = snapshot();
    recording = true;
    let result;
    try { result = await outcome(operation, diagnostics, { ...label, name }); }
    finally { recording = false; }
    const observation = { name, input: observeValue(input), outcome: result, before, after: snapshot(), events: events.splice(0) };
    diagnostics.push({ ...label, ...observation });
    return observation;
  }

  async function request(path, body) {
    const request = new Request(`${origin}/api/auth${path}`, {
      method: "POST", headers: { origin, cookie, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const input = { url: request.url, method: request.method, headers: [...request.headers], body: await request.clone().text() };
    return observe(path, input, async () => {
      const response = await auth.handler(request);
      return { status: response.status, statusText: response.statusText,
        headers: [...response.headers], cookies: response.headers.getSetCookie(), body: await response.text() };
    });
  }

  return { auth, context, memory, initialization, owner, session, sessionToken, observe, request };
}

function unchanged(observation) {
  assert.deepEqual(observation.after, observation.before);
  assert.deepEqual(observation.events, []);
}

function response(observation, status) {
  const response = returned(observation.outcome);
  assert.equal(response.status, status, JSON.stringify(response));
  assert.deepEqual(response.cookies, []);
  return JSON.parse(response.body);
}

async function storedFactor(digits, defaultCase, diagnostics) {
  const server = await runtime(digits, "stored", true, diagnostics);
  const key = server.context.secretConfig;
  const encryptedSecret = returned((await server.observe("encrypt-seeded-secret", { plaintext: secret },
    () => symmetricEncrypt({ key, data: secret }))).outcome);
  const backupPayload = JSON.stringify(backupCodes);
  const encryptedBackupCodes = returned((await server.observe("encrypt-seeded-backup-codes", { plaintext: backupPayload },
    () => symmetricEncrypt({ key, data: backupPayload }))).outcome);
  const decryptedSecret = await server.observe("decrypt-seeded-secret", { ciphertext: encryptedSecret },
    () => symmetricDecrypt({ key, data: encryptedSecret }));
  assert.equal(returned(decryptedSecret.outcome), secret);
  const decryptedBackupCodes = await server.observe("decrypt-seeded-backup-codes", { ciphertext: encryptedBackupCodes },
    () => symmetricDecrypt({ key, data: encryptedBackupCodes }));
  assert.deepEqual(JSON.parse(returned(decryptedBackupCodes.outcome)), backupCodes);
  const factorInput = { model: "twoFactor", forceAllowId: true, data: {
    id: "nan-factor", userId: server.owner.id, secret: encryptedSecret,
    backupCodes: encryptedBackupCodes, verified: true,
  } };
  const seeded = await server.observe("seed-two-factor", factorInput, () => server.context.adapter.create(factorInput));
  returned(seeded.outcome);
  const generation = await server.observe("generateTOTP", { body: { secret } },
    () => server.auth.api.generateTOTP({ body: { secret } }));
  assert.deepEqual(returned(generation.outcome), defaultCase.server);
  unchanged(generation);
  const uri = await server.request("/two-factor/get-totp-uri", {});
  const fetched = response(uri, 200);
  assert.deepEqual(fetched, { totpURI: defaultCase.helper.uri });
  assertURI(fetched.totpURI, secret, digits, 30);
  unchanged(uri);
  const verification = await server.request("/two-factor/verify-totp", { code: defaultCase.server.code });
  assert.deepEqual(response(verification, 200), {
    token: server.sessionToken, user: JSON.parse(JSON.stringify(server.session.user)),
  });
  unchanged(verification);
  const invalid = await server.request("/two-factor/verify-totp", { code: "not-a-totp" });
  assert.deepEqual(response(invalid, 401), { code: "INVALID_CODE", message: "Invalid code" });
  unchanged(invalid);
  return normalize({ initialization: server.initialization, generation, uri, verification, invalid }, [
    [encryptedSecret, "<stored-secret-ciphertext>"], [encryptedBackupCodes, "<stored-backup-ciphertext>"],
  ]);
}

async function enrollment(digits, diagnostics) {
  const server = await runtime(digits, "enrollment", false, diagnostics);
  const enable = await server.request("/two-factor/enable", { method: "totp" });
  const enabled = response(enable, 200);
  assert.equal(server.memory.twoFactor.length, 1);
  const factor = server.memory.twoFactor[0];
  assert.equal(factor.userId, server.owner.id);
  assert.equal(factor.verified, false);
  const key = server.context.secretConfig;
  const generatedSecret = returned((await server.observe("decrypt-enrollment-secret", { ciphertext: factor.secret },
    () => symmetricDecrypt({ key, data: factor.secret }))).outcome);
  assert.equal(generatedSecret.length, 32);
  const decryptedBackupCodes = returned((await server.observe("decrypt-enrollment-backup-codes", { ciphertext: factor.backupCodes },
    () => symmetricDecrypt({ key, data: factor.backupCodes }))).outcome);
  assert.deepEqual(JSON.parse(decryptedBackupCodes), backupCodes);
  const encodedSecret = assertURI(enabled.totpURI, generatedSecret, digits, NaN);
  assert.deepEqual(enabled, { method: "totp", totpURI: enabled.totpURI, backupCodes });
  for (const model of tables.filter(model => model !== "twoFactor")) {
    assert.deepEqual(enable.after[model], enable.before[model]);
  }
  assert.deepEqual(enable.before.twoFactor, []);
  assert.deepEqual(enable.after.twoFactor, [observeValue(factor)]);
  assert.deepEqual(enable.events.filter(event => event.kind === "backup-codes"), [{ kind: "backup-codes", codes: backupCodes }]);
  assert.equal(enable.events.filter(event => event.kind === "generate-id").length, 1);
  assert.deepEqual(enable.events.filter(event => event.kind === "hook"), []);
  const uri = await server.request("/two-factor/get-totp-uri", {});
  const fetched = response(uri, 200);
  assertURI(fetched.totpURI, generatedSecret, digits, 30);
  assert.deepEqual(fetched, { totpURI: enabled.totpURI.replace("&period=NaN", "&period=30") });
  unchanged(uri);
  return normalize({ initialization: server.initialization, enable, uri }, [
    [factor.secret, "<enrollment-secret-ciphertext>"], [factor.backupCodes, "<enrollment-backup-ciphertext>"],
    [encodedSecret, "<enrollment-secret-base32>"], [generatedSecret, "<enrollment-secret>"],
  ]);
}

export async function captureTotpPeriodNaN({ diagnostics = [] } = {}) {
  return withClock(async setClock => {
    setClock(timestampMillis);
    const cases = [];
    for (const digits of [6, 8]) {
      const defaultCase = legacy.cases.find(input => input.name === `omitted-digits-${digits}-time-1`);
      assert.ok(defaultCase);
      assert.equal(defaultCase.timestampMillis, timestampMillis);
      const options = { period: NaN, digits };
      try {
        cases.push({
          options: observeValue(options), helper: await rawHelper(options, defaultCase.server.code, diagnostics),
          server: await storedFactor(digits, defaultCase, diagnostics), enrollment: await enrollment(digits, diagnostics),
        });
      } catch (error) {
        diagnostics.push({ digits, stage: "case-error", error: { ...errorObservation(error), stack: error.stack } });
        throw error;
      }
    }
    return { version, utilsVersion, secret, issuer, account, timestampMillis, scope: {
      helper: "Raw createOTP uses nullish defaults; NaN reaches the counter conversion and remains in the URI",
      server: "generateTOTP, getTOTPURI, and verifyTOTP use the plugin's 30-second default",
      enrollment: "enableTwoFactor retains the configured NaN period in its URI",
      normalization: "Replace ciphertext only after decryption; replace the enrollment secret only after complete URI and Base32 checks",
      storage: "Capture every Memory table before and after each operation; capture core lifecycle hooks and the backup-code callback",
    }, cases };
  });
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the TOTP NaN fixture output path");
  const diagnostics = [];
  try {
    writeFileSync(output, `${JSON.stringify(await captureTotpPeriodNaN({ diagnostics }), null, 2)}\n`);
  } catch (error) {
    diagnostics.push({ stage: "capture-error", error: { ...errorObservation(error), stack: error.stack } });
    throw error;
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
