import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { APIError } from "@better-auth/core/error";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { withRestoredSchema } from "./schema-isolation.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow as now } from "./secondary-native-shared.mjs";
import { createTransport, reviveTransportInput as revive, transportCases, transportFails } from "./passkey-transport-methods-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const origin = "http://passkey-native-errors.test";
const rpID = "passkey-native-errors.test";
const secret = "passkey-native-errors-secret-at-least-thirty-two-characters";
const seedPath = new URL("../../../tests/fixtures/passkey-native-errors-1.7.6.json", import.meta.url);
export const passkeyTransportCases = transportCases.flatMap(method => [false, true].map(validSignature => ({
  name: `${method}-${validSignature ? "valid" : "invalid"}-signature`, method, validSignature,
})));

async function captureCase(scenario, seed) {
  const transport = createTransport(scenario.method);
  const runtime = createSecondaryRuntimeObserver();
  const native = createSecondaryNativeObserver();
  const errors = createProtectedFunctionObserver();
  const logs = [];
  const verification = [];
  const memory = { user: [], session: [], account: [], verification: [], passkey: [] };
  let generated = 0;
  let active = false;
  const auth = betterAuth({
    baseURL: origin, secret, database: memoryAdapter(memory),
    logger: { level: "error", log(level, message, ...args) {
      assert.equal(active, true);
      logs.push({ level, message, arguments: args.map(errors.error), sameOriginal: args.map(value => value === transport.original) });
    } },
    telemetry: { enabled: false }, rateLimit: { enabled: false },
    experimental: { instrumentation: { enabled: false } },
    session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
    advanced: { database: { generateId: ({ model }) => `${model}-${++generated}` } },
    plugins: [passkey({ rpID, rpName: "Native errors", authentication: { afterVerification({ verification: checked, clientData }) {
      verification.push(runtime.value({ verification: checked, clientData }));
    } } }), { id: "passkey-transport-methods", schema: { passkey: { fields: {
      transports: { type: "string", required: false, transform: { output: value => active ? transport.receiver : value } },
    } } } }],
  });
  const context = await auth.$context;
  const input = structuredClone(seed.input);
  input.sessionToken = `${scenario.name}-session-token`;
  if (!scenario.validSignature) {
    const signature = Buffer.from(input.response.response.signature, "base64url");
    assert.equal(signature[0], 0x30);
    signature[signature.length - 1] ^= 1;
    input.response.response.signature = signature.toString("base64url");
  }
  Object.assign(memory, revive(seed.runtime.before));
  const createSession = context.internalAdapter.createSession;
  context.internalAdapter.createSession = function (...args) {
    return Reflect.apply(createSession, this, [args[0], args[1], { ...args[2], token: input.sessionToken }, true, args[4]]);
  };
  const before = runtime.value(memory);
  const rawBefore = native.snapshot(memory);
  active = true;
  let result;
  let caught;
  try {
    result = await auth.api.verifyPasskeyAuthentication({ headers: new Headers(input.headers), body: { response: revive(input.response) } });
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    caught = error;
  }
  active = false;
  transport.assertCalls();
  const succeeded = scenario.validSignature && !transportFails(scenario.method);
  assert.equal(caught === undefined, succeeded);
  assert.deepEqual(memory.user, revive(before.user));
  assert.deepEqual(memory.account, []);
  assert.deepEqual(memory.verification, []);
  assert.deepEqual(runtime.value(memory.passkey), before.passkey.map(row => ({ ...row, counter: succeeded ? 1 : 0 })));
  assert.equal(memory.session.length, succeeded ? 1 : 0);
  assert.equal(verification.length, succeeded ? 1 : 0);
  if (succeeded) {
    assert.deepEqual(result.session, memory.session[0]);
    assert.deepEqual(result.user, memory.user[0]);
    assert.equal(memory.session[0].token, input.sessionToken);
  } else {
    assert.ok(caught instanceof APIError);
    if (scenario.method === "api-error") {
      assert.equal(caught, transport.original);
      assert.equal(caught.statusCode, 409);
    } else {
      assert.notEqual(caught, transport.original);
      assert.equal(caught.statusCode, transportFails(scenario.method) ? 400 : 401);
      assert.deepEqual(caught.body, { message: "Authentication failed", code: "AUTHENTICATION_FAILED" });
    }
  }
  assert.equal(logs.length, transportFails(scenario.method) && scenario.method !== "api-error" ? 1 : 0);
  if (["getter-error", "call-error"].includes(scenario.method)) assert.deepEqual(logs[0].sameOriginal, [true]);
  return {
    name: scenario.name, scenario, input,
    runtime: { before, events: transport.events, verification, logs,
      outcome: { returned: succeeded, result: runtime.value(result), error: caught === undefined ? null : errors.error(caught),
        sameOriginal: caught === transport.original, coreAPIError: caught instanceof APIError },
      after: runtime.value(memory) },
    raw: { before: rawBefore, result: native.snapshot(result), error: native.snapshot(caught),
      splitResult: native.snapshot(transport.result), original: native.snapshot(transport.original), after: native.snapshot(memory), functions: native.functions },
  };
}

export async function capturePasskeyTransportMethods() {
  assertSecondaryNativeVersions();
  assert.equal(JSON.parse(readFileSync(new URL("../node_modules/@better-auth/passkey/package.json", import.meta.url), "utf8")).version, "1.7.6");
  const seedFixture = JSON.parse(readFileSync(seedPath, "utf8"));
  assert.equal(seedFixture.contract, "passkey-native-errors");
  const seed = seedFixture.cases.find(entry => entry.name === "authentication-null-session");
  assert.ok(seed);
  const provenance = [
    ["passkey", "../node_modules/@better-auth/passkey/dist/index.mjs"],
    ["verification", "../node_modules/@simplewebauthn/server/esm/authentication/verifyAuthenticationResponse.js"],
    ["shared", "./passkey-transport-methods-shared.mjs"],
    ["seed", "../../../tests/fixtures/passkey-native-errors-1.7.6.json"],
  ].map(([name, path]) => ({ name, sha256: createHash("sha256").update(readFileSync(new URL(path, import.meta.url))).digest("hex") }));
  return withClock(async setClock => {
    setClock(now);
    return withRestoredSchema(passkey().schema, async () => {
      const cases = [];
      for (const scenario of passkeyTransportCases) cases.push(await captureCase(scenario, seed));
      return { contract: "passkey-transport-methods", version: "1.7.6", backend: "memory", provenance,
        boundary: "Unmodified native Passkey authentication and SimpleWebAuthn signature verification. The existing passkey-native-errors fixture supplies all signed bytes, credential columns, challenge JSON and headers. No signer is run. Each case changes only the declared signature byte or output transform. The supported createSession overrideAll argument fixes the token while retaining real persistence. The shared observers retain complete native returns, errors, callback data, storage and original identities. Raw observations retain host descriptors and stacks; the existing semantic error observer excludes host stack metadata. Rust SQLite options and authentication regressions separately preserve backend snapshots. HTTP headers, symbol reflection and private WebAuthn engine types remain separate boundaries.", cases };
    });
  });
}

if (import.meta.main) {
  assert.equal(process.argv.length, 3, "Pass the output path");
  const serialized = `${JSON.stringify(await capturePasskeyTransportMethods(), null, 2)}\n`;
  writeFileSync(process.argv[2], serialized);
  await writeObservation(serialized);
}
