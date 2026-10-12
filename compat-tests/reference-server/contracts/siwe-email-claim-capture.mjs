import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { APIError } from "@better-auth/core/error";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { siwe } from "better-auth/plugins";
import { withClock } from "./email-verification-duration-capture.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { withRestoredSchema } from "./schema-isolation.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow as now } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const origin = "http://siwe-claims.test";
const address = "0x0000000000000000000000000000000000000001";
const nonce = "native123";
const email = "owner@siwe-claims.test";
const claim = `siwe-email-claim-${email}`;
const body = {
  message: `example.com wants you to sign in with your Ethereum account:\n${address}\n\nChain ID: 1\nNonce: ${nonce}`,
  signature: "verified-by-application", email: email.toUpperCase(),
};
export const siweEmailClaimCases = [
  "success", "reserve-before", "reserve-after", "cleanup-before", "cleanup-after",
  "create-error", "create-error-cleanup-before", "create-error-cleanup-after",
  "retry-query-error", "initial-query-error", "ens-error", "retry-success",
];

async function captureCase(mode) {
  const memory = { user: [], session: [], account: [], verification: [], walletAddress: [] };
  const runtime = createSecondaryRuntimeObserver();
  const native = createSecondaryNativeObserver();
  const observer = createProtectedFunctionObserver();
  const errors = Object.fromEntries(["reserve", "cleanup", "create", "lookup", "ens", "logger"].map(phase => [phase,
    new APIError("CONFLICT", { code: `CLAIM_${phase}`, message: `Original ${phase} error` }),
  ]));
  const events = [];
  const logs = [];
  let lookups = 0;
  let creates = 0;
  let generated = 0;
  let claimed = [];
  let createdUsers = [];
  const auth = betterAuth({
    baseURL: origin, secret: "siwe-email-claim-secret-at-least-thirty-two-characters",
    database: memoryAdapter(memory), telemetry: { enabled: false }, rateLimit: { enabled: false },
    experimental: { instrumentation: { enabled: false } },
    logger: { level: "warn", log(...args) { logs.push(runtime.value(args)); throw errors.logger; } },
    session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
    advanced: { database: { generateId: ({ model }) => `${model}-${++generated}` } },
    plugins: [siwe({
      domain: "example.com", anonymous: false, getNonce: async () => nonce,
      verifyMessage: async () => { events.push("verify"); return true; },
      ensLookup: async () => {
        events.push("ens");
        if (mode === "ens-error") throw errors.ens;
        return {};
      },
    })],
  });
  const context = await auth.$context;
  const internal = context.internalAdapter;
  await internal.createVerificationValue({ identifier: `siwe:${nonce}`, value: nonce, expiresAt: new Date(now + 300_000) });
  const reserve = internal.reserveVerificationValue;
  internal.reserveVerificationValue = async function (...args) {
    assert.equal(args[0].identifier, claim);
    events.push("reserve");
    if (mode === "reserve-before") throw errors.reserve;
    const reserved = await Reflect.apply(reserve, this, args);
    claimed = structuredClone(memory.verification);
    if (mode === "reserve-after") throw errors.reserve;
    return reserved;
  };
  const consume = internal.consumeVerificationValue;
  internal.consumeVerificationValue = async function (...args) {
    const cleanup = args[0] === claim;
    events.push(cleanup ? "cleanup" : "nonce");
    if (cleanup && mode.endsWith("cleanup-before")) throw errors.cleanup;
    const consumed = await Reflect.apply(consume, this, args);
    if (cleanup && mode.endsWith("cleanup-after")) throw errors.cleanup;
    return consumed;
  };
  const find = internal.findUserByEmail;
  internal.findUserByEmail = async function (...args) {
    events.push("lookup");
    lookups++;
    if (mode === "initial-query-error" && lookups === 1 || mode === "retry-query-error" && lookups === 2) throw errors.lookup;
    return Reflect.apply(find, this, args);
  };
  const create = internal.createUser;
  internal.createUser = async function (...args) {
    events.push("create");
    creates++;
    if (mode.startsWith("create-error") || mode === "retry-query-error") throw errors.create;
    const created = await Reflect.apply(create, this, args);
    createdUsers = structuredClone(memory.user);
    if (mode === "retry-success" && creates === 1) throw errors.create;
    return created;
  };
  const createSession = internal.createSession;
  internal.createSession = function (...args) {
    return Reflect.apply(createSession, this, [args[0], args[1], { ...args[2], token: `${mode}-session-token` }, true, args[4]]);
  };
  const before = runtime.value(memory);
  const rawBefore = native.snapshot(memory);
  const request = new Request(`${origin}/api/auth/siwe/verify`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  let result;
  let caught;
  try { result = await auth.api.verifySiweMessage({ request, body }); }
  catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    caught = error;
  }
  const expectedError = ["retry-query-error", "initial-query-error"].includes(mode) ? "lookup"
    : mode.startsWith("create-error") ? "create" : mode === "ens-error" ? "ens" : undefined;
  if (expectedError) {
    assert.equal(caught, errors[expectedError]);
    assert.equal(caught.statusCode, 409);
    for (const model of ["user", "session", "walletAddress", "account"]) assert.deepEqual(memory[model], []);
  } else {
    assert.equal(caught, undefined);
    assert.equal(memory.user.length, mode === "retry-success" ? 2 : 1);
    for (const model of ["session", "walletAddress", "account"]) assert.equal(memory[model].length, 1);
    const user = memory.user.at(-1);
    const placeholder = `${address}@siwe.placeholder.invalid`;
    assert.equal(user.email, ["reserve-before", "reserve-after", "retry-success"].includes(mode) ? placeholder : email);
    assert.equal(user.name, address);
    assert.equal(user.image, "");
    assert.equal(user.emailVerified, false);
    assert.equal(memory.walletAddress[0].userId, user.id);
    assert.equal(memory.walletAddress[0].address, address);
    assert.equal(memory.walletAddress[0].chainId, 1);
    assert.equal(memory.walletAddress[0].isPrimary, true);
    assert.equal(memory.account[0].userId, user.id);
    assert.equal(memory.account[0].providerId, "siwe");
    assert.equal(memory.account[0].accountId, `${address}:1`);
    assert.equal(memory.session[0].userId, user.id);
    assert.deepEqual(result, { token: memory.session[0].token, success: true, user: { id: user.id, walletAddress: address, chainId: 1 } });
    if (mode === "retry-success") assert.equal(memory.user[0].email, email);
  }
  assert.deepEqual(memory.user, createdUsers);
  const expectedEvents = mode === "initial-query-error" ? ["nonce", "verify", "reserve", "lookup"]
    : mode === "ens-error" ? ["nonce", "verify", "reserve", "lookup", "ens"]
    : ["reserve-before", "reserve-after"].includes(mode) ? ["nonce", "verify", "reserve", "ens", "create"]
    : mode === "retry-success" ? ["nonce", "verify", "reserve", "lookup", "ens", "create", "lookup", "create", "cleanup"]
    : mode.startsWith("create-error") || mode === "retry-query-error" ? ["nonce", "verify", "reserve", "lookup", "ens", "create", "lookup", "cleanup"]
    : ["nonce", "verify", "reserve", "lookup", "ens", "create", "cleanup"];
  assert.deepEqual(events, expectedEvents);
  assert.deepEqual(logs, []);
  const claimRemains = ["reserve-after", "initial-query-error", "ens-error"].includes(mode) || mode.endsWith("cleanup-before");
  assert.deepEqual(memory.verification, claimRemains ? claimed : []);
  if (claimRemains) {
    assert.equal(memory.verification.length, 1);
    assert.equal(memory.verification[0].identifier, claim);
    assert.equal(memory.verification[0].value, address);
  }
  return {
    name: mode, input: { body, now },
    runtime: { before, events, logs, claimed: runtime.value(claimed), createdUsers: runtime.value(createdUsers),
      outcome: { returned: caught === undefined, result: runtime.value(result),
        error: caught === undefined ? null : observer.error(caught), sameOriginal: expectedError ? caught === errors[expectedError] : false },
      after: runtime.value(memory) },
    raw: { before: rawBefore, result: native.snapshot(result), error: native.snapshot(caught),
      originals: native.snapshot(errors), after: native.snapshot(memory), functions: native.functions },
  };
}

export async function captureSiweEmailClaims() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = [["siwe", "../node_modules/better-auth/dist/plugins/siwe/index.mjs"],
    ["internal-adapter", "../node_modules/better-auth/dist/db/internal-adapter.mjs"]]
    .map(([name, path]) => ({ name, sha256: createHash("sha256").update(readFileSync(new URL(path, import.meta.url))).digest("hex") }));
  return withClock(async setClock => {
    setClock(now);
    return withRestoredSchema(siwe({ domain: "example.com", getNonce: async () => nonce, verifyMessage: async () => true }).schema, async () => {
      const cases = [];
      for (const mode of siweEmailClaimCases) cases.push(await captureCase(mode));
      return { contract: "siwe-email-claim", version: "1.7.6", backend: "memory", provenance,
        boundary: "Real native SIWE verification with declared errors injected before or after actual internal adapter operations. Unmodified upstream code controls catch/finally scope, fallback creation and persistence. A throwing logger proves that swallowed reservation and cleanup errors do not log. Native results, error identity, complete storage and callback order are retained. Session tokens use the supported createSession overrideAll argument. Rust direct regressions verify the same twelve paths against real Memory storage; they retain their actual clock values and do not compare dates against this source fixture. SQL isolation, HTTP headers, concurrent reservation and native reflection remain separate boundaries.", cases };
    });
  });
}

if (import.meta.main) {
  assert.equal(process.argv.length, 3, "Pass the output path");
  const serialized = `${JSON.stringify(await captureSiweEmailClaims(), null, 2)}\n`;
  writeFileSync(process.argv[2], serialized);
  await writeObservation(serialized);
}
