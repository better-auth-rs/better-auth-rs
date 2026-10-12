import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { serializeSignedCookie } from "better-call";
import { twoFactor } from "better-auth/plugins/two-factor";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, secondaryNativeNow as now, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { createConsumerHarness, consumerSecret } from "./verification-consumer-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const challenge = "2fa-otp-native";
const identifier = `2fa-otp-${challenge}`;
export const twoFactorOtpNativeCases = [
  { name: "native-split-array" },
  { name: "split-getter-error", fail: "split:get" },
  { name: "split-call-error", fail: "split:call" },
  ...["string", "array-like", "null", "undefined"].map(splitShape => ({ name: `split-${splitShape}`, splitShape })),
  ...["string-object", "string-error", "object", "false", "nan"].map(attempts => ({ name: `counter-${attempts}`, attempts })),
  { name: "counter-exhausted", exhausted: true },
  ...["plain", "null", "undefined", "false"].map(value => ({ name: `value-${value}`, value })),
].map(scenario => ({ consumer: "two-factor-otp", value: "methods", ...scenario }));

const factor = () => ({ id: "factor-row", secret: "native-factor-secret", backupCodes: "[]",
  userId: "owner", verified: true, failedVerificationCount: 2, lockedUntil: null });

async function captureCase(scenario) {
  const harness = createConsumerHarness(scenario, identifier);
  for (const [id, key, value] of [["challenge-row", challenge, "owner"], ["attempts-row", `2fa-attempts-${challenge}`, "0"]]) {
    harness.cache.set(`verification:${key}`, JSON.stringify({ id, identifier: key, value,
      expiresAt: new Date(now + 60_000), createdAt: new Date(now), updatedAt: new Date(now) }));
  }
  harness.database.twoFactor = [factor()];
  const plugin = twoFactor({ otpOptions: { storeOTP: "plain", allowedAttempts: 3,
    sendOTP: async () => harness.fail("unexpected:send-otp") } });
  const captured = await harness.capture([plugin], async (auth, context) => {
    const cookie = (await serializeSignedCookie(context.createAuthCookie("two_factor").name, challenge, consumerSecret)).split(";", 1)[0];
    return auth.api.verifyTwoFactorOTP({ body: { code: "wrong" }, headers: new Headers({ cookie }) });
  });
  const { events, after, outcome } = captured.observation.runtime;
  assert.equal(outcome.returned, false);
  const consumed = events.findIndex(event => event.phase === "storage.getAndDelete" && event.key === harness.targetKey);
  assert.ok(consumed >= 0);
  const split = events.findIndex(event => event.phase === "get:split");
  if (scenario.value === "methods") assert.ok(split > consumed);
  else assert.equal(split, -1);
  const original = Boolean(scenario.fail) || scenario.attempts === "string-error";
  if (original) assert.equal(captured.caught, harness.original);
  const invalid = !original && scenario.splitShape !== "array-like" && scenario.value !== "false" && !scenario.exhausted;
  assert.equal(after.targetPresent, invalid);
  assert.equal(after.targetSameRoot, false);
  if (invalid) {
    assert.equal(captured.caught.statusCode, 401);
    assert.deepEqual(captured.caught.body, { code: "INVALID_CODE", message: "Invalid code" });
    const stored = JSON.parse(harness.cache.get(harness.targetKey));
    const otp = scenario.splitShape === "string" ? "1"
      : ["null", "undefined"].includes(scenario.splitShape) || ["null", "undefined"].includes(scenario.value) ? "undefined" : "123456";
    const attempts = scenario.counterText === undefined
      ? scenario.splitShape === "string" || scenario.attempts === "string-object" ? 3 : 1
      : (Number.parseInt(scenario.counterText, 10) || 0) + 1;
    assert.equal(stored.value, `${otp}:${attempts}`);
    assert.equal(stored.expiresAt, new Date(now + 60_000).toISOString());
  }
  if (scenario.exhausted) {
    assert.equal(captured.caught.statusCode, 400);
    assert.equal(captured.caught.body.code, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");
  }
  if (scenario.attempts === "object") assert.equal(events.some(event => event.phase === "get:valueOf"), false);
  assert.deepEqual(harness.database.twoFactor, [{ ...factor(), failedVerificationCount: invalid ? 3 : 2 }]);
  assert.equal(JSON.parse(harness.cache.get(`verification:2fa-attempts-${challenge}`)).value, "0");
  return captured.observation;
}

export async function captureTwoFactorOtpNative(scenarios = twoFactorOtpNativeCases) {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["plugins/two-factor/otp/index.mjs", "plugins/two-factor/verify-two-factor.mjs", "db/internal-adapter.mjs"].map(path => ({
    path: `better-auth/dist/${path}`, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/better-auth/dist/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of scenarios) cases.push(await captureCase(scenario));
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Real verifyTwoFactorOTP endpoint, Memory adapter and native secondary Verification values. Shared observations retain complete return/error values, split getter and receiver order, string counter conversion, original errors, consumed rows, restored attempts, factor writes and complete storage. Symbol iterator overrides remain outside the native value model. No OTP algorithm is copied into the harness.", cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "two-factor-otp-native", ...await captureTwoFactorOtpNative() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
