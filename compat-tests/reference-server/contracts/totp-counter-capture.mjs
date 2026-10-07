import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { twoFactor } from "better-auth/plugins";
import { createOTP } from "@better-auth/utils/otp";
import { observeValue } from "./device-where-capture.mjs";
import { account, issuer, secret } from "./totp-period.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
const utilsVersion = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/utils/package.json", import.meta.url), "utf8")).version;
const ordinaryTimestamp = 1_700_000_025_125;
const offsets = [-2, -1, 0, 1, 2];
const malformedToken = "not-a-totp";
const bigintCounterInputs = {
  "counter-two-to-53": ["9007199254740993"],
  "counter-two-to-64": ["18446744073709551615"],
};

export const counterCaseInputs = [
  { name: "epoch", timestampMillis: 0, period: 30 },
  { name: "before-epoch", timestampMillis: -1, period: 30 },
  { name: "ordinary", timestampMillis: ordinaryTimestamp, period: 30 },
  { name: "positive-infinite-period", timestampMillis: ordinaryTimestamp, period: Infinity },
  { name: "negative-infinite-period", timestampMillis: ordinaryTimestamp, period: -Infinity },
  { name: "negative-period", timestampMillis: ordinaryTimestamp, period: -30 },
  { name: "overflowed-milliseconds", timestampMillis: ordinaryTimestamp, period: Number.MAX_VALUE },
  { name: "counter-two-to-53", timestampMillis: 2 ** 52, period: 0.0005 },
  { name: "counter-before-two-to-64", timestampMillis: 2 ** 52 - 1, period: (2 ** -12) / 1000 },
  { name: "counter-two-to-64", timestampMillis: 2 ** 52, period: (2 ** -12) / 1000 },
  { name: "counter-after-two-to-64", timestampMillis: 2 ** 52 + 1, period: (2 ** -12) / 1000 },
  { name: "tiny-period", timestampMillis: ordinaryTimestamp, period: Number.MIN_VALUE },
].map(({ period, ...input }) => ({ ...input, options: { period, digits: 6 } }));

function errorObservation(error) {
  const keys = Object.getOwnPropertyNames(error).filter(key => key !== "stack");
  return {
    name: error.name, message: error.message, keys,
    properties: Object.fromEntries(keys.map(key => [key, observeValue(error[key])])),
  };
}

function counterObservation(counter) {
  return { rawNumber: observeValue(counter), negativeZero: Object.is(counter, -0) };
}

async function captureCounterCase(input, diagnostics) {
  const auth = betterAuth({
    baseURL: "http://totp-period.test",
    secret: "ordinary-totp-period-server-secret-longer-than-32-characters",
    database: memoryAdapter({ user: [], session: [], account: [], verification: [], twoFactor: [] }),
    logger: { disabled: true },
    telemetry: { enabled: false },
    rateLimit: { enabled: false },
    plugins: [twoFactor({ totpOptions: input.options })],
  });
  await auth.$context;
  const otp = createOTP(secret, input.options);

  async function observe(surface, name, operationInput, operation) {
    let outcome;
    let rawError;
    try { outcome = { kind: "returned", value: observeValue(await operation()) }; }
    catch (error) {
      const observed = errorObservation(error);
      outcome = { kind: "thrown", error: observed };
      rawError = { ...observed, stack: error.stack };
    }
    diagnostics.push({ case: input.name, surface, name, input: observeValue(operationInput), outcome,
      ...(rawError === undefined ? {} : { rawError }) });
    return outcome;
  }

  const originalNow = Date.now;
  try {
    Date.now = () => input.timestampMillis;
    const milliseconds = input.options.period * 1000;
    const counter = Math.floor(Date.now() / milliseconds);
    const server = await observe("server", "generateTOTP", { body: { secret } },
      () => auth.api.generateTOTP({ body: { secret } }));
    const generation = await observe("helper", "totp", { secret, options: input.options }, () => otp.totp());
    const uri = await observe("helper", "url", { issuer, account }, () => otp.url(issuer, account));
    const neighbors = [];
    for (const offset of offsets) {
      const neighborCounter = counter + offset;
      const observedCounter = counterObservation(neighborCounter);
      const hotp = await observe("helper", "hotp", { offset, counter: observedCounter }, () => otp.hotp(neighborCounter));
      const token = hotp.kind === "returned" ? hotp.value : undefined;
      const verification = hotp.kind === "returned"
        ? await observe("helper", "verify", { offset, counter: observedCounter, token }, () => otp.verify(token))
        : { kind: "not-run", reason: "HOTP generation threw before producing a token" };
      const neighbor = { offset, counter: observedCounter, hotp, token: observeValue(token), verification };
      diagnostics.push({ case: input.name, surface: "helper", name: "neighbor", ...neighbor });
      neighbors.push(neighbor);
    }
    const bigintNeighbors = [];
    for (const decimalCounter of bigintCounterInputs[input.name] ?? []) {
      const hotp = await observe("helper", "hotp-bigint", { decimalCounter }, () => otp.hotp(BigInt(decimalCounter)));
      const token = hotp.kind === "returned" ? hotp.value : undefined;
      const verification = hotp.kind === "returned"
        ? await observe("helper", "verify-bigint", { decimalCounter, token }, () => otp.verify(token))
        : { kind: "not-run", reason: "HOTP generation threw before producing a token" };
      const neighbor = { decimalCounter, hotp, token: observeValue(token), verification };
      diagnostics.push({ case: input.name, surface: "helper", name: "bigint-neighbor", ...neighbor });
      bigintNeighbors.push(neighbor);
    }
    const malformed = { token: malformedToken,
      verification: await observe("helper", "verify-malformed", { token: malformedToken }, () => otp.verify(malformedToken)) };
    const result = { ...observeValue(input), milliseconds: observeValue(milliseconds), counter: counterObservation(counter),
      server, helper: { generation, uri, neighbors, bigintNeighbors, malformed } };
    diagnostics.push({ case: input.name, stage: "complete", observation: result });
    return result;
  } finally {
    Date.now = originalNow;
  }
}

export async function captureTotpCounter({ diagnostics = [] } = {}) {
  const cases = [];
  for (const input of counterCaseInputs) {
    diagnostics.push({ case: input.name, stage: "input", input: observeValue(input) });
    cases.push(await captureCounterCase(input, diagnostics));
  }

  assert.equal(version, "1.7.6");
  assert.equal(utilsVersion, "0.4.2");
  assert.equal(cases.length, 12);
  assert.equal(new Set(cases.map(input => input.name)).size, cases.length);
  for (const input of cases) {
    assert.deepEqual(input.helper.neighbors.map(neighbor => neighbor.offset), offsets);
    assert.deepEqual(input.helper.bigintNeighbors.map(neighbor => neighbor.decimalCounter), bigintCounterInputs[input.name] ?? []);
    if (input.server.kind === "returned" && input.helper.generation.kind === "returned") {
      assert.deepEqual(input.server.value, { code: input.helper.generation.value });
    }
    if (input.helper.generation.kind === "returned") {
      const center = input.helper.neighbors.find(neighbor => neighbor.offset === 0);
      assert.deepEqual(center.hotp, input.helper.generation);
    }
    for (const neighbor of input.helper.neighbors) {
      if (neighbor.hotp.kind !== "returned") continue;
      assert.match(neighbor.token, /^\d{6}$/);
      if (neighbor.verification.kind === "returned") {
        assert.equal(typeof neighbor.verification.value, "boolean");
        if (Math.abs(neighbor.offset) <= 1) assert.equal(neighbor.verification.value, true);
      }
    }
    for (const neighbor of input.helper.bigintNeighbors) {
      assert.equal(neighbor.hotp.kind, "returned", JSON.stringify(neighbor.hotp));
      assert.match(neighbor.token, /^\d{6}$/);
      assert.deepEqual(neighbor.verification, { kind: "returned", value: false });
    }
    if (input.helper.malformed.verification.kind === "returned") {
      assert.equal(input.helper.malformed.verification.value, false);
    }
  }
  return { version, utilsVersion, secret, issuer, account, scope: {
    counter: "Record Number division, floor, addition, and negative zero before the upstream HOTP conversion",
    generation: "Capture the complete native generateTOTP and helper totp outcomes",
    verification: "Capture each HOTP token at offsets -2 through 2 and the malformed token with the default verification window",
    bigintNeighbors: "Capture exact integer tokens that Number addition cannot produce at the 2^53 and 2^64 boundaries",
    unavailableToken: "Record verification as not-run when HOTP generation throws; still execute malformed-token verification",
  }, cases };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the TOTP counter fixture output path");
  const diagnostics = [];
  try {
    writeFileSync(output, `${JSON.stringify(await captureTotpCounter({ diagnostics }), null, 2)}\n`);
  } catch (error) {
    diagnostics.push({ stage: "capture-error", error: { ...errorObservation(error), stack: error.stack } });
    throw error;
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
