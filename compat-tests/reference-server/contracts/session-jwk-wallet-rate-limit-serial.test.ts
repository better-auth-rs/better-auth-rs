import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureSessionJwkWalletRateLimitSerial } from "./session-jwk-wallet-rate-limit-serial-capture.mjs";

test("Memory Session, Jwk, WalletAddress, and RateLimit Serial IDs match the captured contract", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/session-jwk-wallet-rate-limit-serial-1.7.6.json", import.meta.url), "utf8"));
  const actual = await captureSessionJwkWalletRateLimitSerial();
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(53);
  const negativeZero = actual.cases.find(entry => entry.operation === "id-update" && entry.name === "negative-zero");
  expect(negativeZero?.input.id).toStrictEqual({ type: "number", value: "-0" });
  expect(negativeZero?.events.find(event => event[0] === "update-before")?.[1].id).toStrictEqual({ type: "number", value: "-0" });
  const zero = actual.cases.find(entry => entry.operation === "id-update" && entry.name === "zero");
  expect(zero?.input.id).toBe(0);
}, 30_000);
