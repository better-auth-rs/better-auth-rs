import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureAccountVerificationSerialPrimary } from "./account-verification-serial-primary-capture.mjs";

test("Memory Account and Verification Serial creation and lifecycle match the captured contract", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/account-verification-serial-primary-1.7.6.json", import.meta.url), "utf8"));
  const actual = await captureAccountVerificationSerialPrimary();
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(14);
}, 30_000);
