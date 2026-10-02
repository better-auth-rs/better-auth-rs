import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/account-lockout-clock-1.7.6.json";
import { captureAccountLockoutClock } from "../../../tests/fixtures/account-lockout-clock.capture.mjs";

test("AccountLockout reads its deadline clock after the threshold increment", async () => {
  expect(await captureAccountLockoutClock()).toStrictEqual(fixture);
});
