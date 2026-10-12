import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("TwoFactor OTP preserves decimal rounding, integer prefixes and complete failure persistence", async () => {
  await expectStandaloneObservation(
    new URL("./two-factor-otp-counter-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/two-factor-otp-counter-1.7.6.json", import.meta.url),
    "two-factor-otp-counter",
  );
}, 120_000);
