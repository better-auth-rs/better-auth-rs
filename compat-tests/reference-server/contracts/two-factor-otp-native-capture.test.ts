import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("TwoFactor OTP retains native split calls, decimal counter coercion and consumed records", async () => {
  await expectStandaloneObservation(
    new URL("./two-factor-otp-native-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/two-factor-otp-native-1.7.6.json", import.meta.url),
    "two-factor-otp-native",
  );
}, 120_000);
