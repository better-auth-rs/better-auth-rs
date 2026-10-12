import { writeFileSync } from "node:fs";
import { captureTwoFactorOtpNative } from "./two-factor-otp-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

export const twoFactorOtpCounterCases = [
  ["negative-rounded-integer", "-544157599796692941"],
  ["negative-leading-zeroes", "  -000544157599796692941tail"],
  ["explicit-decimal-hex-prefix", "-0x10"],
  ["explicit-decimal-exponent-prefix", "-12e4"],
].map(([name, counterText]) => ({ name, counterText, consumer: "two-factor-otp", value: "methods" }));

export async function captureTwoFactorOtpCounter() {
  return { contract: "two-factor-otp-counter", ...await captureTwoFactorOtpNative(twoFactorOtpCounterCases) };
}

if (import.meta.main) {
  const output = `${JSON.stringify(await captureTwoFactorOtpCounter(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], output);
  await writeObservation(output);
}
