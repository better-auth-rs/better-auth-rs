import { expect, test } from "bun:test";
import { captureEmailVerificationClaims } from "./email-verification-claims-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/email-verification-claims-1.7.6.json", import.meta.url)).text();

test("email verification claims retain complete JWT, HTTP, callback, and storage observations", async () => {
  expect(`${JSON.stringify(await captureEmailVerificationClaims(), null, 2)}\n`).toBe(fixture);
}, 60_000);
