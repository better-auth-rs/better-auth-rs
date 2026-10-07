import { expect, test } from "bun:test";
import { captureEmailVerificationPayload } from "./email-verification-payload-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/email-verification-payload-1.7.6.json", import.meta.url)).text();

test("email verification payload retains complete error and storage observations", async () => {
  expect(`${JSON.stringify(await captureEmailVerificationPayload(), null, 2)}\n`).toBe(fixture);
}, 60_000);
