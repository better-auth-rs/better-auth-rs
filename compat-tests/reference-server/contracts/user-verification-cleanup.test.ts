import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("62 Email OTP and Magic Link cleanup cases preserve complete callbacks, errors, storage and proof replay", async () => {
  await expectStandaloneCapture(
    new URL("./user-verification-cleanup-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/user-verification-cleanup-1.7.6.json", import.meta.url),
  );
}, 60_000);
