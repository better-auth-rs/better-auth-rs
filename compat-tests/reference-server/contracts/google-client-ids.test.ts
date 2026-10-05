import { expect, test } from "bun:test";
import { captureGoogleClientIds } from "./google-client-ids-capture.mjs";

test("Google multiple client IDs match the captured ordinary contracts", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/google-client-ids-1.7.6.json", import.meta.url)).json();
  expect(await captureGoogleClientIds()).toStrictEqual(expected);
});
