import { expect, test } from "bun:test";
import { captureOAuthProfileOverride } from "./oauth-profile-override-capture.mjs";

test("only the normal callback applies the provider profile override option", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/oauth-profile-override-1.7.6.json", import.meta.url)).json();
  expect(await captureOAuthProfileOverride()).toStrictEqual(expected);
});
