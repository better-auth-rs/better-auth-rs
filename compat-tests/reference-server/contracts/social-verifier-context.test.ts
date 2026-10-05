import { expect, test } from "bun:test";
import { captureSocialVerifierContext } from "./social-verifier-context-capture.mjs";

test("Social custom verifiers retain ordinary request metadata while using real signature verification", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/social-verifier-context-1.7.6.json", import.meta.url)).json();
  expect(await captureSocialVerifierContext()).toStrictEqual(expected);
});
