import { expect, test } from "bun:test";
import { captureSocialRefreshContext } from "./social-refresh-context-capture.mjs";

test("Social refresh callbacks retain HTTP, native, and absent request context", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/social-refresh-context-1.7.6.json", import.meta.url)).json();
  expect(await captureSocialRefreshContext()).toStrictEqual(expected);
});
