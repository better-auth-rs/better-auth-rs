import { expect, test } from "bun:test";
import { captureSocialMicrosoft } from "./social-microsoft-capture.mjs";

test("Social Microsoft ordinary contracts match the fresh pinned fixture", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/social-microsoft-1.7.6.json", import.meta.url)).json();
  expect(await captureSocialMicrosoft()).toStrictEqual(expected);
});
