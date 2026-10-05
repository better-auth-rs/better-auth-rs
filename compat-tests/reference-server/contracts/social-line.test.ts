import { expect, test } from "bun:test";
import { captureSocialLine } from "./social-line-capture.mjs";

test("Social LINE ordinary contracts match the fresh pinned fixture", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/social-line-1.7.6.json", import.meta.url)).json();
  const actual = JSON.parse(JSON.stringify(await captureSocialLine()));
  expect(actual).toStrictEqual(expected);
});
