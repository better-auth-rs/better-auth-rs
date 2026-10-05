import { expect, test } from "bun:test";
import { captureTikTok } from "./tiktok-capture.mjs";

test("TikTok ordinary authorization, grants and profiles match pinned capture", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/tiktok-1.7.6.json", import.meta.url)).json();
  const actual = JSON.parse(JSON.stringify(await captureTikTok()));
  expect(actual).toStrictEqual(expected);
});
