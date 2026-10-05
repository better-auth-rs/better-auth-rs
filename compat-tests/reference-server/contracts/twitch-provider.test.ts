import { expect, test } from "bun:test";
import { captureTwitch } from "./twitch-provider-capture.mjs";

test("Twitch ordinary contracts match the fresh pinned fixture", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/social-twitch-1.7.6.json", import.meta.url)).json();
  const actual = JSON.parse(JSON.stringify(await captureTwitch()));
  expect(actual).toStrictEqual(expected);
});
