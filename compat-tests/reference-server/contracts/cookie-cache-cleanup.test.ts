import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/cookie-cache-cleanup-1.7.6.json";
import { captureCookieCacheCleanup } from "../../../tests/fixtures/cookie-cache-cleanup.capture.mjs";

test("direct ordinary cache cleanup actions preserve ordered complete headers", async () => {
  expect(await captureCookieCacheCleanup()).toStrictEqual(expected);
});
