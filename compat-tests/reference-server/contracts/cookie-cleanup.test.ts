import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/cookie-cleanup-1.7.6.json";
import { captureCookieCleanup } from "../../../tests/fixtures/cookie-cleanup.capture.mjs";

test("ordinary aggregate cleanup preserves ordered headers and existing entry duplicates", async () => {
  expect(await captureCookieCleanup()).toStrictEqual(expected);
});
