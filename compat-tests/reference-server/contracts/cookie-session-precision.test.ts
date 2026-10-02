import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/cookie-session-precision-1.7.6.json";
import { captureCookieSessionPrecision } from "./cookie-session-precision.mjs";

test("ordinary fractional session lifetimes reach the HTTP cookie writer unchanged", async () => {
  expect(await captureCookieSessionPrecision()).toEqual(expected);
});
