import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureApple } from "./apple-capture.mjs";

test("Apple ordinary authorization, grants, signed profiles and successful routes match the pinned contract", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/social-apple-1.7.6.json", import.meta.url), "utf8"));
  expect(await captureApple()).toEqual(fixture);
});
