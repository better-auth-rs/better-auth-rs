import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureGenericProfileResults } from "./generic-profile-results-capture.mjs";

test("Generic null profiles and application errors retain pinned helper and callback behavior", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/generic-profile-results-1.7.6.json", import.meta.url), "utf8"));
  expect(await captureGenericProfileResults()).toEqual(fixture);
});
