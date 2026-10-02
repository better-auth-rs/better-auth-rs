import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/native-core-join-limits-1.7.6.json";
import { captureLimits } from "../../../tests/fixtures/native-core-join-limits.capture.mjs";

test("ordinary native and fallback child caps preserve numeric configuration", async () => {
  expect(await captureLimits()).toEqual(fixture);
});
