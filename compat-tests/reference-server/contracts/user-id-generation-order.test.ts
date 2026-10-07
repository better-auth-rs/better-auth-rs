import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureUserIdGenerationOrder } from "./user-id-generation-order-capture.mjs";

test("User ID generation retains field order, original errors, and complete storage", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/user-id-generation-order-1.7.6.json", import.meta.url), "utf8"));
  const actual = JSON.parse(JSON.stringify(await captureUserIdGenerationOrder(), (_, value) => value === undefined ? { $undefined: true } : value));
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(24);
}, 30_000);
