import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/verification-catalog-1.7.6.json";
import { captureVerificationCatalog } from "./verification-catalog";

test("Generated SQLite Verification catalogs preserve complete physical metadata", async () => {
  expect(await captureVerificationCatalog()).toStrictEqual(expected);
});
