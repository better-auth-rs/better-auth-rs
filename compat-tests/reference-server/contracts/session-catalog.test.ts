import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/session-catalog-1.7.6.json";
import { captureSessionCatalog } from "./session-catalog";

test("Generated SQLite Session catalogs preserve complete physical metadata", async () => {
  expect(await captureSessionCatalog()).toStrictEqual(expected);
});
