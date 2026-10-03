import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/user-account-catalog-1.7.6.json";
import { captureUserAccountCatalog } from "./user-account-catalog";

test("Generated SQLite User and Account catalogs preserve complete physical metadata", async () => {
  expect(await captureUserAccountCatalog()).toStrictEqual(expected);
});
