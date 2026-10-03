import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/user-sort-field-1.7.6.json";
import { captureUserSortField } from "./user-sort-field";

test("User sort declarations preserve Memory comparison timing and SQLite query preparation", async () => {
  expect(await captureUserSortField()).toStrictEqual(expected);
});
