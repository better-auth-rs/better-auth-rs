import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/sql-user-extra-output-1.7.6.json";
import { captureSqlUserExtraOutput } from "./sql-user-extra-output";

test("SQLite display output preserves column presence and decodes after callbacks", async () => {
  expect(await captureSqlUserExtraOutput()).toStrictEqual(expected);
});
