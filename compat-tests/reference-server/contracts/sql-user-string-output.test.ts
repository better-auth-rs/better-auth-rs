import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/sql-user-string-output-1.7.6.json";
import { captureSqlUserStringOutput } from "./sql-user-string-output";

test("SQL display String output retains null and empty values through point and batch reads", async () => {
  expect(await captureSqlUserStringOutput()).toStrictEqual(expected);
});
