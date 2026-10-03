import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/sqlite-json-generation-1.7.6.json";
import { captureSqliteJsonGeneration } from "./sqlite-json-generation";

test("SQLite JSON display fields preserve scalar bindings and exact stored text", async () => {
  expect(await captureSqliteJsonGeneration()).toStrictEqual(expected);
});
