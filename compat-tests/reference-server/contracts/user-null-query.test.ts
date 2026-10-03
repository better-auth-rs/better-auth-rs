import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/user-null-query-1.7.6.json";
import { captureUserNullQuery } from "./user-null-query";

test("ordinary nullable display queries retain presence and original schema errors", async () => {
  expect(await captureUserNullQuery()).toStrictEqual(expected);
});
