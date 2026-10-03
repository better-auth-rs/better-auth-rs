import { expect, test } from "bun:test";
import { captureUserScalarColumnQuery } from "./user-scalar-column-query";

const expected = await Bun.file(new URL("../../../tests/fixtures/user-scalar-column-query-1.7.6.json", import.meta.url)).json();
const captured = await captureUserScalarColumnQuery();

test("User scalar column queries retain complete display values and independent counts", () => {
  expect(captured).toStrictEqual(expected);
});
