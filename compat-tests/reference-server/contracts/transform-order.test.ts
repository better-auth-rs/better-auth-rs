import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/transform-order-upstream.json";
import { observeTransformOrder } from "../transform-order-oracle";

test("normal core lists preserve output callback order and values in Memory and SQLite", async () => {
  expect(await observeTransformOrder()).toStrictEqual(expected);
});
