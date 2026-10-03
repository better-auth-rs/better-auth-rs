import { expect, test } from "bun:test";
import { captureOpenApiModelKeyOrder } from "./openapi-model-key-order";

const expected = await Bun.file(new URL("../../../tests/fixtures/openapi-model-key-order-1.7.6.json", import.meta.url)).json();
const captured = await captureOpenApiModelKeyOrder();

test("native component model keys retain JavaScript enumeration order", () => {
  expect(captured).toStrictEqual(expected);
});
