import { expect, test } from "bun:test";
import { captureOpenApiEndpointKeyOrder } from "./openapi-endpoint-key-order-capture.mjs";

test("endpoint keys preserve complete operations, path order, and duplicate operation IDs", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/openapi-endpoint-key-order-1.7.6.json", import.meta.url)).json();
  expect(await captureOpenApiEndpointKeyOrder()).toStrictEqual(expected);
});
