import { expect, test } from "bun:test";
import { captureOpenApiModelPresence } from "./openapi-model-presence";

const expected = await Bun.file(new URL("../../../tests/fixtures/openapi-model-presence-1.7.6.json", import.meta.url)).json();
const captured = await captureOpenApiModelPresence();

test("runtime model declarations preserve empty components and plugin order", () => {
  expect(captured).toStrictEqual(expected);
});
