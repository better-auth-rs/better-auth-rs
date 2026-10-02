import { expect, test } from "bun:test";
import { captureFieldJsonText } from "./field-json-text";

const fixture = await Bun.file(new URL("../../../tests/fixtures/field-json-text-1.7.6.json", import.meta.url)).json();
const captured = await captureFieldJsonText();

test("declared display JSON preserves pinned storage and callback text", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.cases).toHaveLength(2);
  expect(captured).toStrictEqual(fixture);
});
