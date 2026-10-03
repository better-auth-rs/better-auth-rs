import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/native-empty-field-mapping-1.7.6.json";
import { captureNativeEmptyFieldMapping } from "./native-empty-field-mapping";

test("Empty native field mappings retain resolved defaults and raw declarations", async () => {
  expect(await captureNativeEmptyFieldMapping()).toStrictEqual(expected);
});
