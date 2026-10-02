import { expect, test } from "bun:test";
import { captureEmptyFieldName } from "./empty-field-name";

const fixture = await Bun.file(new URL("../../../tests/fixtures/empty-field-name-1.7.6.json", import.meta.url)).json();

test("Empty and omitted display aliases share storage and schema columns", async () => {
  expect(await captureEmptyFieldName()).toStrictEqual(fixture);
});
