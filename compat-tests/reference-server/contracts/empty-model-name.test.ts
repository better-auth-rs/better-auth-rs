import { expect, test } from "bun:test";
import { captureEmptyModelName } from "./empty-model-name";

const fixture = await Bun.file(new URL("../../../tests/fixtures/empty-model-name-1.7.6.json", import.meta.url)).json();

test("Empty model names resolve to each upstream schema's omitted-name default", async () => {
  expect(await captureEmptyModelName()).toStrictEqual(fixture);
});
