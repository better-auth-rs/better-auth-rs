import { expect, test } from "bun:test";
import { captureApiKeyNumberName } from "./api-key-number-name-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-number-name-1.7.6.json", import.meta.url)).json();

test("Number name defaults and optional null preserve the complete API Key contract", async () => {
  expect(await captureApiKeyNumberName()).toStrictEqual(fixture);
}, 60_000);
