import { expect, test } from "bun:test";
import { captureApiKeyNumberNameOrder } from "./api-key-number-name-order-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-number-name-order-1.7.6.json", import.meta.url)).json();

test("Unequal Number names and null preserve complete API Key ordering and HTTP input rejection", async () => {
  expect(await captureApiKeyNumberNameOrder()).toStrictEqual(fixture);
}, 60_000);
