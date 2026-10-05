import { expect, test } from "bun:test";
import { captureDeviceGrantMetadata } from "./device-grant-metadata-capture.mjs";

test("Device grant JSON metadata preserves complete operations, merge precedence, and key order", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/device-grant-metadata-1.7.6.json", import.meta.url)).json();
  const document = JSON.parse(JSON.stringify(await captureDeviceGrantMetadata()));
  expect(document).toStrictEqual(expected);
});
