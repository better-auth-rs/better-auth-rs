import { expect, test } from "bun:test";
import { captureDeviceRequestSchema } from "./device-request-schema-capture.mjs";

test("Device request schemas match complete serialized operations and property order", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/device-request-schema-1.7.6.json", import.meta.url)).json();
  expect(await captureDeviceRequestSchema()).toStrictEqual(expected);
});
