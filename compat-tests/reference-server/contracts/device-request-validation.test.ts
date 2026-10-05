import { expect, test } from "bun:test";
import { captureDeviceRequestValidation } from "./device-request-validation-capture.mjs";

test("Device display fields preserve sync endpoint behavior and explicit async schema results", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/device-request-validation-1.7.6.json", import.meta.url)).json();
  expect(await captureDeviceRequestValidation()).toStrictEqual(expected);
});
