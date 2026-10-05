import { expect, test } from "bun:test";
import { captureDeviceGrant } from "./device-grant-capture.mjs";

test("Device grant authorization and fallback preserve ordinary HTTP and native lifecycles", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/device-grant-1.7.6.json", import.meta.url)).json();
  expect(await captureDeviceGrant()).toStrictEqual(expected);
});
