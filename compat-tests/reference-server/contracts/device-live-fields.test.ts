import { expect, test } from "bun:test";
import { captureDeviceLiveFields } from "./device-live-fields";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-live-fields-1.7.6.json", import.meta.url)).json();

test("Device point reads preserve the pinned display-field observation stage", async () => {
  expect(await captureDeviceLiveFields()).toStrictEqual(fixture);
});
