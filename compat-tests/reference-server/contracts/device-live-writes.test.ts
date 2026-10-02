import { expect, test } from "bun:test";
import { captureDeviceLiveWrites } from "./device-live-writes";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-live-writes-1.7.6.json", import.meta.url)).json();

test("Device create and update preserve the pinned display-field observation stage", async () => {
  expect(await captureDeviceLiveWrites()).toStrictEqual(fixture);
});
