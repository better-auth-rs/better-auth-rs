import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/device-interval-1.7.6.json";
import { captureDeviceInterval } from "../../../tests/fixtures/device-interval.capture.mjs";

test("ordinary unconsumed device issuance retains fractional interval metadata", async () => {
  expect(await captureDeviceInterval()).toStrictEqual(expected);
});
