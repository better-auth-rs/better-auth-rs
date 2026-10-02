import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/device-issuance-1.7.6.json";
import { captureDeviceIssuance } from "../../../tests/fixtures/device-issuance.capture.mjs";

test("ordinary Device issuance preserves code shape and verification URI parameters", async () => {
  expect(await captureDeviceIssuance()).toStrictEqual(expected);
});
