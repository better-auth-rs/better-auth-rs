import { expect, test } from "bun:test";
import { captureDeviceAdditionalFields } from "./device-additional-fields";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-additional-fields-1.7.6.json", import.meta.url)).json();
const captured = await captureDeviceAdditionalFields();

test("Device additional fields use the pinned 1.7.6 adapter contract", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured).toEqual(fixture);
  expect(captured.serialReference.outputInputs).toEqual([2, 2]);
  expect(captured.serialReference.created).toBe("2");
});
