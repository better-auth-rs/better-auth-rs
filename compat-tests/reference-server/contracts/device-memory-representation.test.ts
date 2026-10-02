import { expect, test } from "bun:test";
import { captureDeviceMemoryRepresentation } from "./device-memory-representation";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-memory-representation-1.7.6.json", import.meta.url)).json();
const captured = await captureDeviceMemoryRepresentation();

test("Memory Device display fields preserve pinned storage and callback representations", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.cases).toHaveLength(2);
  expect(captured).toStrictEqual(fixture);
});
