import { expect, test } from "bun:test";
import { captureMemoryRecordRepresentation } from "./memory-record-representation";

const expected = await Bun.file(new URL("../../../tests/fixtures/memory-record-representation-1.7.6.json", import.meta.url)).json();
const captured = await captureMemoryRecordRepresentation();

test("Account and Verification display fields preserve Memory storage and callback representations", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.cases).toHaveLength(6);
  expect(captured).toStrictEqual(expected);
});
