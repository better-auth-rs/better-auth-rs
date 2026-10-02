import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/memory-serial-references-1.7.6.json";
import { captureMemorySerialReferences } from "./memory-serial-references";

test("Memory applies Serial reference conversion after field policies", async () => {
  expect(await captureMemorySerialReferences()).toStrictEqual(expected);
});
