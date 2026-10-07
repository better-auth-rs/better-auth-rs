import { expect, test } from "bun:test";
import { captureMemoryTransactionValues } from "./memory-transaction-values-capture.mjs";

test("Memory transaction copies preserve aliases and use complete JSON change detection", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/memory-transaction-values-1.7.6.json", import.meta.url)).json();
  const observed = await captureMemoryTransactionValues();
  expect(observed.version).toBe("1.7.6");
  expect(observed.cases).toHaveLength(11);
  expect(observed).toStrictEqual(fixture);
});
