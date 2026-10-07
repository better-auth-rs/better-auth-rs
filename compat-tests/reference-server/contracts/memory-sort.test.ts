import { expect, test } from "bun:test";
import { captureMemorySort, memorySortCases, memorySortOperations } from "./memory-sort-capture.mjs";

test("Memory name sorting preserves native comparison branches, stored JSON values, stable ties and pagination", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/memory-sort-1.7.6.json", import.meta.url)).json();
  const observed = await captureMemorySort();
  expect(observed.cases.map((scenario: { name: string }) => scenario.name)).toStrictEqual(memorySortCases.map(scenario => scenario.name));
  for (const scenario of observed.cases) {
    expect(scenario.operations.map((operation: { name: string }) => operation.name)).toStrictEqual(memorySortOperations);
  }
  // The fixture records the capture runtime's default collation; no portable locale is assumed.
  expect(observed).toStrictEqual(fixture);
}, 60_000);
