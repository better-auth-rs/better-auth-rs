import { expect, test } from "bun:test";
import { captureMemorySort, memorySortCases, memorySortOperations, memorySortProvenance } from "./memory-sort-capture.mjs";

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

test("Memory sort pairing uses the captured Bun, WebKit, ICU, Unicode and default collation", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/memory-sort-provenance-1.7.6.json", import.meta.url)).json();
  const observed = memorySortProvenance();
  expect(observed.version).toBe(expected.version);
  expect(observed.collator).toStrictEqual(expected.collator);
  expect(observed.runtime.bun).toBe(expected.runtime.bun);
  for (const library of ["webkit", "icu", "unicode"] as const) {
    expect(observed.runtime.versions[library]).toBe(expected.runtime.versions[library]);
  }
});
