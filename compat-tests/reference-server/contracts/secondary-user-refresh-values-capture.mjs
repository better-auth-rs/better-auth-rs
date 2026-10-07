import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureSecondaryUserRefreshCases } from "./secondary-user-refresh-capture.mjs";

export const secondaryUserRefreshValueScenarios = [
  { name: "numeric-cached-expires-at", transaction: false, numericExpiry: true, refreshSuccess: true },
  { name: "non-array-active-index", transaction: false, nonArrayIndex: true },
  { name: "mixed-active-index", transaction: false, mixedIndex: true, refreshSuccess: true },
];

export async function captureSecondaryUserRefreshValues() {
  const captured = await captureSecondaryUserRefreshCases(secondaryUserRefreshValueScenarios);
  assert.equal(captured.cases.length, 6);
  return captured;
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureSecondaryUserRefreshValues(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
