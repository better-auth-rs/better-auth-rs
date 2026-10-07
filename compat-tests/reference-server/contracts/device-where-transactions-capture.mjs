import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureDeviceWhereTransactions } from "./device-where-capture.mjs";

export { captureDeviceWhereTransactions } from "./device-where-capture.mjs";

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceWhereTransactions(backend), null, 2)}\n`);
}
