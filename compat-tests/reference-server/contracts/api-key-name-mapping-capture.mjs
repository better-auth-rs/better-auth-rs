import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import {
  captureApiKeyFieldFailure, captureApiKeyFieldOperations, failureOperations,
} from "./api-key-fields-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
export const nameMappings = ["default", "empty", "renamed"];

export async function captureApiKeyNameMapping() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const cases = [];
    for (const mapping of nameMappings) {
      const operations = await captureApiKeyFieldOperations(backend, mapping);
      const failures = [];
      for (const operation of failureOperations) {
        for (const phase of operation === "decrement" ? ["output"] : ["input", "output"]) {
          failures.push(await captureApiKeyFieldFailure(backend, operation, phase, mapping));
        }
      }
      cases.push({ mapping, operations, failures });
    }
    backends.push({ backend, cases });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureApiKeyNameMapping(), null, 2)}\n`);
}
