import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createProtectedFunctionHarness } from "./protected-function-shared.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

const inputs = [
  { name: "missing", data: () => ({}) },
  { name: "own-undefined", data: () => ({ protectedValue: undefined }) },
  { name: "null", data: () => ({ protectedValue: null }) },
  { name: "false", data: () => ({ protectedValue: false }) },
  { name: "zero", data: () => ({ protectedValue: 0 }) },
  { name: "empty-string", data: () => ({ protectedValue: "" }) },
  { name: "truthy", data: () => ({ protectedValue: "submitted" }) },
  { name: "inherited", data: () => Object.create({ protectedValue: "inherited" }) },
];

export function captureProtectedFunctionInput() {
  const cases = [];
  for (const result of ["string", "undefined", "throws", "function"]) {
    const harness = createProtectedFunctionHarness({ name: `parser-${result}`, result });
    const operations = [];
    for (const action of ["create", "update"]) {
      for (const sample of inputs) {
        const data = sample.data();
        const before = { ...harness.counts };
        const present = "protectedValue" in data;
        let value;
        let outcome;
        try {
          value = harness.parse(action, data);
          outcome = {
            returned: true, result: harness.observe(value), ownKeys: Object.keys(value),
            nullPrototype: Object.getPrototypeOf(value) === null,
            ownsField: Object.hasOwn(value, "protectedValue"), sameDefault: value.protectedValue === harness.defaultFunction,
            sameReturned: value.protectedValue === harness.returnedFunction,
          };
        } catch (caught) {
          outcome = { returned: false, error: harness.error(caught) };
        }
        const calls = harness.counts.factory - before.factory;
        assert.equal(calls, action === "create" && !present ? 1 : 0);
        assert.equal(harness.counts.validator - before.validator, 0);
        assert.equal(harness.counts.input - before.input, 0);
        if (action === "create" && present) {
          assert.equal(outcome.returned, true);
          assert.equal(value.protectedValue, harness.defaultFunction);
          assert.equal(Object.hasOwn(value, "protectedValue"), true);
        } else if (action === "update" && present && data.protectedValue) {
          assert.equal(outcome.returned, false);
        } else if (action === "create" && !present && result === "throws") {
          assert.equal(outcome.returned, false);
        } else {
          assert.equal(outcome.returned, true);
          assert.equal(Object.hasOwn(value, "protectedValue"), action === "create");
        }
        if (outcome.returned) assert.equal(outcome.nullPrototype, true);
        operations.push({
          action, input: sample.name, data: harness.observe(data), inputOwnKeys: Object.keys(data),
          inputHasOwn: Object.hasOwn(data, "protectedValue"), inputHasField: present,
          inheritedValue: present && !Object.hasOwn(data, "protectedValue") ? harness.observe(data.protectedValue) : null,
          ...outcome, ...harness.snapshot(),
        });
      }
    }
    cases.push({ result, operations, functions: harness.functions });
  }
  return { version, cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass a fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(captureProtectedFunctionInput(), null, 2)}\n`);
}
