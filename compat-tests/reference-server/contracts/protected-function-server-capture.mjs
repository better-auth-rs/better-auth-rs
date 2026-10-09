import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import {
  createProtectedFunctionHarness,
  observeProtectedFunction,
  protectedFunctionScenarios,
  protectedFunctionTables,
} from "./protected-function-shared.mjs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

export async function captureProtectedFunctionServer(backend) {
  assert.ok(backend === "postgres" || backend === "mysql", "Select postgres or mysql");
  const cases = [];
  for (const scenario of protectedFunctionScenarios) {
    const harness = createProtectedFunctionHarness(scenario);
    const captured = await captureFreshServerCatalog(
      backend,
      protectedFunctionTables,
      harness.options,
      context => observeProtectedFunction(context, scenario, harness),
    );
    cases.push({ name: scenario.name, ...captured });
  }
  return { version, backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureProtectedFunctionServer(backend), null, 2)}\n`);
}
