import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { createProtectedFunctionHarness, observeProtectedFunction, protectedFunctionScenarios, protectedFunctionTables } from "./protected-function-shared.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/memory-adapter", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

export async function captureProtectedFunction(backend) {
  assert.ok(["memory", "sqlite"].includes(backend));
  const cases = [];
  for (const scenario of protectedFunctionScenarios) {
    const harness = createProtectedFunctionHarness(scenario);
    if (backend === "memory") {
      const memory = Object.fromEntries(protectedFunctionTables.map(table => [table, []]));
      const options = { ...harness.options, database: memoryAdapter(memory) };
      const observation = await observeProtectedFunction({ options, backend, readStorage: async () => memory }, scenario, harness);
      cases.push({ name: scenario.name, observation });
      continue;
    }
    const database = new Database(":memory:");
    try {
      const options = { ...harness.options, database };
      const migration = await getMigrations(options);
      const initialSql = await migration.compileMigrations();
      await migration.runMigrations();
      const columns = Object.fromEntries(protectedFunctionTables.map(table => [table, database.query(`PRAGMA table_info("${table}")`).all()]));
      const observation = await observeProtectedFunction({
        options, backend, query: async (sql, values) => database.query(sql).all(...values),
      }, scenario, harness);
      cases.push({ name: scenario.name, columns, migration: { initialSql }, observation });
    } finally {
      database.close();
    }
  }
  return { version, backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass memory or sqlite and a fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureProtectedFunction(backend), null, 2)}\n`);
}
