import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

export async function captureVerificationServerCatalog(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/verification-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of ["default", "legacy"]) {
    const configuration = configurations[name];
    const tableName = configuration.verification?.modelName || "verification";
    const observation = await captureFreshServerCatalog(backend, [tableName], configuration);
    cases.push({ name, configuration, ...observation });
  }
  return { version, database: backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureVerificationServerCatalog(backend), null, 2) + "\n");
}
