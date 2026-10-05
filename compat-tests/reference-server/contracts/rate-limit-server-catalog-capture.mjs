import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

export async function captureRateLimitServerCatalog(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/jwk-rate-limit-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of ["default", "custom"]) {
    const rateLimit = configurations[name].rateLimit;
    const configuration = rateLimit === undefined ? {} : { rateLimit };
    const tableName = rateLimit?.modelName || "rateLimit";
    const observation = await captureFreshServerCatalog(backend, [tableName], {
      rateLimit: { storage: "database", ...rateLimit },
    });
    cases.push({ name, configuration, ...observation });
  }
  return { version, database: backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureRateLimitServerCatalog(backend), null, 2) + "\n");
}
