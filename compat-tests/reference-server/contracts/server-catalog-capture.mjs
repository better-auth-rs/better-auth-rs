import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

export async function captureServerCatalog(backend) {
  assert.ok(backend === "postgres" || backend === "mysql", "Select postgres or mysql");
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const observation = await captureFreshServerCatalog(backend, ["user", "account"]);
  return { version, database: backend, ...observation };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureServerCatalog(backend), null, 2) + "\n");
}
