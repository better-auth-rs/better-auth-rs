import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { jwt } from "better-auth/plugins";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";
import { withRestoredSchema } from "./schema-isolation.mjs";

export async function captureJwkServerCatalog(backend) {
  return withRestoredSchema(jwt().schema, async () => {
    const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
    assert.equal(version, "1.7.6");
    const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/jwk-rate-limit-catalog-config.json", import.meta.url), "utf8"));
    const cases = [];
    for (const name of ["default", "custom"]) {
      const jwks = configurations[name].jwks;
      const configuration = jwks === undefined ? {} : { jwks };
      const tableName = jwks?.modelName || "jwks";
      const observation = await captureFreshServerCatalog(backend, [tableName], {
        plugins: [jwks === undefined ? jwt() : jwt({ schema: { jwks } })],
      });
      cases.push({ name, configuration, ...observation });
    }
    return { version, database: backend, cases };
  });
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureJwkServerCatalog(backend), null, 2) + "\n");
}
