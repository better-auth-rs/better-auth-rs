import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { organization } from "better-auth/plugins";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

export async function captureMemberServerCatalog(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/member-organization-role-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of ["default", "custom"]) {
    const source = configurations[name];
    const configuration = Object.fromEntries(["user", "organization", "member"]
      .filter(key => source[key] !== undefined).map(key => [key, source[key]]));
    const { user, ...schema } = configuration;
    const tableName = configuration.member?.modelName || "member";
    const observation = await captureFreshServerCatalog(backend, [tableName], {
      ...(user === undefined ? {} : { user }),
      plugins: [organization({ schema })],
    });
    cases.push({ name, configuration, ...observation });
  }
  return { version, database: backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureMemberServerCatalog(backend), null, 2) + "\n");
}
