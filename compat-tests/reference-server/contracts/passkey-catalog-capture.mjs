import { withRestoredSchema } from "./schema-isolation.mjs";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { getMigrations } from "better-auth/db/migration";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

async function captureSqlite(tableName, configuration) {
  const database = new Database(":memory:");
  try {
    const options = {
      database, baseURL: "http://catalog.example.test",
      secret: "ordinary-server-catalog-secret-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      ...configuration,
    };
    const initial = await getMigrations(options);
    const initialSql = await initial.compileMigrations();
    await initial.runMigrations();
    const observed = observeSqliteCatalog(database, tableName, "The generated Passkey table exists in the SQLite catalog");
    const repeated = await getMigrations(options);
    assert.equal(repeated.toBeCreated.length, 0);
    assert.equal(repeated.toBeAdded.length, 0);
    assert.equal(repeated.toBeAddedIndexes.length, 0);
    assert.equal(repeated.schemaProblems.length, 0);
    return { ...observed, migration: { initialSql, repeatedSql: await repeated.compileMigrations() } };
  } finally {
    database.close();
  }
}

export async function capturePasskeyCatalog(backend) {
  return withRestoredSchema(passkey().schema, async () => {
    assert.ok(["sqlite", "postgres", "mysql"].includes(backend), "Select sqlite, postgres or mysql");
    const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
    const pluginVersion = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/passkey/package.json", import.meta.url), "utf8")).version;
    assert.equal(version, "1.7.6");
    assert.equal(pluginVersion, version);
    const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/passkey-catalog-config.json", import.meta.url), "utf8"));
    const cases = [];
    for (const name of backend === "sqlite" ? ["default", "legacy", "custom"] : ["default", "custom"]) {
      const configuration = configurations[name];
      const tableName = configuration.passkey?.modelName || "passkey";
      const options = { plugins: [configuration.passkey === undefined
        ? passkey() : passkey({ schema: configuration })] };
      const observed = backend === "sqlite"
        ? await captureSqlite(tableName, options)
        : await captureFreshServerCatalog(backend, [tableName], options,
          context => observeServerIndexes(context, tableName));
      cases.push({ name, configuration, ...observed });
    }
    return { version, database: backend, cases };
  });
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, `${JSON.stringify(await capturePasskeyCatalog(backend), null, 2)}\n`);
}
