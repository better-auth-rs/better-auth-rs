import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

function configuredOptions(configuration) {
  if (configuration.twoFactor === undefined) return { plugins: [twoFactor()] };
  const { twoFactorEnabled, ...userFields } = configuration.user.fields;
  return {
    user: { modelName: configuration.user.modelName, fields: userFields },
    plugins: [twoFactor({ schema: {
      user: { fields: { twoFactorEnabled } },
      twoFactor: configuration.twoFactor,
    } })],
  };
}

async function captureSqlite(tableNames, configuration) {
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
    const catalog = {};
    const ddl = {};
    for (const [model, tableName] of Object.entries(tableNames)) {
      const observed = observeSqliteCatalog(database, tableName, `The generated ${model} table exists in the SQLite catalog`);
      catalog[model] = observed.catalog;
      ddl[model] = observed.ddl;
    }
    const repeated = await getMigrations(options);
    assert.equal(repeated.toBeCreated.length, 0);
    assert.equal(repeated.toBeAdded.length, 0);
    assert.equal(repeated.toBeAddedIndexes.length, 0);
    assert.equal(repeated.schemaProblems.length, 0);
    return { catalog, ddl, migration: { initialSql, repeatedSql: await repeated.compileMigrations() } };
  } finally {
    database.close();
  }
}

export async function captureTwoFactorCatalog(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend), "Select sqlite, postgres or mysql");
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/two-factor-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of backend === "sqlite" ? ["default", "legacy", "custom"] : ["default", "custom"]) {
    const configuration = configurations[name];
    const tableNames = {
      user: configuration.user?.modelName || "user",
      twoFactor: configuration.twoFactor?.modelName || "twoFactor",
    };
    const options = configuredOptions(configuration);
    const observed = backend === "sqlite"
      ? await captureSqlite(tableNames, options)
      : await captureFreshServerCatalog(backend, Object.values(tableNames), options, async context => {
        const observation = {};
        for (const [model, tableName] of Object.entries(tableNames)) {
          observation[model] = await observeServerIndexes(context, tableName);
        }
        return observation;
      });
    cases.push({ name, configuration, ...observed });
  }
  return { version, database: backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, `${JSON.stringify(await captureTwoFactorCatalog(backend), null, 2)}\n`);
}
