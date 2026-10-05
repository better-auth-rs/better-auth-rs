import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization } from "better-auth/plugins";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

async function observeServerIndexes({ query, backend }, tableName) {
  const indexSql = backend === "postgres"
    ? `SELECT t.relname AS "table", i.relname AS "name",
      CASE WHEN x.indisunique THEN 'YES' ELSE 'NO' END AS "unique",
      CAST(k.position AS text) AS "position", a.attname AS "column"
      FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace
      JOIN pg_index x ON x.indrelid = t.oid JOIN pg_class i ON i.oid = x.indexrelid
      JOIN LATERAL unnest(x.indkey) WITH ORDINALITY k(attnum, position) ON TRUE
      LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
      WHERE n.nspname = current_schema() AND t.relname = $1 AND k.position <= x.indnkeyatts
      ORDER BY i.relname, k.position`
    : `SELECT TABLE_NAME AS \`table\`, INDEX_NAME AS \`name\`,
      CASE WHEN NON_UNIQUE = 0 THEN 'YES' ELSE 'NO' END AS \`unique\`,
      CAST(SEQ_IN_INDEX AS CHAR) AS \`position\`, COLUMN_NAME AS \`column\`
      FROM information_schema.STATISTICS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY INDEX_NAME, SEQ_IN_INDEX`;
  const foreignKeySql = backend === "postgres"
    ? `SELECT t.relname AS "table", c.conname AS "name",
      CAST(k.position AS text) AS "position", a.attname AS "column",
      r.relname AS "targetTable", ra.attname AS "targetColumn",
      CASE c.confupdtype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
        WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' END AS "onUpdate",
      CASE c.confdeltype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
        WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' END AS "onDelete"
      FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
      JOIN pg_namespace n ON n.oid = t.relnamespace JOIN pg_class r ON r.oid = c.confrelid
      JOIN LATERAL unnest(c.conkey, c.confkey) WITH ORDINALITY k(attnum, refnum, position) ON TRUE
      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
      JOIN pg_attribute ra ON ra.attrelid = r.oid AND ra.attnum = k.refnum
      WHERE c.contype = 'f' AND n.nspname = current_schema() AND t.relname = $1
      ORDER BY c.conname, k.position`
    : `SELECT k.TABLE_NAME AS \`table\`, k.CONSTRAINT_NAME AS \`name\`,
      CAST(k.ORDINAL_POSITION AS CHAR) AS \`position\`, k.COLUMN_NAME AS \`column\`,
      k.REFERENCED_TABLE_NAME AS \`targetTable\`, k.REFERENCED_COLUMN_NAME AS \`targetColumn\`,
      r.UPDATE_RULE AS \`onUpdate\`, r.DELETE_RULE AS \`onDelete\`
      FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.TABLE_NAME = k.TABLE_NAME
        AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ? AND k.REFERENCED_TABLE_NAME IS NOT NULL
      ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION`;
  return {
    indexes: await query(indexSql, [tableName]),
    foreignKeys: await query(foreignKeySql, [tableName]),
  };
}

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
    const observation = observeSqliteCatalog(database, tableName, "The generated DeviceCode table exists in the SQLite catalog");
    const repeated = await getMigrations(options);
    assert.equal(repeated.toBeCreated.length, 0);
    assert.equal(repeated.toBeAdded.length, 0);
    assert.equal(repeated.toBeAddedIndexes.length, 0);
    assert.equal(repeated.schemaProblems.length, 0);
    return { ...observation, migration: { initialSql, repeatedSql: await repeated.compileMigrations() } };
  } finally {
    database.close();
  }
}

export async function captureDeviceCodeCatalog(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend), "Select sqlite, postgres or mysql");
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/device-code-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of backend === "sqlite" ? ["default", "legacy", "custom"] : ["default", "custom"]) {
    const configuration = configurations[name];
    const tableName = configuration.deviceCode?.modelName || "deviceCode";
    const options = { plugins: [configuration.deviceCode === undefined
      ? deviceAuthorization() : deviceAuthorization({ schema: configuration })] };
    const observation = backend === "sqlite"
      ? await captureSqlite(tableName, options)
      : await captureFreshServerCatalog(backend, [tableName], options,
        context => observeServerIndexes(context, tableName));
    cases.push({ name, configuration, ...observation });
  }
  return { version, database: backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, `${JSON.stringify(await captureDeviceCodeCatalog(backend), null, 2)}\n`);
}
