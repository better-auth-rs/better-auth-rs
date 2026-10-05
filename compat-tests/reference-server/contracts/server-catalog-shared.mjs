import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { getMigrations } from "better-auth/db/migration";

function columnQuery(backend, count) {
  const parameters = Array.from({ length: count }, (_, index) => backend === "postgres" ? `$${index + 1}` : "?").join(", ");
  return backend === "postgres"
    ? `SELECT table_name AS "table", CAST(ordinal_position AS text) AS "position",
    column_name AS "name", data_type AS "type", udt_name AS "nativeType",
    CAST(character_maximum_length AS text) AS "maxLength",
    CAST(datetime_precision AS text) AS "datetimePrecision",
    is_nullable AS "nullable", column_default AS "default"
    FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name IN (${parameters})
    ORDER BY table_name, ordinal_position`
    : `SELECT TABLE_NAME AS \`table\`, CAST(ORDINAL_POSITION AS CHAR) AS \`position\`,
    COLUMN_NAME AS \`name\`, DATA_TYPE AS \`type\`, COLUMN_TYPE AS \`nativeType\`,
    CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR) AS \`maxLength\`,
    CAST(DATETIME_PRECISION AS CHAR) AS \`datetimePrecision\`,
    IS_NULLABLE AS \`nullable\`, COLUMN_DEFAULT AS \`default\`
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (${parameters})
    ORDER BY TABLE_NAME, ORDINAL_POSITION`;
}

async function observe(database, query, backend, tableNames, configuration, observeRows) {
  const options = {
    database, baseURL: "http://catalog.example.test",
    secret: "ordinary-server-catalog-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    ...configuration,
  };
  const initial = await getMigrations(options);
  const initialSql = await initial.compileMigrations();
  await initial.runMigrations();
  const columns = await query(columnQuery(backend, tableNames.length), tableNames);
  assert.deepEqual([...new Set(columns.map(column => column.table))], [...tableNames].sort());
  const repeated = await getMigrations(options);
  assert.equal(repeated.toBeCreated.length, 0);
  assert.equal(repeated.toBeAdded.length, 0);
  assert.equal(repeated.toBeAddedIndexes.length, 0);
  assert.equal(repeated.schemaProblems.length, 0);
  const observation = observeRows ? await observeRows({ options, query, backend }) : undefined;
  return {
    columns,
    migration: { initialSql, repeatedSql: await repeated.compileMigrations() },
    ...(observeRows ? { observation } : {}),
  };
}

async function postgres(tableNames, configuration, observeRows) {
  const { Pool } = await import("pg");
  const connectionString = process.env.BETTER_AUTH_TEST_POSTGRES_URL;
  assert.ok(connectionString, "CI must supply BETTER_AUTH_TEST_POSTGRES_URL");
  const pool = new Pool({ connectionString, max: 1 });
  const schema = `ba_catalog_${randomUUID().replaceAll("-", "")}`;
  try {
    await pool.query(`CREATE SCHEMA "${schema}"`);
    try {
      await pool.query(`SET search_path TO "${schema}"`);
      return await observe(pool, async (sql, values) => (await pool.query(sql, values)).rows, "postgres", tableNames, configuration, observeRows);
    } finally {
      await pool.query("RESET search_path");
      await pool.query(`DROP SCHEMA "${schema}" CASCADE`);
    }
  } finally {
    await pool.end();
  }
}

async function mysql(tableNames, configuration, observeRows) {
  const { createPool } = await import("mysql2/promise");
  const connectionString = process.env.BETTER_AUTH_TEST_MYSQL_URL;
  assert.ok(connectionString, "CI must supply BETTER_AUTH_TEST_MYSQL_URL");
  const admin = createPool(connectionString);
  const name = `ba_catalog_${randomUUID().replaceAll("-", "")}`;
  try {
    await admin.query(`CREATE DATABASE \`${name}\``);
    try {
      const url = new URL(connectionString);
      url.pathname = `/${name}`;
      const pool = createPool(url.href);
      try {
        return await observe(pool, async (sql, values) => (await pool.query(sql, values))[0], "mysql", tableNames, configuration, observeRows);
      } finally {
        await pool.end();
      }
    } finally {
      await admin.query(`DROP DATABASE \`${name}\``);
    }
  } finally {
    await admin.end();
  }
}

export async function captureFreshServerCatalog(backend, tableNames, configuration = {}, observeRows) {
  assert.ok(backend === "postgres" || backend === "mysql", "Select postgres or mysql");
  return backend === "postgres" ? postgres(tableNames, configuration, observeRows) : mysql(tableNames, configuration, observeRows);
}

export async function observeServerIndexes({ query, backend }, tableName) {
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
