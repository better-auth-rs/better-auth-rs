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
