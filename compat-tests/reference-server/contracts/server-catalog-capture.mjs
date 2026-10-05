import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { getMigrations } from "better-auth/db/migration";

const queries = {
  postgres: `SELECT table_name AS "table", CAST(ordinal_position AS text) AS "position",
    column_name AS "name", data_type AS "type", udt_name AS "nativeType",
    CAST(character_maximum_length AS text) AS "maxLength",
    CAST(datetime_precision AS text) AS "datetimePrecision",
    is_nullable AS "nullable", column_default AS "default"
    FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name IN ('user', 'account')
    ORDER BY table_name, ordinal_position`,
  mysql: `SELECT TABLE_NAME AS \`table\`, CAST(ORDINAL_POSITION AS CHAR) AS \`position\`,
    COLUMN_NAME AS \`name\`, DATA_TYPE AS \`type\`, COLUMN_TYPE AS \`nativeType\`,
    CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR) AS \`maxLength\`,
    CAST(DATETIME_PRECISION AS CHAR) AS \`datetimePrecision\`,
    IS_NULLABLE AS \`nullable\`, COLUMN_DEFAULT AS \`default\`
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ('user', 'account')
    ORDER BY TABLE_NAME, ORDINAL_POSITION`,
};

async function observe(database, query, backend) {
  const options = {
    database, baseURL: "http://catalog.example.test",
    secret: "ordinary-server-catalog-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
  };
  const initial = await getMigrations(options);
  const initialSql = await initial.compileMigrations();
  await initial.runMigrations();
  const columns = await query(queries[backend]);
  assert.deepEqual([...new Set(columns.map(column => column.table))], ["account", "user"]);
  const repeated = await getMigrations(options);
  assert.equal(repeated.toBeCreated.length, 0);
  assert.equal(repeated.toBeAdded.length, 0);
  assert.equal(repeated.toBeAddedIndexes.length, 0);
  assert.equal(repeated.schemaProblems.length, 0);
  return {
    columns,
    migration: { initialSql, repeatedSql: await repeated.compileMigrations() },
  };
}

async function postgres() {
  const { Pool } = await import("pg");
  const connectionString = process.env.BETTER_AUTH_TEST_POSTGRES_URL;
  assert.ok(connectionString, "CI must supply BETTER_AUTH_TEST_POSTGRES_URL");
  const pool = new Pool({ connectionString, max: 1 });
  const schema = `ba_catalog_${randomUUID().replaceAll("-", "")}`;
  try {
    await pool.query(`CREATE SCHEMA "${schema}"`);
    try {
      await pool.query(`SET search_path TO "${schema}"`);
      return await observe(pool, async sql => (await pool.query(sql)).rows, "postgres");
    } finally {
      await pool.query("RESET search_path");
      await pool.query(`DROP SCHEMA "${schema}" CASCADE`);
    }
  } finally {
    await pool.end();
  }
}

async function mysql() {
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
        return await observe(pool, async sql => (await pool.query(sql))[0], "mysql");
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

export async function captureServerCatalog(backend) {
  assert.ok(backend === "postgres" || backend === "mysql", "Select postgres or mysql");
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const observation = await (backend === "postgres" ? postgres() : mysql());
  return { version, database: backend, ...observation };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureServerCatalog(backend), null, 2) + "\n");
}
