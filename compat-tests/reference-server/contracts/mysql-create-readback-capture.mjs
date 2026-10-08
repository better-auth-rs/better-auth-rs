import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { Kysely, MysqlDialect } from "kysely";
import { createPool } from "mysql2";
import { observeValue } from "./device-where-capture.mjs";
import { withRestoredSchema } from "./schema-isolation.mjs";
import { captureMysqlCreateLifecycle } from "./mysql-create-lifecycle-capture.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const table = "readback_jwks";
const date = "2030-01-02T03:04:05.000Z";
const fieldDefinitions = [
  ["publicKey", "string", "stored_public_key"],
  ["privateKey", "string", "stored_private_key"],
  ["createdAt", "date", "stored_created_at"],
  ["expiresAt", "date", "stored_expires_at"],
  ["alg", "string", "stored_algorithm"],
  ["crv", "string", "stored_curve"],
];

export const mysqlCreateReadbackScenarios = [
  { name: "explicit-id", generation: false, storage: "default", rewrite: "publicKey", input: { id: "explicit-id" } },
  { name: "serial-id", generation: "serial", storage: "serial", rewrite: "publicKey" },
  { name: "database-default-full-match", generation: false, storage: "default" },
  { name: "mapped-unique-first-hit", generation: false, storage: "default", unique: true, rewrite: "privateKey" },
  { name: "mapped-unique-first-miss-second-hit", generation: false, storage: "default", unique: true, rewrite: "publicKey" },
  { name: "mapped-unique-null-skipped", generation: false, storage: "default", unique: true, input: { publicKey: null } },
  { name: "mapped-unique-empty-probed", generation: false, storage: "default", unique: true, rewrite: "publicKey", input: { publicKey: "" } },
  { name: "full-match-single-then-duplicate", generation: false, storage: "trigger", repeat: 2 },
  { name: "full-match-transaction-single-then-duplicate", generation: false, storage: "trigger", repeat: 2, transaction: true },
  { name: "readback-error-direct", generation: "serial", storage: "missing-id" },
  { name: "readback-error-transaction", generation: "serial", storage: "missing-id", transaction: true },
];

function declaration(scenario) {
  return Object.fromEntries(fieldDefinitions.map(([name, type, fieldName]) => [name, {
    type, fieldName, required: name === "createdAt" || name === "privateKey",
    unique: Boolean(scenario.unique && (name === "publicKey" || name === "privateKey")),
  }]));
}

function configuration(scenario, trace) {
  const fields = Object.fromEntries(Object.entries(declaration(scenario)).map(([name, field]) => [name, {
    ...field,
    transform: {
      input(value) { trace.push({ phase: "input", field: name, value: observeValue(value) }); return value; },
      output(value) { trace.push({ phase: "output", field: name, value: observeValue(value) }); return value; },
    },
  }]));
  return {
    baseURL: "http://mysql-readback.test",
    secret: "ordinary-mysql-readback-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: scenario.generation } },
    plugins: [jwt(), { id: "mysql-readback-fields", schema: { jwks: { modelName: table, fields } } }],
  };
}

function setupStatements(scenario) {
  const id = scenario.storage === "missing-id"
    ? "`database_id` INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY"
    : scenario.storage === "serial"
      ? "`id` INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY"
      : "`id` VARCHAR(36) NOT NULL DEFAULT 'database-default-id' PRIMARY KEY";
  const keyType = scenario.unique ? "VARCHAR(255) UNIQUE" : "TEXT";
  const statements = [
    `CREATE TABLE \`${table}\` (${id},
      \`stored_public_key\` ${keyType} NULL,
      \`stored_private_key\` ${keyType} NOT NULL,
      \`stored_created_at\` TIMESTAMP(3) NOT NULL,
      \`stored_expires_at\` TIMESTAMP(3) NULL,
      \`stored_algorithm\` TEXT NULL,
      \`stored_curve\` TEXT NULL) ENGINE=InnoDB`,
  ];
  if (scenario.storage === "trigger") {
    statements.push(
      "CREATE TABLE readback_counter (next_id INTEGER NOT NULL) ENGINE=InnoDB",
      "INSERT INTO readback_counter (next_id) VALUES (0)",
      `CREATE TRIGGER readback_generate_id BEFORE INSERT ON \`${table}\` FOR EACH ROW BEGIN
        UPDATE readback_counter SET next_id = next_id + 1;
        SET NEW.id = CONCAT('database-', (SELECT next_id FROM readback_counter));
      END`,
    );
  }
  if (scenario.rewrite) {
    const field = declaration(scenario)[scenario.rewrite].fieldName;
    statements.push(`CREATE TRIGGER readback_rewrite_key BEFORE INSERT ON \`${table}\` FOR EACH ROW
      SET NEW.\`${field}\` = 'database-rewritten-key'`);
  }
  return statements;
}

function observeError(error) {
  if (error instanceof assert.AssertionError) throw error;
  assert.ok(error instanceof Error);
  // Stack traces and query timings describe the capture host, not the SQL contract.
  return { name: error.name, message: error.message, properties: observeValue(Object.fromEntries(Object.entries(error))) };
}

async function observeCreate(adapter, pool, scenario, trace) {
  const data = {
    publicKey: "submitted-public-key", privateKey: "submitted-private-key",
    createdAt: new Date(date), expiresAt: null, alg: "EdDSA", crv: undefined,
    ...scenario.input,
  };
  const input = observeValue(data);
  let outcome;
  try {
    const create = current => current.create({ model: "jwks", forceAllowId: true, data });
    const result = scenario.transaction ? await adapter.transaction(create) : await create(adapter);
    outcome = { returned: true, result: observeValue(result), keys: result === null ? [] : Object.keys(result) };
  } catch (error) {
    outcome = { returned: false, error: observeError(error) };
  }
  const idColumn = scenario.storage === "missing-id" ? "database_id" : "id";
  const [rows] = await pool.promise().query(`SELECT * FROM \`${table}\` ORDER BY \`${idColumn}\``);
  return {
    input, ...outcome, trace: trace.splice(0),
    stored: rows.map(row => ({ row: observeValue(row), keys: Object.keys(row) })),
  };
}

function assertBranches(scenario, operations) {
  for (const [index, operation] of operations.entries()) {
    const label = `${scenario.name}/${index}: ${JSON.stringify(operation)}`;
    const input = operation.trace.filter(event => event.phase === "input");
    assert.deepEqual(input.map(event => event.field), fieldDefinitions.map(([name]) => name), label);
    const output = operation.trace.filter(event => event.phase === "output");
    const sql = operation.trace.filter(event => event.phase === "sql");
    assert.equal(sql.filter(event => event.sql.startsWith("insert into")).length, 1, label);
    assert.equal(sql.filter(event => event.sql === "begin").length, 1, label);
    const inserted = operation.trace.findIndex(event => event.phase === "sql" && event.sql.startsWith("insert into"));
    const begun = operation.trace.findIndex(event => event.phase === "sql" && event.sql === "begin");
    assert.equal(begun < inserted, Boolean(scenario.transaction), label);
    if (scenario.storage === "missing-id") {
      assert.equal(operation.returned, false, label);
      assert.equal(operation.error.properties.code, "ER_BAD_FIELD_ERROR", label);
      assert.equal(output.length, 0, label);
      assert.equal(operation.stored.length, scenario.transaction ? 0 : 1, label);
      assert.equal(sql.at(-1).sql, "rollback", label);
      continue;
    }
    assert.equal(operation.returned, true, label);
    assert.equal(operation.stored.length, index + 1, label);
    assert.equal(sql.at(-1).sql, "commit", label);
    if (scenario.storage === "trigger" && index === 1) {
      assert.equal(operation.result, null, label);
      assert.equal(output.length, 0, label);
    } else {
      assert.deepEqual(output.map(event => event.field), fieldDefinitions.map(([name]) => name), label);
      const expectedId = scenario.storage === "trigger" ? "database-1"
        : scenario.storage === "serial" ? "1" : scenario.input?.id ?? "database-default-id";
      assert.equal(operation.result.id, expectedId, label);
    }
    const selects = sql.filter(event => event.sql.startsWith("select * from"));
    if (scenario.unique) {
      const names = scenario.name === "mapped-unique-first-hit" ? ["stored_public_key"]
        : scenario.name === "mapped-unique-null-skipped" ? ["stored_private_key"]
          : ["stored_public_key", "stored_private_key"];
      assert.deepEqual(selects.map(event => event.sql), names.map(name => `select * from \`${table}\` where \`${name}\` = ? limit ?`), label);
      if (scenario.name === "mapped-unique-empty-probed") assert.equal(selects[0].parameters[0], "", label);
    } else if (scenario.generation === "serial" || scenario.input?.id) {
      assert.deepEqual(selects.map(event => event.sql), [`select * from \`${table}\` where \`id\` = ? limit ?`], label);
    } else {
      assert.equal(selects.length, 1, label);
      assert.ok(selects[0].sql.includes("`stored_expires_at` is null"), label);
      assert.ok(!selects[0].sql.includes("stored_curve"), label);
      assert.equal(selects[0].parameters.at(-1), 2, label);
    }
  }
}

async function withReadbackDatabase(admin, connectionString, setup, capture) {
  const databaseName = `ba_readback_${randomUUID().replaceAll("-", "")}`;
  await admin.query(`CREATE DATABASE \`${databaseName}\``);
  try {
    const url = new URL(connectionString);
    url.pathname = `/${databaseName}`;
    // LAST_INSERT_ID belongs to a connection. This contract has no concurrent pool borrowers.
    const pool = createPool({ uri: url.href, connectionLimit: 1, timezone: "Z" });
    const trace = [];
    const db = new Kysely({
      dialect: new MysqlDialect({ pool }),
      log(event) {
        trace.push({ phase: "sql", level: event.level, sql: event.query.sql,
          parameters: observeValue(event.query.parameters),
          ...(event.level === "error" ? { error: observeError(event.error) } : {}),
        });
      },
    });
    try {
      for (const statement of setup) await pool.promise().query(statement);
      return await capture({ pool, db, trace });
    } finally {
      // Setup can fail before Kysely initializes; the capture owns the pool in both paths.
      await pool.promise().end();
    }
  } finally {
    await admin.query(`DROP DATABASE \`${databaseName}\``);
  }
}

async function captureCase(admin, connectionString, scenario) {
  const setup = setupStatements(scenario);
  return withReadbackDatabase(admin, connectionString, setup, async ({ pool, db, trace }) => {
    const options = { ...configuration(scenario, trace), database: { db, type: "mysql", transaction: true } };
    const { adapter } = await betterAuth(options).$context;
    assert.deepEqual(trace, []);
    const operations = [];
    for (let index = 0; index < (scenario.repeat ?? 1); index++) {
      operations.push(await observeCreate(adapter, pool, scenario, trace));
    }
    assertBranches(scenario, operations);
    return { name: scenario.name, generation: scenario.generation, transaction: Boolean(scenario.transaction),
      declaration: { modelName: table, fields: declaration(scenario) }, setup, operations };
  });
}

export async function captureMysqlCreateReadback() {
  const connectionString = process.env.BETTER_AUTH_TEST_MYSQL_URL;
  assert.ok(connectionString, "CI must supply BETTER_AUTH_TEST_MYSQL_URL");
  const admin = createPool(connectionString).promise();
  try {
    const cases = [];
    for (const scenario of mysqlCreateReadbackScenarios) {
      cases.push(await withRestoredSchema(jwt().schema, () => captureCase(admin, connectionString, scenario)));
    }
    const lifecycle = await captureMysqlCreateLifecycle((setup, capture) =>
      withReadbackDatabase(admin, connectionString, setup, capture));
    return { version, backend: "mysql", model: "jwks", cases, lifecycle };
  } finally {
    await admin.end();
  }
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.equal(backend, "mysql", "This contract requires MySQL");
  assert.ok(output, "Pass the fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureMysqlCreateReadback(), null, 2)}\n`);
}
