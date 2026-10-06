import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const json = value => JSON.parse(JSON.stringify(value));

async function observeStorage({ options, query, backend }, configuration) {
  const { adapter } = await betterAuth(options).$context;
  const createdAt = "2030-01-02T03:04:05.123Z";
  const owner = json(await adapter.create({
    model: "user",
    data: {
      name: "TwoFactor catalog owner", email: "owner@two-factor-catalog.test",
      emailVerified: false, image: null,
      createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
    },
  }));
  assert.equal(typeof owner.id, "string");
  assert.ok(owner.id.length > 0);
  assert.deepEqual(owner, {
    id: owner.id, name: "TwoFactor catalog owner", email: "owner@two-factor-catalog.test",
    emailVerified: false, image: null, createdAt, updatedAt: createdAt, twoFactorEnabled: false,
  });
  const ownerWhere = [{ field: "id", value: owner.id }];
  const ownerRead = json(await adapter.findOne({ model: "user", where: ownerWhere }));
  assert.deepEqual(ownerRead, owner);
  const created = json(await adapter.create({
    model: "twoFactor",
    data: {
      userId: owner.id, secret: "ordinary-encrypted-secret",
      backupCodes: "ordinary-encrypted-codes", verified: false,
    },
  }));
  assert.equal(typeof created.id, "string");
  assert.ok(created.id.length > 0);
  assert.deepEqual(created, {
    id: created.id, userId: owner.id, secret: "ordinary-encrypted-secret",
    backupCodes: "ordinary-encrypted-codes", verified: false,
    failedVerificationCount: 0, lockedUntil: null,
  });

  const quote = name => backend === "mysql" ? `\`${name.replaceAll("`", "``")}\`` : `"${name.replaceAll('"', '""')}"`;
  const table = model => quote(configuration[model]?.modelName || model);
  const column = (model, field) => quote(configuration[model]?.fields?.[field] || field);
  const parameter = backend === "postgres" ? "$1" : "?";
  await query(`UPDATE ${table("user")} SET ${column("user", "twoFactorEnabled")} = NULL WHERE ${quote("id")} = ${parameter}`, [owner.id]);
  await query(`UPDATE ${table("twoFactor")} SET ${column("twoFactor", "verified")} = NULL, ${column("twoFactor", "failedVerificationCount")} = NULL WHERE ${quote("id")} = ${parameter}`, [created.id]);
  const nullableOwner = json(await adapter.findOne({ model: "user", where: ownerWhere }));
  assert.deepEqual(nullableOwner, { ...owner, twoFactorEnabled: null });
  const where = [{ field: "id", value: created.id }];
  const read = async () => json(await adapter.findOne({ model: "twoFactor", where }));
  const nullable = await read();
  assert.deepEqual(nullable, { ...created, verified: null, failedVerificationCount: null });
  const increment = async () => json(await adapter.incrementOne({
    model: "twoFactor", where, increment: { failedVerificationCount: 1 },
  }));
  const nullableIncrement = await increment();
  assert.deepEqual(nullableIncrement, nullable);
  const nullableRead = await read();
  assert.deepEqual(nullableRead, nullable);
  const reset = json(await adapter.update({
    model: "twoFactor", where, update: { failedVerificationCount: 0, lockedUntil: null },
  }));
  assert.deepEqual(reset, { ...nullable, failedVerificationCount: 0 });
  const increments = [];
  for (const failedVerificationCount of [1, 2]) {
    const row = await increment();
    assert.deepEqual(row, { ...reset, failedVerificationCount });
    increments.push(row);
  }
  const updated = json(await adapter.update({
    model: "twoFactor", where,
    update: { backupCodes: "replacement-encrypted-codes", verified: true },
  }));
  assert.deepEqual(updated, {
    ...increments[1], backupCodes: "replacement-encrypted-codes", verified: true,
  });
  const updatedRead = await read();
  assert.deepEqual(updatedRead, updated);
  assert.deepEqual(json(await adapter.findOne({ model: "user", where: ownerWhere })), nullableOwner);
  const visibleOwner = row => ({ ...row, id: "<owner-id>" });
  const visible = row => ({ ...row, id: "<two-factor-id>", userId: "<owner-id>" });
  return {
    ownerCreated: visibleOwner(owner), ownerRead: visibleOwner(ownerRead), created: visible(created),
    nullableOwner: visibleOwner(nullableOwner), nullable: visible(nullable),
    nullableIncrement: visible(nullableIncrement), nullableRead: visible(nullableRead),
    reset: visible(reset), increments: increments.map(visible),
    updated: visible(updated), updatedRead: visible(updatedRead),
  };
}

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

async function captureSqlite(tableNames, configuration, observeRows) {
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
    const storage = await observeRows({ options, backend: "sqlite", query: async (sql, values) => database.query(sql).all(...values) });
    return { catalog, ddl, migration: { initialSql, repeatedSql: await repeated.compileMigrations() }, observation: { storage } };
  } finally {
    database.close();
  }
}

async function captureCase(backend, name) {
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/two-factor-catalog-config.json", import.meta.url), "utf8"));
  const configuration = configurations[name];
  const tableNames = {
    user: configuration.user?.modelName || "user",
    twoFactor: configuration.twoFactor?.modelName || "twoFactor",
  };
  const options = configuredOptions(configuration);
  const observeRows = context => observeStorage(context, configuration);
  const observed = backend === "sqlite"
    ? await captureSqlite(tableNames, options, observeRows)
    : await captureFreshServerCatalog(backend, Object.values(tableNames), options, async context => {
      const observation = {};
      for (const [model, tableName] of Object.entries(tableNames)) {
        observation[model] = await observeServerIndexes(context, tableName);
      }
      observation.storage = await observeRows(context);
      return observation;
    });
  return { name, configuration, ...observed };
}

export async function captureTwoFactorCatalog(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend), "Select sqlite, postgres or mysql");
  const directory = await mkdtemp(join(tmpdir(), "better-auth-two-factor-cases-"));
  try {
    const cases = [];
    for (const name of backend === "sqlite" ? ["default", "legacy", "custom"] : ["default", "custom"]) {
      const output = join(directory, `${name}.json`);
      // Upstream mutates shared schema references. Each configuration needs a fresh process.
      const child = Bun.spawn([process.execPath, "--no-install", fileURLToPath(import.meta.url), backend, output, name], {
        stdout: "inherit", stderr: "inherit",
      });
      assert.equal(await child.exited, 0, `${backend}/${name} catalog capture succeeds`);
      cases.push(JSON.parse(await readFile(output, "utf8")));
    }
    return { version, database: backend, cases };
  } finally {
    await rm(directory, { recursive: true });
  }
}

if (import.meta.main) {
  const [backend, output, name] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  const observation = name === undefined
    ? await captureTwoFactorCatalog(backend) : await captureCase(backend, name);
  writeFileSync(output, `${JSON.stringify(observation, null, 2)}\n`);
}
