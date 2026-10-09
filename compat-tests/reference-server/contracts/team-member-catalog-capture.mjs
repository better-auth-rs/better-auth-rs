import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

const input = {
  seedAt: "2030-01-02T03:04:05.123Z",
  users: ["user-a", "user-b"],
  organization: "org",
  teams: ["team-a", "team-b"],
};
const fields = ["id", "teamId", "userId", "membershipKey", "createdAt"];
const json = value => JSON.parse(JSON.stringify(value));

async function observeMemberships({ query, backend }, configuration) {
  const quote = name => backend === "mysql" ? `\`${name.replaceAll("`", "``")}\`` : `"${name.replaceAll('"', '""')}"`;
  const table = model => quote(configuration[model]?.modelName || model);
  const fieldName = (model, field) => configuration[model]?.fields?.[field] || field;
  const column = (model, field) => quote(fieldName(model, field));
  const parameter = index => backend === "postgres" ? `$${index + 1}` : "?";
  const insert = (model, row) => query(
    `INSERT INTO ${table(model)} (${Object.keys(row).map(field => column(model, field)).join(", ")}) VALUES (${Object.keys(row).map((_, index) => parameter(index)).join(", ")})`,
    Object.values(row),
  );
  const snapshot = async () => {
    const rows = await query(`SELECT * FROM ${table("teamMember")} ORDER BY ${column("teamMember", "id")}`, []);
    return rows.map(row => {
      assert.deepEqual(Object.keys(row).sort(), fields.map(field => fieldName("teamMember", field)).sort());
      return Object.fromEntries(fields.map(field => [field, row[fieldName("teamMember", field)]]));
    });
  };
  const seedAt = backend === "sqlite" ? input.seedAt : new Date(input.seedAt);
  for (const id of input.users) {
    await insert("user", {
      id, name: id, email: `${id}@team-member-catalog.test`,
      emailVerified: backend === "postgres" ? false : 0, createdAt: seedAt, updatedAt: seedAt,
    });
  }
  await insert("organization", { id: input.organization, name: input.organization, slug: input.organization, createdAt: seedAt });
  for (const id of input.teams) {
    await insert("team", { id, name: id, organizationId: input.organization, memberCount: 0, createdAt: seedAt });
  }

  const expected = [];
  const inserted = [];
  for (const row of [
    { id: "member-a", teamId: "team-a", userId: "user-a", membershipKey: "key-a" },
    { id: "member-b", teamId: "team-a", userId: "user-a", membershipKey: "key-b", createdAt: null },
  ]) {
    await insert("teamMember", row);
    expected.push({ ...row, createdAt: null });
    const rows = await snapshot();
    assert.deepEqual(rows, expected);
    inserted.push(rows);
  }

  const rejected = [];
  for (const [name, kind, row] of [
    ["duplicateKey", "unique", { id: "member-key-duplicate", teamId: "team-b", userId: "user-b", membershipKey: "key-a" }],
    ["duplicateId", "unique", { id: "member-a", teamId: "team-b", userId: "user-b", membershipKey: "key-c" }],
    ["missingTeam", "foreign-key", { id: "member-invalid-team", teamId: "missing", userId: "user-b", membershipKey: "key-c" }],
    ["missingUser", "foreign-key", { id: "member-invalid-user", teamId: "team-b", userId: "missing", membershipKey: "key-c" }],
  ]) {
    await assert.rejects(() => insert("teamMember", row), error => {
      if (backend === "postgres") {
        assert.equal(error.code, kind === "unique" ? "23505" : "23503");
      } else if (backend === "mysql") {
        assert.equal(error.code, kind === "unique" ? "ER_DUP_ENTRY" : "ER_NO_REFERENCED_ROW_2");
      } else {
        assert.match(error.message, kind === "unique" ? /UNIQUE constraint failed:/ : /FOREIGN KEY constraint failed/);
      }
      return true;
    });
    const rows = await snapshot();
    assert.deepEqual(rows, expected);
    rejected.push({ name, kind, rows });
  }

  for (const id of ["member-c", "member-d"]) {
    const row = { id, teamId: "team-b", userId: "user-b", membershipKey: null, createdAt: null };
    await insert("teamMember", row);
    expected.push(row);
  }
  const afterNullKeys = await snapshot();
  assert.deepEqual(afterNullKeys, expected);
  await query(`DELETE FROM ${table("team")} WHERE ${column("team", "id")} = ${parameter(0)}`, ["team-a"]);
  const afterTeamDelete = await snapshot();
  assert.deepEqual(afterTeamDelete, expected.slice(2));
  await query(`DELETE FROM ${table("user")} WHERE ${column("user", "id")} = ${parameter(0)}`, ["user-b"]);
  const afterUserDelete = await snapshot();
  assert.deepEqual(afterUserDelete, []);
  return { inserted, rejected, afterNullKeys, afterTeamDelete, afterUserDelete };
}

async function captureSqlite(tableName, configuration, observeRows) {
  const database = new Database(":memory:");
  try {
    database.exec("PRAGMA foreign_keys = ON");
    const options = {
      database, baseURL: "http://catalog.example.test",
      secret: "ordinary-server-catalog-secret-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, ...configuration,
    };
    const initial = await getMigrations(options);
    const initialSql = await initial.compileMigrations();
    await initial.runMigrations();
    assert.equal(database.query("PRAGMA foreign_keys").get().foreign_keys, 1);
    const catalog = observeSqliteCatalog(database, tableName, "The generated TeamMember table exists in the SQLite catalog");
    const repeated = await getMigrations(options);
    assert.equal(repeated.toBeCreated.length, 0);
    assert.equal(repeated.toBeAdded.length, 0);
    assert.equal(repeated.toBeAddedIndexes.length, 0);
    assert.equal(repeated.schemaProblems.length, 0);
    const storage = await observeRows({ backend: "sqlite", query: async (sql, values) => database.query(sql).all(...values) });
    return { ...catalog, migration: { initialSql, repeatedSql: await repeated.compileMigrations() }, observation: { storage } };
  } finally {
    database.close();
  }
}

export async function captureTeamMemberCatalog(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend), "Select sqlite, postgres or mysql");
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/team-member-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of backend === "sqlite" ? ["default", "legacy", "custom"] : ["default", "custom"]) {
    const configuration = configurations[name];
    const tableName = configuration.teamMember?.modelName || "teamMember";
    const { user, ...schema } = configuration;
    const options = {
      ...(user === undefined ? {} : { user }),
      plugins: [organization({ teams: { enabled: true }, schema })],
    };
    const observeRows = context => observeMemberships(context, configuration);
    const observation = backend === "sqlite"
      ? await captureSqlite(tableName, options, observeRows)
      : await captureFreshServerCatalog(backend, [tableName], options, async context => ({
        ...await observeServerIndexes(context, tableName), storage: await observeRows(context),
      }));
    cases.push({ name, configuration, ...observation });
  }
  return json({ version, database: backend, input, cases });
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, `${JSON.stringify(await captureTeamMemberCatalog(backend), null, 2)}\n`);
}
