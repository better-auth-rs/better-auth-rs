import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { organization, testUtils } from "better-auth/plugins";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const teams = { enabled: true, defaultTeam: { enabled: false } };

async function observeTeam({ options, query, backend }, schema) {
  const auth = betterAuth(options);
  const context = await auth.$context;
  const owner = await context.test.saveUser(context.test.createUser({
    name: "Team catalog owner", email: "owner@team-catalog.test",
  }));
  const login = await context.test.login({ userId: owner.id });
  async function call(path, body, parameters) {
    const headers = new Headers(login.headers);
    headers.set("origin", options.baseURL);
    headers.set("accept", "application/json");
    const url = new URL(`/api/auth/organization/${path}`, options.baseURL);
    if (parameters) url.search = new URLSearchParams(parameters).toString();
    if (body !== undefined) headers.set("content-type", "application/json");
    const response = await auth.handler(new Request(url, {
      method: body === undefined ? "GET" : "POST", headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }));
    const value = await response.json();
    assert.equal(response.status, 200, `${path}: ${JSON.stringify(value)}`);
    return value;
  }
  const parent = await call("create", { name: "Team catalog", slug: "team-catalog" });
  const membership = await context.adapter.findOne({ model: "member", where: [
    { field: "organizationId", value: parent.id }, { field: "userId", value: owner.id },
  ] });
  assert.equal(membership.role, "owner");
  const started = Date.now();
  const created = await call("create-team", { organizationId: parent.id, name: "Catalog team" });
  const createdFinished = Date.now();
  const id = created.id;
  assert.equal(typeof id, "string");
  assert.ok(id.length > 0);
  for (const name of ["createdAt", "updatedAt"]) {
    assert.ok(started <= Date.parse(created[name]) && Date.parse(created[name]) <= createdFinished);
  }
  const quote = name => backend === "postgres" ? `"${name.replaceAll('"', '""')}"` : `\`${name.replaceAll("`", "``")}\``;
  const table = quote(schema.team?.modelName || "team");
  const count = quote(schema.team?.fields?.memberCount || "memberCount");
  async function storedCount() {
    const rows = await query(`SELECT ${count} AS count FROM ${table} WHERE id = ${backend === "postgres" ? "$1" : "?"}`, [id]);
    assert.equal(rows.length, 1);
    assert.equal(typeof rows[0].count, "number");
    return rows[0].count;
  }
  async function readTeam() {
    const rows = await call("list-teams", undefined, { organizationId: parent.id });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].id, id);
    return rows[0];
  }
  const read = await readTeam();
  assert.equal(read.updatedAt, created.updatedAt);
  const before = await storedCount();
  assert.equal(before, 0);
  const addedStarted = Date.now();
  const member = await call("add-team-member", { organizationId: parent.id, teamId: id, userId: owner.id });
  const addedFinished = Date.now();
  assert.equal(member.teamId, id);
  assert.equal(member.userId, owner.id);
  assert.equal(typeof member.id, "string");
  assert.ok(member.id.length > 0);
  assert.ok(addedStarted <= Date.parse(member.createdAt) && Date.parse(member.createdAt) <= addedFinished);
  const reread = await readTeam();
  const after = await storedCount();
  assert.equal(after, 1);
  function visible(team) {
    assert.equal(team.id, id);
    assert.equal(team.organizationId, parent.id);
    assert.equal(team.createdAt, created.createdAt);
    assert.ok(Date.parse(created.updatedAt) <= Date.parse(team.updatedAt) && Date.parse(team.updatedAt) <= addedFinished);
    return { ...team, id: "<team-id>", organizationId: "<organization-id>",
      createdAt: "<created-at>", updatedAt: "<updated-at>" };
  }
  return { created: visible(created), read: visible(read), reread: visible(reread),
    member: { ...member, id: "<member-id>", teamId: "<team-id>", userId: "<owner-id>", createdAt: "<member-created-at>" },
    before, after };
}

export async function captureTeamInvitationServer(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const cases = [];
  for (const model of ["team", "invitation"]) {
    const configurations = JSON.parse(readFileSync(new URL(`../../schema-consumer/${model}-catalog-config.json`, import.meta.url), "utf8"));
    for (const name of ["default", "custom"]) {
      const source = configurations[name];
      const configuration = Object.fromEntries(["user", "organization", model]
        .filter(key => source[key] !== undefined).map(key => [key, source[key]]));
      const { user, ...schema } = configuration;
      const table = schema[model]?.modelName || model;
      const observation = await captureFreshServerCatalog(backend, [table], {
        ...(user === undefined ? {} : { user }), rateLimit: { enabled: false },
        plugins: [testUtils(), organization({ schema, teams })],
      }, model === "team" ? context => observeTeam(context, schema) : undefined);
      cases.push({ model, name, configuration, ...observation });
    }
  }
  // Observe serialized JSON; generated IDs and times are replaced only after their relationships are checked.
  return JSON.parse(JSON.stringify({ version, database: backend, teams, cases }));
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, `${JSON.stringify(await captureTeamInvitationServer(backend), null, 2)}\n`);
}
