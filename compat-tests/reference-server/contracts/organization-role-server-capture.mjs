import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { organization, testUtils } from "better-auth/plugins";
import { defaultAc } from "better-auth/plugins/organization/access";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const createdPermission = { organization: ["update"], member: ["create"] };
const updatedPermission = { member: ["update", "delete"], organization: ["delete", "update"] };

async function observeRoles({ options, query, backend }, schema) {
  const auth = betterAuth(options);
  const context = await auth.$context;
  const owner = await context.test.saveUser(context.test.createUser({
    name: "Role catalog owner", email: "owner@role-catalog.test",
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
  const parent = await call("create", { name: "Role catalog", slug: "role-catalog" });
  const member = await context.adapter.findOne({ model: "member", where: [
    { field: "organizationId", value: parent.id }, { field: "userId", value: owner.id },
  ] });
  assert.equal(member.role, "owner");
  const started = Date.now();
  const created = await call("create-role", {
    organizationId: parent.id, role: "catalog-editor", permission: createdPermission,
  });
  const createdFinished = Date.now();
  assert.equal(created.success, true);
  assert.deepEqual(created.statements, createdPermission);
  const id = created.roleData.id;
  assert.equal(typeof id, "string");
  assert.ok(id.length > 0);
  const createdAt = created.roleData.createdAt;
  assert.ok(started <= Date.parse(createdAt) && Date.parse(createdAt) <= createdFinished);

  const quote = name => backend === "postgres" ? `"${name.replaceAll('"', '""')}"` : `\`${name.replaceAll("`", "``")}\``;
  const table = quote(schema.organizationRole?.modelName || "organizationRole");
  const permission = quote(schema.organizationRole?.fields?.permission || "permission");
  async function stored() {
    const rows = await query(`SELECT ${permission} AS permission FROM ${table} WHERE id = ${backend === "postgres" ? "$1" : "?"}`, [id]);
    assert.equal(rows.length, 1);
    assert.equal(typeof rows[0].permission, "string");
    return rows[0].permission;
  }
  const storedCreated = await stored();
  assert.deepEqual(JSON.parse(storedCreated), createdPermission);
  const read = await call("get-role", undefined, { organizationId: parent.id, roleId: id });
  const updateStarted = Date.now();
  const updated = await call("update-role", {
    organizationId: parent.id, roleId: id,
    data: { roleName: "catalog-maintainer", permission: updatedPermission },
  });
  const updateFinished = Date.now();
  assert.equal(updated.success, true);
  const storedUpdated = await stored();
  assert.deepEqual(JSON.parse(storedUpdated), updatedPermission);
  const reread = await call("get-role", undefined, { organizationId: parent.id, roleId: id });
  function visible(role) {
    assert.equal(role.id, id);
    assert.equal(role.organizationId, parent.id);
    assert.equal(role.createdAt, createdAt);
    const result = { ...role, id: "<role-id>", organizationId: "<organization-id>", createdAt: "<created-at>" };
    if (role.updatedAt !== null && role.updatedAt !== undefined) {
      const value = Date.parse(role.updatedAt);
      assert.ok(updateStarted <= value && value <= updateFinished);
      result.updatedAt = "<updated-at>";
    }
    return result;
  }
  return { created: visible(created.roleData), read: visible(read), updated: visible(updated.roleData),
    reread: visible(reread), storedCreated, storedUpdated };
}

export async function captureOrganizationRoleServer(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/member-organization-role-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of ["default", "custom"]) {
    const source = configurations[name];
    const configuration = Object.fromEntries(["user", "organization", "member", "organizationRole"]
      .filter(key => source[key] !== undefined).map(key => [key, source[key]]));
    const { user, ...schema } = configuration;
    const tableName = schema.organizationRole?.modelName || "organizationRole";
    const observation = await captureFreshServerCatalog(backend, [tableName], {
      ...(user === undefined ? {} : { user }), rateLimit: { enabled: false },
      plugins: [testUtils(), organization({ schema, ac: defaultAc, dynamicAccessControl: { enabled: true } })],
    }, context => observeRoles(context, schema));
    cases.push({ name, configuration, ...observation });
  }
  return { version, database: backend, cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, JSON.stringify(await captureOrganizationRoleServer(backend), null, 2) + "\n");
}
