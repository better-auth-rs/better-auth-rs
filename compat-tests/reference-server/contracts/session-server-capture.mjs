import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { testUtils } from "better-auth/plugins";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const input = {
  expiresIn: 3600,
  initial: { ipAddress: "192.0.2.10", userAgent: "catalog-session/1" },
  update: { ipAddress: "192.0.2.20", userAgent: "catalog-session/2" },
};
const json = value => JSON.parse(JSON.stringify(value));

async function observeSession({ options, query, backend }, configuration) {
  const auth = betterAuth(options);
  const context = await auth.$context;
  const owner = await context.test.saveUser(context.test.createUser({
    name: "Session catalog owner", email: "owner@session-catalog.test",
  }));
  const adapter = context.internalAdapter;
  const started = Date.now();
  const created = json(await adapter.createSession(owner.id, false, input.initial));
  const createdFinished = Date.now();
  for (const field of ["id", "token"]) {
    assert.equal(typeof created[field], "string");
    assert.ok(created[field].length > 0);
  }
  assert.equal(created.userId, owner.id);
  assert.equal(created.ipAddress, input.initial.ipAddress);
  assert.equal(created.userAgent, input.initial.userAgent);
  for (const field of ["createdAt", "updatedAt", "expiresAt"]) {
    const offset = field === "expiresAt" ? input.expiresIn * 1000 : 0;
    assert.ok(started + offset <= Date.parse(created[field]) && Date.parse(created[field]) <= createdFinished + offset);
  }
  async function readSession() {
    const value = await adapter.findSession(created.token);
    if (value === null) return null;
    assert.equal(value.user.id, owner.id);
    return json(value.session);
  }
  const quote = name => backend === "postgres" ? `"${name.replaceAll('"', '""')}"` : `\`${name.replaceAll("`", "``")}\``;
  const schema = configuration.session;
  const fields = ["id", "expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId"];
  const columns = fields.map(field => `${quote(schema?.fields?.[field] || field)} AS ${quote(field)}`).join(", ");
  const table = quote(schema?.modelName || "session");
  const tokenColumn = quote(schema?.fields?.token || "token");
  async function stored() {
    return json(await query(`SELECT ${columns} FROM ${table} WHERE ${tokenColumn} = ${backend === "postgres" ? "$1" : "?"}`, [created.token]));
  }
  const read = await readSession();
  assert.deepEqual(read, created);
  const storedCreated = await stored();
  assert.deepEqual(storedCreated, [created]);
  const updatedStarted = Date.now();
  const updated = json(await adapter.updateSession(created.token, input.update));
  const updatedFinished = Date.now();
  for (const field of ["id", "token", "userId", "createdAt", "expiresAt"]) {
    assert.equal(updated[field], created[field]);
  }
  assert.equal(updated.ipAddress, input.update.ipAddress);
  assert.equal(updated.userAgent, input.update.userAgent);
  assert.ok(updatedStarted <= Date.parse(updated.updatedAt) && Date.parse(updated.updatedAt) <= updatedFinished);
  const reread = await readSession();
  assert.deepEqual(reread, updated);
  const storedUpdated = await stored();
  assert.deepEqual(storedUpdated, [updated]);
  await adapter.deleteSession(created.token);
  const deleted = await readSession();
  assert.equal(deleted, null);
  const storedDeleted = await stored();
  assert.deepEqual(storedDeleted, []);
  const retainedOwner = await context.adapter.findOne({ model: "user", where: [{ field: "id", value: owner.id }] });
  assert.equal(retainedOwner.id, owner.id);
  function visible(session, updatedAt) {
    return { ...session, id: "<session-id>", token: "<session-token>", userId: "<owner-id>",
      createdAt: "<created-at>", expiresAt: "<expires-at>", updatedAt };
  }
  return {
    created: visible(created, "<initial-updated-at>"), read: visible(read, "<initial-updated-at>"),
    updated: visible(updated, "<updated-at>"), reread: visible(reread, "<updated-at>"),
    storedCreated: storedCreated.map(value => visible(value, "<initial-updated-at>")),
    storedUpdated: storedUpdated.map(value => visible(value, "<updated-at>")),
    deleted, storedDeleted, ownerRetained: true,
  };
}

export async function captureSessionServer(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/session-catalog-config.json", import.meta.url), "utf8"));
  const cases = [];
  for (const name of ["default", "custom"]) {
    const configuration = configurations[name];
    const table = configuration.session?.modelName || "session";
    const observation = await captureFreshServerCatalog(backend, [table], {
      ...configuration, session: { ...configuration.session, expiresIn: input.expiresIn },
      rateLimit: { enabled: false }, plugins: [testUtils()],
    }, context => observeSession(context, configuration));
    cases.push({ name, configuration, ...observation });
  }
  // Preserve the complete JSON document after checking each generated identity and timestamp relationship.
  return json({ version, database: backend, input, cases });
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the second argument");
  writeFileSync(output, `${JSON.stringify(await captureSessionServer(backend), null, 2)}\n`);
}
