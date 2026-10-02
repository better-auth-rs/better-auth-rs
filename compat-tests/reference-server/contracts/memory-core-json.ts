import { notEqual, ok } from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";
import { getOrgAdapter } from "better-auth/plugins/organization";

const organizationModels = ["organization", "member", "invitation", "team", "organizationRole"] as const;
const aliases = {
  settings: "stored_settings",
  nullableSettings: "stored_nullable_settings",
  encodedSettings: "stored_encoded_settings",
  labels: "stored_labels",
  displayOrder: "stored_display_order",
} as const;
type Field = keyof typeof aliases;
type Row = Record<string, any>;
type Operation = { name: string; events: unknown[]; result: unknown; storedPhysical: unknown[] };
const names = Object.keys(aliases) as Field[];
const instant = () => new Date("2030-01-01T00:00:00Z");

const input = (label: string, updated = false) => ({
  settings: { label },
  nullableSettings: null,
  encodedSettings: updated ? '{"kind":"updated"}' : '{"kind":"text"}',
  labels: updated ? ["updated"] : ["alpha", "beta"],
  displayOrder: updated ? [3] : [1, 2],
});

const display = (row: Row | null | undefined) => {
  ok(row, "Expected the ordinary display record");
  return Object.fromEntries(names.map((name) => {
    ok(Object.hasOwn(row, name), `Expected declared field ${name}`);
    notEqual(row[name], undefined, `Expected supplied field ${name}`);
    return [name, row[name]];
  }));
};

export async function captureMemoryCoreJson() {
  const memory: Record<string, Row[]> = Object.fromEntries([
    "user", "session", "account", "verification", ...organizationModels, "teamMember",
  ].map((model) => [model, []]));
  const events: unknown[] = [];
  const types: Record<Field, "json" | "string[]" | "number[]"> = {
    settings: "json", nullableSettings: "json", encodedSettings: "json",
    labels: "string[]", displayOrder: "number[]",
  };
  const fields = (model: string) => Object.fromEntries(names.map((name) => [name, {
    type: types[name], required: false, fieldName: aliases[name],
    transform: {
      input(value: unknown) {
        notEqual(value, undefined, `Expected supplied input field ${model}.${name}`);
        events.push(["input", model, name, value]);
        return value;
      },
      output(value: unknown) {
        notEqual(value, undefined, `Expected stored output field ${model}.${name}`);
        events.push(["output", model, name, value]);
        return value;
      },
    },
  }]));
  const options = {
    teams: { enabled: true },
    dynamicAccessControl: { enabled: true },
    schema: Object.fromEntries(organizationModels.map((model) => [model, { additionalFields: fields(model) }])),
  };
  let nextId = 1;
  const context = await betterAuth({
    baseURL: "http://memory-core-json.test",
    secret: "ordinary-memory-core-json-secret-at-least-32-characters",
    database: memoryAdapter(memory),
    advanced: { database: { generateId: () => String(nextId++), joins: true } },
    user: { additionalFields: fields("user") },
    session: { additionalFields: fields("session") },
    logger: { disabled: true },
    telemetry: { enabled: false },
    plugins: [organization(options)],
  }).$context;
  const { adapter, internalAdapter } = context;
  const org = getOrgAdapter(context, options);
  const storedPhysical = (model: string, result: Row) => {
    const row = memory[model].find((row) => row.id === result.id);
    ok(row, "Expected the raw ordinary display record");
    return { model, fields: Object.fromEntries(names.map((name) => {
      const alias = aliases[name];
      ok(Object.hasOwn(row, alias), `Expected physical field ${alias}`);
      notEqual(row[alias], undefined, `Expected stored field ${alias}`);
      return [alias, row[alias]];
    })) };
  };
  const observe = (operations: Operation[], name: string, result: unknown, rows: [string, Row][]) => {
    operations.push({
      name, events: events.splice(0), result,
      storedPhysical: rows.map(([model, row]) => storedPhysical(model, row)),
    });
  };

  const userOperations: Operation[] = [];
  const userA = await internalAdapter.createUser({
    name: "Display User A", email: "user-a@memory-core-json.test", ...input("user-a"),
  }, { method: "ordinary-display" });
  observe(userOperations, "create-a", display(userA), [["user", userA]]);
  const userB = await internalAdapter.createUser({
    name: "Display User B", email: "user-b@memory-core-json.test", ...input("user-b"),
  }, { method: "ordinary-display" });
  observe(userOperations, "create-b", display(userB), [["user", userB]]);
  const updatedUser = await internalAdapter.updateUser(userA.id, input("user-a-updated", true));
  observe(userOperations, "update-a", display(updatedUser), [["user", userA]]);
  const readUser = await internalAdapter.findUserById(userA.id);
  observe(userOperations, "read-a", display(readUser), [["user", userA]]);

  const sessionOperations: Operation[] = [];
  const sessionA = await internalAdapter.createSession(userA.id, false, input("session-a"));
  observe(sessionOperations, "create-a", display(sessionA), [["session", sessionA]]);
  const sessionB = await internalAdapter.createSession(userA.id, false, input("session-b"));
  observe(sessionOperations, "create-b", display(sessionB), [["session", sessionB]]);
  const updatedSession = await internalAdapter.updateSession(sessionA.token, input("session-a-updated", true));
  observe(sessionOperations, "update-a", display(updatedSession), [["session", sessionA]]);
  const sessions = await internalAdapter.listSessions(userA.id, { onlyActiveSessions: false });
  observe(sessionOperations, "list", sessions.map(display), [["session", sessionA], ["session", sessionB]]);

  const snapshotOperations: Operation[] = [];
  const create = async (model: string, label: string, data: Row) => {
    const row = await adapter.create<Row>({ model, data: { ...data, ...input(label) } });
    observe(snapshotOperations, `create-${label}`, display(row), [[model, row]]);
    return row;
  };
  const organizationA = await create("organization", "organization-a", {
    name: "Display Organization A", slug: "display-organization-a", createdAt: instant(),
  });
  const organizationB = await create("organization", "organization-b", {
    name: "Display Organization B", slug: "display-organization-b", createdAt: instant(),
  });
  const memberAA = await create("member", "member-a-a", {
    organizationId: organizationA.id, userId: userA.id, role: "member", createdAt: instant(),
  });
  const memberBA = await create("member", "member-b-a", {
    organizationId: organizationA.id, userId: userB.id, role: "member", createdAt: instant(),
  });
  const memberAB = await create("member", "member-a-b", {
    organizationId: organizationB.id, userId: userA.id, role: "member", createdAt: instant(),
  });
  const team = await create("team", "team", {
    organizationId: organizationA.id, name: "Display Team", memberCount: 0, createdAt: instant(),
  });
  const invitation = await create("invitation", "invitation", {
    organizationId: organizationA.id, inviterId: userA.id, email: "invitee@memory-core-json.test",
    role: "member", status: "pending", expiresAt: new Date("2100-01-01T00:00:00Z"), createdAt: instant(),
  });
  const role = await create("organizationRole", "role", {
    organizationId: organizationA.id, role: "viewer", permission: "{}", createdAt: instant(),
  });
  for (const [model, label, row] of [
    ["organization", "organization", organizationA], ["member", "member", memberAA],
    ["team", "team", team], ["invitation", "invitation", invitation], ["organizationRole", "role", role],
  ] as [string, string, Row][]) {
    const read = await adapter.findOne<Row>({ model, where: [{ field: "id", value: row.id }] });
    observe(snapshotOperations, `read-${label}`, display(read), [[model, row]]);
  }

  const joinedQueryOperations: Operation[] = [];
  const organizations = await org.listOrganizations(userA.id);
  observe(joinedQueryOperations, "list-for-user-a", organizations.map(display), [
    ["member", memberAA], ["member", memberAB], ["organization", organizationA], ["organization", organizationB],
  ]);
  const filtered = await org.listMembers({
    organizationId: organizationA.id, limit: 10, offset: 0,
    filter: { field: "settings", value: { label: "member-a-a" }, operator: "eq" },
  });
  observe(joinedQueryOperations, "filter-members", { rows: filtered.members.map(display), total: filtered.total }, [
    ["member", memberAA], ["member", memberBA],
  ]);

  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    groups: [
      { name: "user", operations: userOperations },
      { name: "session", operations: sessionOperations },
      { name: "organization-snapshot", operations: snapshotOperations },
      { name: "organization-joined-query", operations: joinedQueryOperations },
    ],
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureMemoryCoreJson(), null, 2));
