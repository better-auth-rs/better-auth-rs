import { afterAll, test } from "bun:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Database } from "bun:sqlite";
import expectedObservations from "./organization-lists-upstream.json";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { getOrgAdapter } = await import(`${modules}/better-auth/dist/plugins/organization/adapter.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);
const secret = "organization-list-contract-secret-at-least-thirty-two";
const observations: any[] = [];

async function fixture(backend: string, limit?: number) {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: string[] = [];
  const field = (kind: string, required = true) => ({ type: "string", required,
    transform: { output(value: any) { events.push(`${kind}:${value}`); return value; } } });
  const plugin = { teams: { enabled: true }, dynamicAccessControl: { enabled: true }, schema: {
    organization: { additionalFields: { name: field("organization") } },
    member: { additionalFields: { role: field("member") } },
    team: { additionalFields: { name: field("team") } },
    invitation: { additionalFields: { role: field("invitation", false) } },
    organizationRole: { additionalFields: { role: field("role") } },
  } };
  const options = { database, secret, baseURL: "http://localhost:3000",
    logger: { disabled: true }, rateLimit: { enabled: false },
    advanced: { database: { defaultFindManyLimit: limit } },
    user: { additionalFields: { username: field("user", false) } },
    plugins: [organization(plugin)],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const ctx = await auth.$context;
  const adapter = getOrgAdapter(ctx, plugin);
  const now = new Date("2025-01-01T00:00:00Z");
  const create = (model: string, data: any) => ctx.adapter.create({ model, forceAllowId: true,
    data: { createdAt: now, updatedAt: now, ...data } });
  for (const name of ["alice", "bob", "carol"]) await create("user", {
    id: name, name, username: name, email: `${name}@example.test`, emailVerified: true,
  });
  for (const suffix of ["a", "b"]) {
    await create("organization", { id: `org-${suffix}`, name: `org-${suffix}`, slug: `org-${suffix}` });
    await create("member", { id: `member-${suffix}`, organizationId: `org-${suffix}`, userId: "alice", role: "owner" });
  }
  await create("member", { id: "member-bob", organizationId: "org-a", userId: "bob", role: "member" });
  for (const suffix of ["a", "b"]) await create("team", {
    id: `team-${suffix}`, name: `team-${suffix}`, organizationId: "org-a",
    memberCount: suffix === "a" ? 1 : 2,
  });
  for (const [teamId, userId] of [["team-b", "alice"], ["team-a", "alice"], ["team-b", "bob"]])
    await create("teamMember", { id: `${teamId}-${userId}`, teamId, userId, membershipKey: `${teamId}-${userId}` });
  for (const [id, status, role, expiresAt] of [
    ["accepted", "accepted", "member", "2099-01-01T00:00:00Z"],
    ["expired", "pending", "admin", "2020-01-01T00:00:00Z"],
    ["fresh", "pending", "member", "2099-01-01T00:00:00Z"],
  ]) await create("invitation", { id, status, role, expiresAt: new Date(expiresAt), organizationId: "org-a", email: "carol@example.test", inviterId: "alice" });
  for (const role of ["first", "second"]) await create("organizationRole", {
    id: role, organizationId: "org-a", role, permission: "{}",
  });
  for (const userId of ["alice", "carol"]) await create("session", {
    userId, token: `${userId}-session`, expiresAt: new Date("2099-01-01T00:00:00Z"), activeOrganizationId: "org-a",
  });
  const headers = (name: string) => {
    const token = `${name}-session`;
    const signature = createHmac("sha256", secret).update(token).digest("base64");
    return new Headers({ cookie: `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}` });
  };
  events.length = 0;
  return { auth, ctx, adapter, events, headers, close: () => database?.close() };
}

for (const backend of ["memory", "sqlite"]) for (const limit of [undefined, 1, 2]) {
  test(`${backend}: organization pages and normal associations at limit ${limit}`, async () => {
    const f = await fixture(backend, limit);
    const output: any = { backend, limit: limit ?? null, operations: {} };
    const capture = async (name: string, run: () => Promise<any>, project: (value: any) => any) => {
      f.events.length = 0;
      const result = project(await run());
      output.operations[name] = { result, events: [...f.events] };
      return result;
    };
    const page = <T>(values: T[]) => values.slice(0, limit ?? values.length);
    try {
      assert.deepEqual(await capture("organizations", () => f.adapter.listOrganizations("alice"), rows => rows.map((r: any) => r.name)), page(["org-a", "org-b"]));
      assert.deepEqual(await capture("teams", () => f.adapter.listTeams("org-a"), rows => rows.map((r: any) => r.name)), page(["team-a", "team-b"]));
      assert.deepEqual(await capture("userTeams", () => f.adapter.listTeamsByUser({ userId: "alice" }), rows => rows.map((r: any) => r.name)), page(["team-b", "team-a"]));
      assert.deepEqual(await capture("teamMembers", () => f.adapter.listTeamMembers({ teamId: "team-b" }), rows => rows.map((r: any) => r.userId)), page(["alice", "bob"]));
      assert.deepEqual(await capture("roles", () => f.ctx.adapter.findMany({ model: "organizationRole", where: [{ field: "organizationId", value: "org-a" }] }), rows => rows.map((r: any) => r.role)), page(["first", "second"]));
      assert.deepEqual(await capture("invitations", () => f.adapter.listInvitations({ organizationId: "org-a" }), rows => rows.map((r: any) => r.id)), page(["accepted", "expired", "fresh"]));
      const received = await capture("received", () => f.auth.api.listUserInvitations({ headers: f.headers("carol") }), rows => rows.map((r: any) => ({ id: r.id, name: r.organizationName })));
      assert.deepEqual(received, page(["accepted", "expired", "fresh"]).filter(id => id !== "accepted").map(id => ({ id, name: "org-a" })));
      const full = await capture("full", () => f.auth.api.getFullOrganization({ headers: f.headers("alice"), query: { organizationId: "org-a" } }), row => ({ name: row.name, members: row.members.map((r: any) => r.user.username ?? r.user.name), invitations: row.invitations.map((r: any) => r.id), teams: row.teams.map((r: any) => r.name) }));
      assert.deepEqual(full, { name: "org-a", members: page(["alice", "bob"]), invitations: page(["accepted", "expired", "fresh"]), teams: page(["team-a", "team-b"]) });
      const phases = output.operations.full.events;
      assert(phases.indexOf("organization:org-a") < phases.indexOf("invitation:member"));
      assert(phases.lastIndexOf("invitation:member") < phases.indexOf("team:team-a"));
      assert(phases.indexOf("team:team-a") < phases.lastIndexOf("user:alice"));
      await capture("fullSlug", () => f.auth.api.getFullOrganization({ headers: f.headers("alice"), query: { organizationSlug: "org-a" } }), row => ({ name: row.name, members: row.members.map((r: any) => r.user.username ?? r.user.name), invitations: row.invitations.map((r: any) => r.id), teams: row.teams.map((r: any) => r.name) }));
      assert.deepEqual(output.operations.fullSlug, output.operations.full);
      const expected = expectedObservations.find(row => row.backend === backend && row.limit === (limit ?? null));
      assert.deepEqual(output, expected);
      observations.push(output);
      console.log(JSON.stringify(output));
    } finally { f.close(); }
  });
}

afterAll(async () => {
  if (process.env.ORGANIZATION_LISTS_OUTPUT) await Bun.write(process.env.ORGANIZATION_LISTS_OUTPUT, `${JSON.stringify(observations, null, 2)}\n`);
});
