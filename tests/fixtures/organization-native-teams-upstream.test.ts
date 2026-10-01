import { afterAll, test } from "bun:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Database } from "bun:sqlite";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { createAuthMiddleware } = await import(`${modules}/better-auth/dist/api/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);
const secret = "native-team-contract-secret-at-least-thirty-two";
const observations: any[] = [];
const teamValue = (team: any) => ({ name: team.name, organizationId: team.organizationId, label: team.label });

for (const backend of ["memory", "sqlite"]) for (const mode of ["trusted", "owner"]) {
  test(`${backend}: ${mode} native team lifecycle`, async () => {
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const events: any[] = [];
    let createdId = "";
    const bodyValue = (body: any) => body?.teamId === createdId ? { ...body, teamId: "created" } : body;
    const event = (phase: string, data: any) => events.push({ phase, user: data.user?.id ?? null, team: teamValue(data.team) });
    const options = { database, baseURL: "http://localhost:3000", secret,
      logger: { disabled: true }, rateLimit: { enabled: false },
      hooks: {
        before: createAuthMiddleware(async (ctx: any) => { events.push({ phase: "before", path: ctx.path, body: bodyValue(ctx.body) }); }),
        after: createAuthMiddleware(async (ctx: any) => { events.push({ phase: "after", path: ctx.path, body: bodyValue(ctx.body) }); }),
      },
      plugins: [organization({
        teams: { enabled: true, maximumTeams: async ({ organizationId, session }: any) => {
          events.push({ phase: "limit", organizationId, user: session?.user.id ?? null });
          return 100;
        } },
        schema: { team: { additionalFields: { label: { type: "string", required: false,
          transform: { input: (value: any) => `${value}:in`, output: (value: any) => `${value}:out` },
        } } } },
        organizationHooks: {
          beforeCreateTeam: async (data: any) => {
            event("create-before", data);
            return { data: { name: `${data.team.name}:hook`, label: `${data.team.label}:hook` } };
          },
          afterCreateTeam: async (data: any) => { event("create-after", data); },
          beforeDeleteTeam: async (data: any) => { event("delete-before", data); },
          afterDeleteTeam: async (data: any) => { event("delete-after", data); },
        },
      })],
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const ctx = await auth.$context;
    const now = new Date("2025-01-01T00:00:00Z");
    const create = (model: string, data: any) => ctx.adapter.create({ model, forceAllowId: true, data: { createdAt: now, updatedAt: now, ...data } });
    try {
      await create("user", { id: "owner", name: "Owner", email: "owner@example.test", emailVerified: true });
      await create("organization", { id: "org", name: "Organization", slug: "organization" });
      await create("member", { id: "membership", organizationId: "org", userId: "owner", role: "owner" });
      await create("team", { id: "existing", organizationId: "org", name: "Existing", label: "seed" });
      await create("session", { id: "session", userId: "owner", token: "owner-token", expiresAt: new Date("2099-01-01T00:00:00Z"), activeOrganizationId: "org" });
      const signature = createHmac("sha256", secret).update("owner-token").digest("base64");
      const source = mode === "owner" ? { headers: new Headers({ cookie: `better-auth.session_token=${encodeURIComponent(`owner-token.${signature}`)}` }) } : {};
      const body = { name: "New", label: "sent", ignored: true, ...(mode === "trusted" ? { organizationId: "org" } : {}) };
      events.length = 0;
      const created = await auth.api.createTeam({ ...source, body });
      assert.equal(typeof created.id, "string");
      assert(created.id.length > 0);
      assert(created.createdAt instanceof Date);
      assert(created.updatedAt instanceof Date);
      createdId = created.id;
      const stored = await ctx.adapter.findOne({ model: "team", where: [{ field: "id", value: createdId }] });
      const projected = { name: "New:hook", organizationId: "org", label: "sent:hook:in:out" };
      assert.deepEqual(teamValue(created), projected);
      assert.deepEqual(teamValue(stored), projected);
      await create("invitation", { id: "invitation", organizationId: "org", email: "invitee@example.test", role: "member", status: "pending", inviterId: "owner", expiresAt: new Date("2099-01-01T00:00:00Z"), teamId: `${createdId},existing` });
      const removed = await auth.api.removeTeam({ ...source, body: { teamId: createdId, ...(mode === "trusted" ? { organizationId: "org" } : {}) } });
      assert.deepEqual(removed, { message: "Team removed successfully." });
      const remaining = await ctx.adapter.findMany({ model: "team" });
      assert.deepEqual(remaining.map((team: any) => team.name), ["Existing"]);
      const invitation = await ctx.adapter.findOne({ model: "invitation", where: [{ field: "id", value: "invitation" }] });
      assert.equal(invitation.teamId, "existing");
      const user = mode === "owner" ? "owner" : null;
      const removeBody = { teamId: "created", ...(mode === "trusted" ? { organizationId: "org" } : {}) };
      assert.deepEqual(events, [
        { phase: "before", path: "/organization/create-team", body },
        { phase: "limit", organizationId: "org", user },
        { phase: "create-before", user, team: { name: "New", organizationId: "org", label: "sent" } },
        { phase: "create-after", user, team: projected },
        { phase: "after", path: "/organization/create-team", body },
        { phase: "before", path: "/organization/remove-team", body: removeBody },
        { phase: "delete-before", user, team: projected },
        { phase: "delete-after", user, team: projected },
        { phase: "after", path: "/organization/remove-team", body: removeBody },
      ]);
      observations.push({ backend, mode, created: teamValue(created), stored: teamValue(stored), removed, remaining: remaining.map((team: any) => team.name), invitationTeam: invitation.teamId, events });
    } finally { database?.close(); }
  });
}

test("request-bearing team lifecycle calls still require a session", async () => {
  const auth = betterAuth({ baseURL: "http://localhost:3000", secret,
    logger: { disabled: true }, rateLimit: { enabled: false },
    plugins: [organization({ teams: { enabled: true } })],
  });
  for (const [method, path, body] of [
    ["createTeam", "/organization/create-team", { name: "New", organizationId: "org" }],
    ["removeTeam", "/organization/remove-team", { teamId: "team", organizationId: "org" }],
  ] as const) {
    for (const source of [{ headers: new Headers() }, { request: new Request("http://localhost:3000/source") }]) {
      const response = await auth.api[method]({ ...source, body, asResponse: true });
      assert.equal(response.status, 401);
      assert.equal(await response.text(), "");
    }
    const response = await auth.handler(new Request(`http://localhost:3000/api/auth${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    }));
    assert.equal(response.status, 401);
    assert.equal(await response.text(), "");
  }
});

afterAll(async () => {
  if (process.env.NATIVE_TEAMS_OUTPUT) await Bun.write(process.env.NATIVE_TEAMS_OUTPUT, `${JSON.stringify(observations, null, 2)}\n`);
});
