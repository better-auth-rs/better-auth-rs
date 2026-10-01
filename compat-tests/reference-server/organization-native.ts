import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { organization } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAdapter, getCurrentAuthEndpointContext, runWithTransaction } from "@better-auth/core/context";
import { Database } from "bun:sqlite";

export async function organizationNativeCase(backend: string, mode: string) {
  const events: any[] = [];
  const absent = (value: any) => value === undefined ? { $undefined: true } : value;
  const project = (value: any): any => {
    if (value === undefined) return { $undefined: true };
    if (Array.isArray(value)) return value.map(project);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([key]) => !["id", "createdAt", "updatedAt"].includes(key)).map(([key, item]) => [key, project(item)]));
    return value;
  };
  const record = (phase: string, ctx: any) => events.push({ phase, path: absent(ctx.path), ambient: absent(getCurrentAuthEndpointContext()?.path), body: absent(ctx.body) });
  let active = false;
  const error = () => new APIError("FORBIDDEN", { code: "FIXTURE_REJECTED", message: "fixture rejected" });
  const options: any = {
    baseURL: "http://localhost:3000", secret: "organization-native-fixture-secret-long-enough", logger: { disabled: true }, rateLimit: { enabled: false },
    database: backend === "sqlite" ? new Database(":memory:") : undefined,
    advanced: { database: { defaultFindManyLimit: mode === "limit" ? 1 : 100, generateId: (() => { let next = 0; return ({ model }: any) => `${model}-${++next}`; })() } },
    hooks: {
      before: createAuthMiddleware(async ctx => {
        record("before", ctx);
        if (mode === "before-error") throw error();
        if (mode === "stop") return ctx.json({ stopped: true });
        if (mode === "patch") return { context: { body: { role: "admin", label: "patched", ignored: "still unknown" } } };
      }),
      after: createAuthMiddleware(async ctx => {
        record("after", ctx);
        if (mode === "replace") return ctx.json({ replaced: true });
        if (mode === "after-error") throw error();
      }),
    },
    plugins: [organization({
      membershipLimit: mode === "limit" ? 2 : async (_user: any, _organization: any) => { events.push({ phase: "limit" }); if (mode === "policy-error") throw error(); return 100; },
      teams: { enabled: mode !== "team-disabled", ...(["team-limit", "tx-team-catch", "team-reassign", "tx-team-reassign"].includes(mode) ? { maximumMembersPerTeam: 0 } : {}), ...(mode === "team-dynamic-limit" ? { maximumMembersPerTeam: async () => 1 } : {}) },
      schema: { member: { additionalFields: {
        label: { type: "string", required: false, defaultValue: "default", transform: { input: (v: any) => `${v}:in`, output: (v: any) => `${v}:out` } },
        secret: { type: "string", required: false, input: false, returned: false, defaultValue: "hidden" },
        ...(mode === "override" ? { role: { type: "string", required: true } } : {}),
        ...(mode === "org-number" ? { organizationId: { type: "number", required: true } } : {}),
      } } },
      organizationHooks: {
        beforeAddMember: async ({ member }: any) => { events.push({ phase: "member-before", member: project(member), ambient: absent(getCurrentAuthEndpointContext()?.path) }); if (mode === "member-error") throw error(); return { data: { label: `${member.label ?? "default"}:hook`, ...(mode.endsWith("reassign") ? { userId: "owner" } : {}) } }; },
        afterAddMember: async ({ member }: any) => { events.push({ phase: "member-after", member: project(member), ambient: absent(getCurrentAuthEndpointContext()?.path) }); },
      },
    })],
  };
  if (options.database) { const migration = await getMigrations(options); await migration.runMigrations(); }
  const auth = betterAuth(options);
  const ctx = await auth.$context;
  const now = new Date();
  const seedUser = async (id: string) => (await getCurrentAdapter(ctx.adapter)).create({ model: "user", forceAllowId: true, data: { id, name: id, email: `${id}@example.com`, emailVerified: true, createdAt: now, updatedAt: now } });
  await seedUser("owner");
  if (!mode.startsWith("tx-")) await seedUser("target");
  await ctx.adapter.create({ model: "organization", forceAllowId: true, data: { id: "org", name: "Org", slug: "org", createdAt: now } });
  await ctx.adapter.create({ model: "member", forceAllowId: true, data: { id: "owner-member", organizationId: "org", userId: "owner", role: "owner", createdAt: now } });
  if (mode === "limit") { await seedUser("other"); await ctx.adapter.create({ model: "member", data: { organizationId: "org", userId: "other", role: "member", createdAt: now } }); }
  if (mode === "duplicate") await ctx.adapter.create({ model: "member", data: { organizationId: "org", userId: "target", role: "member", createdAt: now } });
  if (mode !== "team-disabled") await ctx.adapter.create({ model: "team", forceAllowId: true, data: { id: "team", organizationId: "org", name: "Team", createdAt: now } });
  if (mode.endsWith("reassign")) await ctx.adapter.create({ model: "teamMember", data: { userId: "owner", teamId: "team", createdAt: now } });
  const count = ctx.adapter.count.bind(ctx.adapter);
  ctx.adapter.count = async (input: any) => { if (active) events.push({ phase: "count", model: input.model }); return count(input); };
  const body: any = { userId: "target", organizationId: mode === "missing-org" ? "missing" : "org", role: mode === "override" ? ["member"] : ["member", "admin"], label: "sent", secret: "forged", unknown: true };
  if (mode.startsWith("team")) body.teamId = "team";
  if (mode.startsWith("tx-team")) body.teamId = "team";
  if (mode === "org-number") body.organizationId = 42;
  if (mode === "invalid") delete body.role;
  events.length = 0; active = true;
  const invoke = async () => (auth.api as any).addMember({ body });
  let output: any;
  try {
    const result = mode.startsWith("tx-") ? await runWithTransaction(ctx.adapter, async () => {
      await seedUser("target");
      let result: any;
      try { result = await invoke(); }
      catch (cause: any) { if (!["tx-team-catch", "tx-team-reassign"].includes(mode)) throw cause; result = { caught: cause.body.code }; }
      events.push({ phase: "transaction", members: await (await getCurrentAdapter(ctx.adapter)).count({ model: "member", where: [{ field: "userId", value: "target" }] }) });
      if (mode === "tx-rollback" || mode === "tx-team-rollback") throw new Error("rollback requested");
      return result;
    }) : await invoke();
    output = { result: project(result) };
  } catch (cause: any) {
    output = { error: cause.name === "APIError" ? { status: typeof cause.status === "number" ? cause.status : cause.statusCode, body: cause.body } : { message: cause.message } };
  }
  active = false;
  const members = await ctx.adapter.findMany({ model: "member", where: [{ field: "userId", value: "target" }], limit: 1000 });
  const teams = mode === "team-disabled" ? 0 : await ctx.adapter.count({ model: "teamMember", where: [{ field: "userId", value: "target" }] });
  const ownerTeams = mode.endsWith("reassign") ? await ctx.adapter.count({ model: "teamMember", where: [{ field: "userId", value: "owner" }] }) : undefined;
  options.database?.close();
  return { ...output, events, members: project(members), teams, ...(ownerTeams === undefined ? {} : { ownerTeams }) };
}
