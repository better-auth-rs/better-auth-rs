import { Database } from "bun:sqlite";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { getOrgAdapter } = await import(`${modules}/better-auth/dist/plugins/organization/adapter.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);
const { APIError } = await import(`${modules}/better-auth/dist/api/index.mjs`);

type Path = "member-org" | "member-id" | "full" | "organizations" | "team-members" | "teams" | "invitations";
type Mode = "sync" | "parent-read" | "child-read" | "parent-wait" | "child-wait" | "parent-error" | "child-error";
type Case = { path: Path; mode: Mode; limit?: number; membersLimit?: number; includeTeams?: boolean; unconfiguredLogo?: boolean };
export const cases: Case[] = [
  ...(["member-org", "member-id", "full", "organizations", "team-members", "teams", "invitations"] as Path[])
    .map(path => ({ path, mode: "sync" as const, limit: 2 })),
  { path: "full", mode: "sync", limit: 1, membersLimit: 2, includeTeams: false },
  { path: "full", mode: "sync", limit: 2, membersLimit: 1 },
  ...(["member-org", "full", "organizations", "invitations"] as Path[])
    .map(path => ({ path, mode: "parent-read" as const, limit: 2 })),
  { path: "full", mode: "child-read", limit: 2 },
  { path: "teams", mode: "child-read", limit: 2 },
  ...(["organizations", "invitations"] as Path[])
    .map(path => ({ path, mode: "parent-wait" as const, limit: 2 })),
  ...(["full", "teams"] as Path[])
    .map(path => ({ path, mode: "child-wait" as const, limit: 2 })),
  ...(["member-org", "full", "organizations", "invitations"] as Path[])
    .map(path => ({ path, mode: "parent-error" as const, limit: 2 })),
  ...(["member-id", "full", "teams"] as Path[])
    .map(path => ({ path, mode: "child-error" as const, limit: 2 })),
];

export async function capture(backend: string, joins: boolean, spec: Case) {
  const { path, mode } = spec;
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: unknown[] = [];
  const blocked = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const peerFinished = Promise.withResolvers<void>();
  let enabled = false;
  let changed = false;
  let adapter: any;
  let sequence = 0;
  const failure = new APIError("BAD_REQUEST", {
    code: "ORDINARY_ORGANIZATION_DISPLAY_FAILURE", message: "Ordinary display callback failed",
  });
  const parent = spec.unconfiguredLogo ? ["organization.name", "O-A"] : path === "full" ? ["organization.name", "O-A"]
    : path === "invitations" ? ["invitation.label", "I-A"]
    : ["member.label", "M-A"];
  const child = path === "full" ? ["invitation.label", "I-A"]
    : path === "teams" ? ["team.name", "T-A"]
    : ["user.name", "U-A"];
  const isParent = (field: string, value: unknown) => field === parent[0] && value === parent[1];
  const isChild = (field: string, value: unknown) => field === child[0] && value === child[1];
  const isList = path === "organizations" || path === "invitations" || path === "teams";

  async function updateDisplay(childPhase: boolean) {
    changed = true;
    const update = childPhase
      ? path === "teams" ? { model: "team", id: "team-b", data: { label: "T-B-label-after" } }
        : { model: "invitation", id: "invitation-a-other", data: { detail: "I-A2-detail-after" } }
      : path === "full" ? { model: "invitation", id: "invitation-a", data: { detail: "I-A-detail-after" } }
        : path === "member-org" ? { model: "user", id: "user-a", data: { image: "U-A-image-after" } }
          : { model: "organization", id: "organization-a", data: { logo: "O-A-logo-after" } };
    await adapter.update({ model: update.model, where: [{ field: "id", value: update.id }], update: update.data });
    events.push(["display-write", update.model, update.data]);
  }
  function field(model: string, key: string) {
    const name = `${model}.${key}`;
    return { type: "string", required: false, transform: { output(value: unknown) {
      if (!enabled) return value;
      events.push([name, value]);
      const visible = () => mode === "sync" ? `${value}:${++sequence}` : `${value}-visible`;
      if (name === "organization.logo" && value === "O-B-logo"
          || name === "team.label" && value === "T-B-label") peerFinished.resolve();
      if (mode === "parent-error" && isParent(name, value)
          || mode === "child-error" && isChild(name, value)) throw failure;
      if (mode === "parent-wait" && isParent(name, value)
          || mode === "child-wait" && isChild(name, value)) {
        blocked.resolve();
        return release.promise.then(visible);
      }
      if (!changed && (mode === "parent-read" && isParent(name, value)
          || mode === "child-read" && isChild(name, value))) {
        return updateDisplay(mode === "child-read").then(visible);
      }
      return visible();
    } } };
  }
  const plugin = {
    teams: { enabled: true },
    schema: {
      organization: { additionalFields: { name: field("organization", "name"), ...(!spec.unconfiguredLogo ? { logo: field("organization", "logo") } : {}) } },
      member: { additionalFields: { label: field("member", "label"), detail: field("member", "detail") } },
      invitation: { additionalFields: { label: field("invitation", "label"), detail: field("invitation", "detail") } },
      team: { additionalFields: { name: field("team", "name"), label: field("team", "label") } },
    },
  };
  const options = {
    database, baseURL: "http://ordinary-native-org.test",
    secret: "ordinary-native-organization-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
    advanced: { database: { joins, defaultFindManyLimit: spec.limit } },
    user: { additionalFields: { name: field("user", "name"), image: field("user", "image") } },
    plugins: [organization(plugin)],
  };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const context = await betterAuth(options).$context;
    adapter = context.adapter;
    const org = getOrgAdapter(context, plugin);
    const createdAt = new Date("2025-01-01T00:00:00.000Z");
    const create = (model: string, data: object) => adapter.create({
      model, forceAllowId: true, data: { createdAt, updatedAt: createdAt, ...data },
    });
    for (const label of ["A", "B"]) {
      const suffix = label.toLowerCase();
      await create("user", { id: `user-${suffix}`, name: `U-${label}`, image: `U-${label}-image`,
        email: `${suffix}@ordinary-native-org.test`, emailVerified: true });
      await create("organization", { id: `organization-${suffix}`, name: `O-${label}`,
        slug: `ordinary-${suffix}`, logo: `O-${label}-logo` });
      await create("member", { id: `member-${suffix}`, organizationId: `organization-${suffix}`,
        userId: "user-a", role: "member", label: `M-${label}`, detail: `M-${label}-detail` });
      await create("team", { id: `team-${suffix}`, organizationId: "organization-a",
        name: `T-${label}`, label: `T-${label}-label`, memberCount: 1 });
      await create("teamMember", { id: `team-member-${suffix}`, teamId: `team-${suffix}`, userId: "user-a",
        membershipKey: `ordinary-team-member-${suffix}` });
      await create("invitation", { id: `invitation-${suffix}`, organizationId: `organization-${suffix}`,
        email: "recipient@ordinary-native-org.test", role: "member", status: "pending", inviterId: "user-a",
        expiresAt: new Date("2099-01-01T00:00:00.000Z"), label: `I-${label}`, detail: `I-${label}-detail` });
    }
    await create("member", { id: "member-a-other", organizationId: "organization-a", userId: "user-b",
      role: "member", label: "M-A2", detail: "M-A2-detail" });
    await create("invitation", { id: "invitation-a-other", organizationId: "organization-a",
      email: "other@ordinary-native-org.test", role: "member", status: "pending", inviterId: "user-a",
      expiresAt: new Date("2099-01-01T00:00:00.000Z"), label: "I-A2", detail: "I-A2-detail" });
    await create("teamMember", { id: "team-member-a-other", teamId: "team-a", userId: "user-b",
      membershipKey: "ordinary-team-member-a-other" });

    const user = (row: any) => ({ name: row.name, image: row.image });
    const member = (row: any) => ({ label: row.label, detail: row.detail, user: user(row.user) });
    const organizationDisplay = (row: any) => ({ name: row.name, logo: row.logo });
    const team = (row: any) => ({ name: row.name, label: row.label });
    async function query() {
      if (path === "member-org") return member(await org.findMemberByOrgId({ organizationId: "organization-a", userId: "user-a" }));
      if (path === "member-id") return member(await org.findMemberById("member-a"));
      if (path === "organizations") return (await org.listOrganizations("user-a")).map(organizationDisplay);
      if (path === "teams") return (await org.listTeamsByUser({ userId: "user-a" })).map(team);
      if (path === "invitations") return (await org.listUserInvitations("RECIPIENT@ordinary-native-org.test"))
        .map((row: any) => ({ label: row.label, detail: row.detail, organizationName: row.organizationName }));
      if (path === "team-members") {
        const row = await org.findTeamById({ teamId: "team-a", organizationId: "organization-a", includeTeamMembers: true });
        return { ...team(row), members: row.members.map((member: any) => ({ userId: member.userId, hasMembershipKey: "membershipKey" in member })) };
      }
      const row = await org.findFullOrganization({ organizationId: "organization-a", includeTeams: spec.includeTeams ?? true, membersLimit: spec.membersLimit });
      return { ...organizationDisplay(row),
        invitations: row.invitations.map((row: any) => ({ label: row.label, detail: row.detail })),
        members: row.members.map(member), teams: row.teams?.map(team) ?? null };
    }
    enabled = true;
    let originalError = false;
    const pending = query().then(result => ({ result })).catch((error: any) => {
      if (error !== failure) throw error;
      originalError = true;
      return { error: { status: error.status, code: error.body?.code, message: error.body?.message } };
    });
    if (mode === "parent-wait" || mode === "child-wait") {
      await blocked.promise;
      if (isList) await peerFinished.promise;
      events.push(["controller", isList ? "peer-finished" : "first-child-blocked"]);
      release.resolve();
    }
    const outcome = await pending;
    if (isList && (mode === "parent-error" || mode === "child-error")) await peerFinished.promise;
    enabled = false;
    const stored = {
      organizations: (await adapter.findMany({ model: "organization", limit: 10, sortBy: { field: "slug", direction: "asc" } })).map(organizationDisplay),
      teams: (await adapter.findMany({ model: "team", limit: 10, sortBy: { field: "id", direction: "asc" } })).map(team),
      invitations: (await adapter.findMany({ model: "invitation", limit: 10, sortBy: { field: "id", direction: "asc" } })).map((row: any) => ({ label: row.label, detail: row.detail })),
      users: (await adapter.findMany({ model: "user", limit: 10, sortBy: { field: "email", direction: "asc" } })).map(user),
    };
    return { backend, joins, ...spec, events, ...outcome, originalError, stored };
  } finally { database?.close(); }
}

if (import.meta.main) {
  const observations = [];
  for (const backend of ["memory", "sqlite"]) for (const joins of [false, true]) {
    for (const spec of cases) observations.push(await capture(backend, joins, spec));
  }
  console.log(JSON.stringify({ version: "1.7.6", cases: observations }, null, 2));
}
