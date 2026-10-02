import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { bearer, organization } from "better-auth/plugins";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
const modelNames = ["organization", "member", "invitation", "team", "organizationRole"] as const;
const now = new Date("2026-01-01T00:00:00.000Z");
const expiresAt = new Date("2100-01-01T00:00:00.000Z");
const email = "user@organization-serial.test";
const present = (value: unknown) => value === undefined ? { $undefined: true } : value;
const member = (row: any) => ({ id: row.id, organizationId: row.organizationId, userId: row.userId, role: row.role });
const joinedMember = (row: any) => ({ ...member(row), userIdFromJoin: row.user.id });

function reference(trace?: unknown[]) {
  return {
    type: "string" as const,
    fieldName: "stored_reference",
    references: { model: "user", field: "id" },
    defaultValue: " 001 ",
    onUpdate: () => " 1 ",
    transform: {
      input(value: unknown) { trace?.push(["input", value]); return String(value).trim(); },
      output(value: unknown) { trace?.push(["output", value]); return value; },
    },
  };
}

async function context(schema: Record<string, unknown>, joins = false) {
  const memory: Record<string, any[]> = Object.fromEntries([
    "user", "session", "account", "verification", ...modelNames, "teamMember",
  ].map(name => [name, []]));
  const options = { teams: { enabled: true, maximumMembersPerTeam: 10 }, dynamicAccessControl: { enabled: true }, schema };
  const auth = betterAuth({
    database: memoryAdapter(memory), baseURL: "http://organization-serial.test",
    secret: "ordinary-organization-serial-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    advanced: { database: { generateId: "serial", joins } },
    plugins: [bearer(), organization(options)],
  });
  const context = await auth.$context;
  const user = await context.adapter.create<any>({ model: "user", data: {
    name: "User", email, emailVerified: true, createdAt: now, updatedAt: now,
  } });
  return { auth, context, adapter: context.adapter, org: getOrgAdapter(context, options), user };
}

async function fieldFamilies() {
  const families: Record<string, unknown> = {};
  for (const model of modelNames) {
    const trace: unknown[] = [];
    const { adapter } = await context({ [model]: { additionalFields: { reference: reference(trace) } } });
    if (model !== "organization") {
      await adapter.create({ model: "organization", data: { name: "Organization", slug: "ordinary", createdAt: now } });
    }
    const data = {
      organization: { name: "Organization", slug: "ordinary", createdAt: now },
      member: { organizationId: "001", userId: "001", role: "owner", createdAt: now },
      invitation: { organizationId: "001", inviterId: "001", email, role: "member", status: "pending", expiresAt, createdAt: now },
      team: { organizationId: "001", name: "Team", memberCount: 0, createdAt: now },
      organizationRole: { organizationId: "001", role: "viewer", permission: "{}", createdAt: now },
    }[model];
    const update = {
      organization: { name: "Updated" }, member: { role: "admin" }, invitation: { status: "canceled" },
      team: { name: "Updated" }, organizationRole: { role: "updated" },
    }[model];
    const created = await adapter.create<any>({ model, data });
    const updated = await adapter.update<any>({ model, where: [{ field: "id", value: created.id }], update });
    if (!updated) throw new Error("Ordinary reference update must return its row");
    families[model] = { created: present(created.reference), updated: present(updated.reference), trace };
  }
  return families;
}

async function lifecycle(joins: boolean) {
  const { auth, context: ctx, adapter, org, user } = await context({ member: { additionalFields: {
    reference: { ...reference(), references: { model: "organizationRole", field: "id" } },
    userId: { type: "string", fieldName: "stored_user_id", references: { model: "user", field: "id" } },
  } } }, joins);
  const organizationRow = await org.createOrganization({ organization: { name: "Organization", slug: "ordinary", createdAt: now } });
  const organizationId = organizationRow.id;
  const paddedOrganization = `00${organizationId}`;
  const paddedUser = `00${user.id}`;
  const role = await adapter.create<any>({ model: "organizationRole", data: {
    organizationId: paddedOrganization, role: "viewer", permission: "{}", createdAt: now,
  } });
  const paddedRole = `00${role.id}`;
  const createdMember = await org.createMember({ organizationId: paddedOrganization, userId: paddedUser, role: "owner" });
  const team = await org.createTeam({ name: "Team", organizationId: paddedOrganization, createdAt: now });
  const paddedTeam = `00${team.id}`;
  await org.findOrCreateTeamMember({ teamId: team.id, userId: user.id });
  const invitation = await org.createInvitation({ invitation: {
    organizationId: paddedOrganization, email, role: "member", teamIds: [team.id],
  }, user: { id: paddedUser } });
  const filtered = await org.listMembers({ organizationId: paddedOrganization, filter: { field: "reference", value: paddedRole, operator: "eq" } });
  const full = await org.findFullOrganization({ organizationId: paddedOrganization, includeTeams: true });
  const roleWhere = [{ field: "organizationId", value: paddedOrganization }];
  const foundRole = await adapter.findOne<any>({ model: "organizationRole", where: [...roleWhere, { field: "role", value: "viewer" }] });
  if (!foundRole) throw new Error("Ordinary role lookup must return its row");
  const numericMember = await adapter.findOne<any>({ model: "member", where: [
    { field: "organizationId", value: Number(organizationId) }, { field: "userId", value: Number(user.id) },
  ] });
  const pointTeamMember = await org.findTeamMember({ teamId: paddedTeam, userId: paddedUser });
  const lookup = {
    numericMember: member(numericMember),
    member: joinedMember(await org.findMemberByOrgId({ organizationId: paddedOrganization, userId: paddedUser })),
    memberById: joinedMember(await org.findMemberById(createdMember.id)),
    filtered: { total: filtered.total, members: filtered.members.map(joinedMember) },
    organizations: (await org.listOrganizations(paddedUser)).map((row: any) => row.id),
    teams: (await org.listTeamsByUser({ userId: paddedUser })).map((row: any) => row.id),
    teamMembers: (await org.listTeamMembers({ teamId: paddedTeam })).map((row: any) => ({ teamId: row.teamId, userId: row.userId })),
    teamMember: { teamId: pointTeamMember.teamId, userId: pointTeamMember.userId },
    counts: {
      members: await org.countMembers({ organizationId: paddedOrganization }),
      owners: await adapter.count({ model: "member", where: [...roleWhere, { field: "role", value: "owner" }] }),
      pendingInvitations: (await org.findPendingInvitations({ organizationId: paddedOrganization })).length,
      teams: await adapter.count({ model: "team", where: roleWhere }),
      teamMembers: await org.countTeamMembers({ teamId: paddedTeam }),
      roles: await adapter.count({ model: "organizationRole", where: roleWhere }),
    },
    role: foundRole.organizationId,
    invitations: (await org.listUserInvitations(email)).map((row: any) => ({ organizationId: row.organizationId, inviterId: row.inviterId, organizationName: present(row.organizationName), teamId: present(row.teamId) })),
    pending: (await org.findPendingInvitation({ organizationId: paddedOrganization, email })).map((row: any) => row.id),
    full: { id: full.id, members: full.members.map(joinedMember), teams: full.teams.map((row: any) => ({ id: row.id, organizationId: row.organizationId })), invitations: full.invitations.map((row: any) => ({ organizationId: row.organizationId, inviterId: row.inviterId })) },
  };
  await org.deleteMember({ memberId: createdMember.id, organizationId: paddedOrganization });
  const removed = {
    members: await org.countMembers({ organizationId: paddedOrganization }),
    teamMembers: await org.countTeamMembers({ teamId: paddedTeam }),
  };
  const session = await ctx.internalAdapter.createSession(user.id);
  if (!session) throw new Error("Ordinary session setup must return a row");
  const accepted = await auth.api.acceptInvitation({ body: { invitationId: invitation.id }, headers: new Headers({ authorization: `Bearer ${session.token}` }) });
  const sessionAfter = await ctx.internalAdapter.findSession(session.token);
  if (!sessionAfter) throw new Error("Ordinary session must remain available");
  const acceptance = {
    member: member(accepted.member), status: accepted.invitation.status, teamId: present(accepted.invitation.teamId),
    teamMembers: (await org.listTeamMembers({ teamId: paddedTeam })).map((row: any) => ({ teamId: row.teamId, userId: row.userId })),
    activeOrganizationId: present(sessionAfter.session.activeOrganizationId), activeTeamId: present(sessionAfter.session.activeTeamId),
  };
  await org.removeTeamMember({ teamId: paddedTeam, userId: paddedUser });
  const removedTeamMember = await org.countTeamMembers({ teamId: paddedTeam });
  await org.deleteTeam(team.id);
  await adapter.delete({ model: "organizationRole", where: [{ field: "id", value: role.id }] });
  await org.deleteOrganization(organizationId);
  const cleanup = {
    removedTeamMember,
    members: await org.countMembers({ organizationId: paddedOrganization }),
    invitations: (await org.listInvitations({ organizationId: paddedOrganization })).length,
    teams: (await org.listTeams(paddedOrganization)).length,
    roles: await adapter.count({ model: "organizationRole", where: roleWhere }),
    organizationPresent: (await org.findOrganizationById(organizationId)) !== null,
    userPresent: (await adapter.findOne({ model: "user", where: [{ field: "id", value: user.id }] })) !== null,
  };
  return { joins, lookup, removed, acceptance, cleanup };
}

async function explicitReferenceReplacement() {
  const outputs: unknown[] = [];
  const { adapter, org } = await context({ organizationRole: { additionalFields: {
    organizationId: { type: "string", fieldName: "stored_organization_id", transform: {
      output(value: unknown) { outputs.push(value); return value; },
    } },
  } } });
  const organizationRow = await org.createOrganization({ organization: { name: "Organization", slug: "ordinary", createdAt: now } });
  const created = await adapter.create<any>({ model: "organizationRole", data: {
    organizationId: organizationRow.id, role: "viewer", permission: "{}", createdAt: now,
  } });
  const read = await adapter.findOne<any>({ model: "organizationRole", where: [
    { field: "organizationId", value: organizationRow.id }, { field: "role", value: "viewer" },
  ] });
  if (!read) throw new Error("Ordinary replaced-reference lookup must return its row");
  return { created: created.organizationId, read: read.organizationId, outputs };
}

export async function captureOrganizationSerialReferences() {
  return { version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    families: await fieldFamilies(), replacement: await explicitReferenceReplacement(), lifecycles: [await lifecycle(false), await lifecycle(true)] };
}

if (import.meta.main) {
  const destination = process.argv[2];
  if (!destination) throw new Error("Pass the absolute fixture destination path");
  await Bun.write(destination, `${JSON.stringify(await captureOrganizationSerialReferences(), null, 2)}\n`);
}
