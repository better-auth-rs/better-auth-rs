import { APIError } from "better-auth/api";
import type { OrganizationOptions } from "better-auth/plugins/organization";

const hookNames = [
  "beforeCreateOrganization", "afterCreateOrganization", "beforeUpdateOrganization", "afterUpdateOrganization", "beforeDeleteOrganization", "afterDeleteOrganization",
  "beforeAddMember", "afterAddMember", "beforeRemoveMember", "afterRemoveMember", "beforeUpdateMemberRole", "afterUpdateMemberRole",
  "beforeCreateInvitation", "afterCreateInvitation", "beforeAcceptInvitation", "afterAcceptInvitation", "beforeRejectInvitation", "afterRejectInvitation", "beforeCancelInvitation", "afterCancelInvitation",
  "beforeCreateTeam", "afterCreateTeam", "beforeUpdateTeam", "afterUpdateTeam", "beforeDeleteTeam", "afterDeleteTeam",
  "beforeAddTeamMember", "afterAddTeamMember", "beforeRemoveTeamMember", "afterRemoveTeamMember",
] as const;

function project(value: any) {
  if (!value) return null;
  return {
    ...Object.fromEntries(["id", "name", "slug", "email", "organizationId", "userId", "role", "teamId", "status", "activeOrganizationId", "activeTeamId", "secretNote"]
      .filter((key) => value[key] !== undefined && value[key] !== null).map((key) => [key, value[key]])),
    ...(value.metadata !== undefined ? { metadata: value.metadata } : {}),
    dates: Object.fromEntries(["createdAt", "updatedAt", "expiresAt"].map((key) => [key,
      !Object.hasOwn(value, key) ? "absent" : value[key] === null ? "null" : value[key] === undefined ? "undefined" : "value",
    ])),
  };
}

export function createOrganizationCallbacks(profile: string) {
  const enabled = profile === "organization-callbacks" || profile === "organization-custom-team";
  let events: unknown[] = [];
  let fail: string | null = null;
  let limits: Record<string, number | boolean> = {};
  let organizationIdOverride: string | null = null;
  let clearLogo = false;
  let metadataOverride: unknown = undefined;
  const reset = () => { events = []; fail = null; limits = {}; organizationIdOverride = null; clearLogo = false; metadataOverride = undefined; };
  async function record(event: string, data: any = {}, ctx?: any) {
    await Promise.resolve();
    events.push({
      event,
      organization: project(data.organization), user: project(data.user ?? data.inviter ?? data.cancelledBy),
      member: project(data.member), team: project(data.team), invitation: project(data.invitation), teamMember: project(data.teamMember),
      newRole: data.newRole ?? null, previousRole: data.previousRole ?? null,
      organizationId: data.organizationId ?? null, teamId: data.teamId ?? null,
      session: data.session ? { user: project(data.session.user), session: project(data.session.session) } : null,
      hasRequest: ctx ? Boolean(ctx.request) : null,
    });
    if (fail === event) throw APIError.from("FORBIDDEN", { code: "FIXTURE_HOOK_REJECTED", message: "Hook rejected" });
  }
  const hooks = Object.fromEntries(hookNames.map((name) => [name, async (data: any, ctx?: any) => {
    await record(name, data, ctx);
    if (name === "beforeCreateOrganization") return { data: {
      name: `hook:${data.organization.name}`,
      ...(metadataOverride !== undefined ? { metadata: metadataOverride } : {}),
    } };
    if (name === "beforeUpdateOrganization") return { data: {
      ...(data.organization.name ? { name: `updated:${data.organization.name}` } : {}),
      ...(organizationIdOverride ? { id: organizationIdOverride } : {}),
      ...(clearLogo ? { logo: null } : {}),
      ...(metadataOverride !== undefined ? { metadata: metadataOverride } : {}),
    } };
    if (name === "beforeAddMember" && data.member.role === "member") return { data: { role: "admin" } };
    if (name === "beforeUpdateMemberRole") return { data: { role: "member" } };
    if (name === "beforeCreateInvitation") return { data: { role: "admin" } };
    if (name === "beforeCreateTeam") return { data: { name: `team:${data.team.name}` } };
    if (name === "beforeUpdateTeam" && data.updates.name) return { data: { name: `updated:${data.updates.name}` } };
    if (name === "beforeAddTeamMember") return { data: { userId: "ignored-hook-user" } };
  }])) as OrganizationOptions["organizationHooks"];
  const options: OrganizationOptions = {
    organizationHooks: hooks,
    allowUserToCreateOrganization: async (user) => { await record("allowCreate", { user }); return limits.allowCreate !== false; },
    organizationLimit: async (user) => { await record("organizationLimit", { user }); return limits.organizationLimit === true; },
    membershipLimit: async (user, organization) => { await record("membershipLimit", { user, organization }); return Number(limits.membershipLimit ?? 100); },
    invitationLimit: async (data) => { await record("invitationLimit", data); return Number(limits.invitationLimit ?? 100); },
    teams: {
      enabled: true,
      allowRemovingAllTeams: true,
      defaultTeam: {
        enabled: true,
        ...(profile === "organization-custom-team" ? { customCreateDefaultTeam: async (organization: any, ctx: any) => {
          await record("createDefaultTeam", { organization }, ctx);
          return ctx.context.adapter.create({ model: "team", data: { organizationId: organization.id, name: `custom:${organization.name}`, createdAt: new Date() } });
        } } : {}),
      },
      maximumTeams: async (data, ctx) => { await record("maximumTeams", data, ctx); return Number(limits.maximumTeams ?? 100); },
      maximumMembersPerTeam: async (data) => { await record("maximumMembersPerTeam", data); return Number(limits.maximumMembersPerTeam ?? 100); },
    },
    dynamicAccessControl: { enabled: true, maximumRolesPerOrganization: async (organizationId) => {
      await record("maximumRoles", { organizationId }); return Number(limits.maximumRoles ?? 100);
    } },
  };
  return {
    options: enabled ? options : {}, reset,
    async route(request: Request): Promise<Response | null> {
      if (new URL(request.url).pathname !== "/__test/organization-callbacks") return null;
      if (request.method === "POST") {
        const body = await request.json();
        events = [];
        fail = body.fail ?? null;
        limits = body.limits ?? {};
        organizationIdOverride = body.organizationIdOverride ?? null;
        clearLogo = body.clearLogo === true;
        metadataOverride = body.metadataOverride;
        return Response.json({ status: true });
      }
      return Response.json(events);
    },
  };
}
