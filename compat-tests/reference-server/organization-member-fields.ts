import type { OrganizationOptions } from "better-auth/plugins/organization";

export function organizationMemberFieldOptions(profile: string): OrganizationOptions {
  if (!["organization-member-fields", "organization-invitation-teams"].includes(profile)) return {};
  const invitationTeams = profile === "organization-invitation-teams";
  const unconstrained = { type: ["unconstrained"] as string[], required: false };
  const json = { type: "json" as const, required: false, transform: { input: (value: unknown) => typeof value === "string" ? JSON.stringify(value) : value } };
  return {
    teams: { enabled: true, defaultTeam: { enabled: false } },
    organizationHooks: {
      beforeCreateInvitation: async ({ invitation }) => ({ data: { hookState: {
        status: invitation.status,
        createdAt: invitation.createdAt,
        expiresAt: invitation.expiresAt,
        inviterId: invitation.inviterId,
        ...(invitationTeams ? { teamIds: invitation.teamIds, teamId: invitation.teamId } : {}),
      } } }),
    },
    schema: {
      member: { additionalFields: {
        role: { ...json, defaultValue: "member" },
        organizationId: { ...unconstrained, references: { model: "organization", field: "id" } },
        userId: { ...unconstrained, references: { model: "user", field: "id" } },
        teamId: unconstrained,
        zetaText: { type: "string", required: false },
        alphaCount: { type: "number", required: false },
      } },
      invitation: { additionalFields: {
        email: json,
        role: json,
        organizationId: { ...unconstrained, references: { model: "organization", field: "id" } },
        status: { type: "string", required: false },
        createdAt: { type: "string", required: false, transform: { input: (value: unknown) => value instanceof Date ? value.toISOString() : value } },
        expiresAt: { type: "string", required: false, transform: { input: (value: unknown) => value instanceof Date ? value.toISOString() : value } },
        inviterId: { type: "string", required: false },
        hookState: { type: "json", input: false, required: false },
        zetaText: { type: "string", required: false },
        alphaCount: { type: "number", required: false },
        ...(invitationTeams ? { teamId: unconstrained } : {}),
      } },
    },
  };
}
