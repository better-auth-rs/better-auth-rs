import type { OrganizationOptions } from "better-auth/plugins/organization";

function fields() {
  return {
    label: {
      type: "string" as const, required: false, fieldName: "physical_label", defaultValue: "guest",
      transform: { input: (value: unknown) => `${value}:in`, output: (value: unknown) => `${value}:out` },
    },
    secret: { type: "string" as const, required: false, returned: false, defaultValue: "hidden" },
    protected: { type: "string" as const, required: false, input: false, defaultValue: "server" },
    marker: { type: "string" as const, required: false, defaultValue: "created", onUpdate: () => "updated" },
    score: {
      type: "number" as const, required: false, defaultValue: 1,
      validator: { input: { "~standard": { version: 1 as const, vendor: "compat", validate: (value: unknown) =>
        typeof value === "number" && value >= 0 ? { value } : { issues: [{ message: "score must be nonnegative" }] },
      } } },
    },
    tags: { type: "string[]" as const, required: false, defaultValue: ["starter"] },
    payload: { type: "json" as const, required: false, defaultValue: { theme: "system" } },
  };
}

export function organizationFieldOptions(profile: string): OrganizationOptions {
  if (profile !== "organization-fields") return {};
  return {
    teams: { enabled: true, maximumMembersPerTeam: 1 },
    schema: {
      organization: {
        modelName: "app_organization", fields: { name: "physical_name" },
        additionalFields: {
          ...fields(),
          requiredTag: { type: "string", required: true, defaultValue: "fallback" },
          implicitTag: { type: "string" },
          category: { type: ["basic", "pro"], required: false, defaultValue: "basic" },
          joinedAt: { type: "date", required: false, defaultValue: () => new Date("2020-01-02T03:04:05.000Z") },
        },
      },
      member: { modelName: "app_member", fields: { role: "physical_role" }, additionalFields: fields() },
      invitation: { modelName: "app_invitation", fields: { role: "physical_role" }, additionalFields: fields() },
      team: { modelName: "app_team", fields: { name: "physical_name" }, additionalFields: fields() },
      teamMember: { modelName: "app_team_member", fields: { membershipKey: "physical_membership_key" } },
      organizationRole: {
        modelName: "app_organization_role", fields: { role: "physical_role" },
        additionalFields: { ...fields(), roleRequired: { type: "string", required: true, defaultValue: "role-default" } },
      },
    },
  };
}
