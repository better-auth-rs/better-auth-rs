import type { OrganizationOptions } from "better-auth/plugins/organization";

const rawDate = "2000-01-02T03:04:05+02:00";
export function organizationDynamicFieldOptions(profile: string): OrganizationOptions {
  if (profile !== "organization-dynamic-fields") return {};
  return {
    teams: { enabled: true, defaultTeam: { enabled: false } },
    schema: {
      organization: { additionalFields: {
        name: { type: "number", required: false, transform: { output: (value: unknown) => value === 99 ? undefined : value } },
        logo: { type: "boolean", required: false },
        createdAt: { type: "string", input: false, transform: { input: () => rawDate } },
        updatedAt: { type: "string", required: false, defaultValue: "public-updated" },
      } },
      team: { additionalFields: {
        name: { type: "json", required: false },
        createdAt: { type: "string", required: false },
        updatedAt: { type: "string", input: false, transform: { input: () => rawDate } },
        memberCount: { type: "number", required: false, defaultValue: 17 },
      } },
    },
  };
}
