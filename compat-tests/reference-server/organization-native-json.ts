import type { OrganizationOptions } from "better-auth/plugins/organization";

export function organizationNativeJsonOptions(profile: string): OrganizationOptions {
  if (!profile.startsWith("organization-native-json")) return {};
  const json = profile === "organization-native-json-object";
  const replace = (from: string, to: string) => (value: unknown) => typeof value === "string" ? value.replaceAll(from, to) : value;
  return {
    teams: { enabled: true, defaultTeam: { enabled: false } },
    organizationHooks: {
      beforeUpdateOrganization: async ({ organization }) => {
        if (organization.metadata && typeof organization.metadata === "object" && "clear" in organization.metadata) return { data: { ...organization, metadata: null } };
      },
    },
    schema: {
      organization: { additionalFields: {
        metadata: {
          type: json ? "json" : "string", required: false, defaultValue: '{"source":"default"}',
          transform: { input: replace("source", "stored"), output: (value: unknown) => {
            if (json && value !== null && value !== undefined && typeof value !== "string") throw new Error("JSON output callback requires stored text");
            return replace("stored", "visible")(value);
          } },
        },
      } },
      organizationRole: { additionalFields: {
        permission: {
          type: json ? "json" : "string", required: false,
          transform: { input: replace("create", "delete"), output: replace("delete", "update") },
          onUpdate: () => '{"member":["create"]}',
        },
        role: { type: "string", required: false },
        organizationId: { type: "string", required: false },
        id: { type: "string", required: false, fieldName: "ignored_id" },
      } },
    },
  };
}
