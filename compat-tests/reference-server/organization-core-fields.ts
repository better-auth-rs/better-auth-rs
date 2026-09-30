import type { OrganizationOptions } from "better-auth/plugins/organization";

const text = (input: string, output: string) => ({
  type: "string" as const,
  required: true,
  transform: {
    input: (value: unknown) => `${value}${input}`,
    output: (value: unknown) => `${value}${output}`,
  },
});

export function organizationCoreFieldOptions(profile: string): OrganizationOptions {
  if (profile !== "organization-core-fields") return {};
  return {
    teams: { enabled: true, defaultTeam: { enabled: false } },
    schema: {
      organization: { additionalFields: {
        id: id(),
        name: text(":in", ":out"),
        logo: { type: "string", required: false, input: false, defaultValue: "default-logo" },
        createdAt: { type: "date", input: false, returned: false },
      } },
      member: { additionalFields: { role: { ...text(",member", ",admin"), returned: false } } },
      invitation: { additionalFields: { id: id(), role: text(",member", ",admin") } },
      team: { additionalFields: {
        id: id(),
        name: text(":team-in", ":team-out"),
        updatedAt: { type: "date", required: false, input: false, onUpdate: () => new Date("2020-01-02T03:04:05.000Z") },
      } },
      organizationRole: { additionalFields: { role: text("_stored", "_visible") } },
    },
  };
}

function id() {
  const unexpected = () => { throw new Error("ID policies must not execute"); };
  return {
    type: "string" as const, required: false, fieldName: "unused_id",
    defaultValue: unexpected, transform: { input: unexpected, output: unexpected },
  };
}
