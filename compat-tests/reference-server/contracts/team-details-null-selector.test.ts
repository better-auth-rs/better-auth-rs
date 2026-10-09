import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
const date = () => new Date("2030-01-01T00:00:00.000Z");
type Fields = Record<string, unknown>;

for (const joins of [false, true]) for (const missingId of [false, true]) for (const selector of [null, undefined]) {
  test(`Memory TeamDetails id=${missingId ? "missing" : "null"}, selector=${String(selector)}, joins=${joins}`, async () => {
    const events: unknown[][] = [];
    const output = (name: string) => (value: unknown) => {
      events.push([name, "output", value]);
      return value;
    };
    const parent: Fields = {
      name: "No typed ID", memberCount: 0, organizationId: "organization", createdAt: date(), updatedAt: date(),
      ...(missingId ? {} : { id: null }),
    };
    const children: Fields[] = [
      { id: "missing", userId: "user-a", createdAt: date() },
      { id: "null", userId: "user-a", createdAt: date(), teamId: null },
    ];
    const memory: Record<string, Fields[]> = Object.fromEntries([
      "user", "session", "account", "verification", "organization", "member", "invitation", "team", "teamMember",
    ].map(model => [model, []]));
    memory.team = [parent];
    memory.teamMember = children;
    const before = structuredClone(memory);
    const organizationOptions = { teams: { enabled: true } };
    const context = await betterAuth({
      database: memoryAdapter(memory), baseURL: "http://team-details-null-selector.test",
      secret: "team-details-null-selector-contract-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } },
      plugins: [organization(organizationOptions), { id: "team-details-null-fields", schema: {
        team: { fields: { name: { type: "string", transform: { output: output("team.name") } } } },
        teamMember: { fields: { teamId: {
          type: "string", references: { model: "team", field: "id" },
          transform: { output: output("member.teamId") },
        } } },
      } }],
    }).$context;
    const org = getOrgAdapter(context, organizationOptions);
    const result = await org.findTeamById({ teamId: selector, includeTeamMembers: true });
    const found = missingId || selector === null;
    const value = missingId ? undefined : null;
    expect(result).toStrictEqual(found ? {
      name: "No typed ID", organizationId: "organization", createdAt: date(), updatedAt: date(), id: value,
      members: joins ? [{ ...children[missingId ? 0 : 1], teamId: value }] : [],
    } : null);
    expect(events).toStrictEqual(found ? [
      ["team.name", "output", "No typed ID"],
      ...(joins ? [["member.teamId", "output", value]] : []),
    ] : []);
    expect(memory).toStrictEqual(before);
  });
}
