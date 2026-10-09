import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { date, setup, team, type Events, type Policies } from "./organization-team-member-contract";
import { memberEvents, memberFields, physicalMember, publicTeam, seedFields, seedMember } from "./organization-team-details-contract";

for (const backend of ["memory", "sqlite"] as const) {
  for (const policy of ["empty", "hidden"] as const) {
    for (const entry of ["native", "http"] as const) {
      test(`${backend} Team route ${entry} preserves custom-default-${policy} callback values`, async () => {
        const fixture = await setup(backend, seedFields);
        const events: Events = [];
        const visibleName = () => { events.push(["team.name", "called"]); return "Callback Team"; };
        const callbackTeam = publicTeam("team-a", "Callback Team");
        // JavaScript callbacks can return Function values outside the declared Team shape.
        Object.defineProperty(callbackTeam, "name", { enumerable: true, value: visibleName });
        try {
          await seedMember(fixture, "member-a", "team-a", "user-a");
          const session = {
            id: "session-a", userId: "user-a", token: "callback-token", createdAt: date(0), updatedAt: date(0),
            expiresAt: new Date("2100-01-01T00:00:00.000Z"), ipAddress: null, userAgent: null,
            activeOrganizationId: "organization", activeTeamId: null,
          };
          await fixture.context.adapter.create({ model: "session", forceAllowId: true, data: session });
          const organizationsBefore = await fixture.context.adapter.findMany({ model: "organization" });
          const fixedCreatedAt = (model: string): Policies => ({ createdAt: { type: "date", transform: { input(value) {
            expect(value).toBeInstanceOf(Date);
            events.push([`${model}.createdAt`, "input", "native-date"]);
            return date(0);
          } } } });
          const auth = betterAuth({
            ...fixture.options,
            rateLimit: { enabled: false },
            plugins: [organization({
              teams: { enabled: true, defaultTeam: { enabled: true, customCreateDefaultTeam: async organization => {
                events.push(["customCreateDefaultTeam", "callback", organization]);
                return callbackTeam;
              } } },
              schema: { team: { additionalFields: policy === "hidden" ? { name: { type: "string", returned: false } } : {} } },
              organizationHooks: {
                beforeCreateTeam({ team }) { events.push(["beforeCreateTeam", "hook", team]); return Promise.resolve(); },
                afterCreateTeam({ team }) {
                  expect(team).toBe(callbackTeam);
                  expect(team.name).toBe(visibleName);
                  events.push(["afterCreateTeam", "hook", team]);
                  return Promise.resolve();
                },
                afterCreateOrganization({ organization, member }) {
                  events.push(["afterCreateOrganization", "hook", organization, member]);
                  return Promise.resolve();
                },
              },
            }), { id: "ordinary-custom-default-team-fields", schema: {
              organization: { fields: fixedCreatedAt("organization") }, member: { fields: fixedCreatedAt("member") },
              teamMember: { fields: memberFields(events) },
              team: { fields: { name: { type: "string", transform: { output(value) {
                events.push(["team.name", "output", value]); return value;
              } } } } },
            }],
          });
          const organizationView = {
            id: "organization-a", name: "Created Organization", slug: "created", logo: null, metadata: {}, createdAt: date(0),
          };
          const member = { id: "member-a", organizationId: "organization-a", userId: "user-a", role: "owner", createdAt: date(0) };
          const expected = { ...organizationView, members: [member] };
          const baseURL = "http://team-member-fields.test";
          const cookie = (await serializeSignedCookie("better-auth.session_token", "callback-token", fixture.options.secret!)).split(";", 1)[0];
          const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
          const body = { name: "Created Organization", slug: "created", logo: null, metadata: {}, keepCurrentActiveOrganization: true };
          if (entry === "native") expect(await auth.api.createOrganization({ headers, body })).toStrictEqual(expected);
          else {
            const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/create`, {
              method: "POST", headers, body: JSON.stringify(body),
            }));
            expect(response.status).toBe(200);
            expect(await response.json()).toStrictEqual({
              ...expected, createdAt: date(0).toISOString(), members: [{ ...member, createdAt: date(0).toISOString() }],
            });
          }
          expect(events).toStrictEqual([
            ["organization.createdAt", "input", "native-date"], ["member.createdAt", "input", "native-date"],
            ["beforeCreateTeam", "hook", { name: "Created Organization", organizationId: "organization-a" }],
            ["customCreateDefaultTeam", "callback", organizationView], ...memberEvents(backend, "team-a", "user-a"),
            ["afterCreateTeam", "hook", callbackTeam], ["afterCreateOrganization", "hook", organizationView, member],
          ]);
          expect(fixture.rawTeams()).toStrictEqual([
            fixture.stored(team("team-a", "Team A", 1)), fixture.stored(team("team-b", "Team B")),
          ]);
          expect(fixture.rawMembers()).toStrictEqual([fixture.stored(physicalMember("member-a", "team-a", "user-a"))]);
          expect(fixture.rawInvitations()).toStrictEqual([]);
          expect(await fixture.context.adapter.findMany({ model: "organization" })).toStrictEqual([
            ...organizationsBefore, { ...organizationView, metadata: "{}" },
          ]);
          expect(await fixture.context.adapter.findMany({ model: "member" })).toStrictEqual([member]);
          expect(await fixture.context.adapter.findMany({ model: "session" })).toStrictEqual([session]);
        } finally { fixture.close(); }
      });
    }
  }
}
