import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { date, setup, team, type Events, type Policies } from "./organization-team-member-contract";
import { memberEvents, memberFields, parentFields, physicalMember, seedFields, seedMember } from "./organization-team-details-contract";

async function seedInvitationFixture(fixture: Awaited<ReturnType<typeof setup>>, secondTeamId = "team-a") {
  await seedMember(fixture, "member-a", "team-a", "user-a");
  await seedMember(fixture, "member-b", secondTeamId, "user-b");
  await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: {
    id: "owner-member", userId: "user-a", organizationId: "organization", role: "owner", createdAt: date(0),
  } });
  await fixture.context.adapter.create({ model: "session", forceAllowId: true, data: {
    id: "session-a", userId: "user-a", token: "invitation-token", createdAt: date(0), updatedAt: date(0),
    expiresAt: new Date("2100-01-01T00:00:00.000Z"), ipAddress: null, userAgent: null,
    activeOrganizationId: "organization", activeTeamId: null,
  } });
}

function invitationDateFields(): Policies {
  return {
    createdAt: { type: "date", transform: { input(value) {
      expect(value).toBeInstanceOf(Date);
      return date(0);
    } } },
    expiresAt: { type: "date", transform: { input(value) {
      expect(value).toBeInstanceOf(Date);
      return date(30);
    } } },
  };
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const joins of [false, true]) {
    for (const mode of ["no-limit", "success", "full", "child-error"] as const) {
      test(`${backend} Team invitation ${joins ? "native" : "fallback"} preserves ${mode} selection and capacity`, async () => {
        const fixture = await setup(backend, seedFields, { joins });
        const events: Events = [];
        const failure = new Error("team-details-member-output-failed");
        try {
          await seedInvitationFixture(fixture);
          const teamFields: Policies = {
            ...parentFields(events),
            organizationId: { type: "string", transform: { output(value) {
              events.push(["team.organizationId", "output", value]);
              return "visible-organization";
            } } },
            id: { type: "string", transform: { output(value) {
              events.push(["team.id", "output", value]);
              return "visible-team";
            } } },
          };
          const auth = betterAuth({
            ...fixture.options,
            rateLimit: { enabled: false },
            advanced: { database: {
              ...fixture.options.advanced?.database,
              ...(mode === "no-limit" ? {} : { defaultFindManyLimit: mode === "success" ? 1 : 2 }),
            } },
            plugins: [organization({ teams: {
              enabled: true,
              ...(mode === "no-limit" ? {} : { maximumMembersPerTeam: async ({ organizationId, teamId, session }) => {
                events.push(["limit", "callback", [organizationId, teamId, session.user.id]]);
                return 2;
              } }),
            } }), {
              id: "ordinary-team-invitation-fields",
              schema: {
                team: { fields: teamFields },
                teamMember: { fields: memberFields(events, "id", false, mode === "child-error" ? failure : undefined) },
                invitation: { fields: invitationDateFields() },
              },
            }],
          });
          const baseURL = "http://team-member-fields.test";
          const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-token", fixture.options.secret!)).split(";", 1)[0];
          const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/invite-member`, {
            method: "POST", headers: { cookie, origin: baseURL, "content-type": "application/json" },
            body: JSON.stringify({ email: "invited@team-member-fields.test", role: "member", organizationId: "organization", teamId: "team-a" }),
          }));
          const accepted = mode === "no-limit" || mode === "success";
          const invitation = {
            id: "invitation-a", organizationId: "organization", email: "invited@team-member-fields.test", role: "member",
            teamId: "team-a", status: "pending", inviterId: "user-a", createdAt: date(0), expiresAt: date(30),
          };
          expect(response.status).toBe(accepted ? 200 : mode === "full" ? 403 : 500);
          if (accepted) expect(await response.json()).toStrictEqual({
            ...invitation, createdAt: date(0).toISOString(), expiresAt: date(30).toISOString(),
          });
          else if (mode === "full") expect(await response.json()).toStrictEqual({
            code: "TEAM_MEMBER_LIMIT_REACHED", message: "Team member limit reached",
          });
          else expect(await response.text()).toBe("");
          const parentEvents = [["team.name", "output", "Team A"], ["team.organizationId", "output", "organization"]];
          expect(events).toStrictEqual([
            ...parentEvents,
            ...(mode === "no-limit" ? [] : [
              ...parentEvents,
              ...(mode === "child-error" ? [["teamId", "output", "team-a"], ["userId", "output", "user-a"]] : [
                ...memberEvents(backend, "team-a", "user-a"),
                ...(mode === "full" ? memberEvents(backend, "team-a", "user-b") : []),
                ["limit", "callback", ["organization", "team-a", "user-a"]],
              ]),
            ]),
          ]);
          expect(fixture.rawInvitations()).toStrictEqual(accepted ? [fixture.stored(invitation)] : []);
          expect(fixture.rawMembers()).toStrictEqual([
            physicalMember("member-a", "team-a", "user-a"), physicalMember("member-b", "team-a", "user-b"),
          ].map(row => fixture.stored(row)));
          expect(fixture.rawTeams()).toStrictEqual([
            fixture.stored(team("team-a", "Team A", 2)), fixture.stored(team("team-b", "Team B")),
          ]);
        } finally { fixture.close(); }
      });
    }
  }
}

const cloneCases = [
  { name: "unset plural", policy: "unset", functionAt: 2, singular: false, result: "success" },
  { name: "empty first lookup", policy: "empty", functionAt: 1, singular: false, result: "clone-error" },
  { name: "hidden plural", policy: "hidden", functionAt: 2, singular: false, result: "clone-error" },
  { name: "empty singular", policy: "empty", functionAt: 2, singular: true, result: "clone-error" },
  { name: "unset singular", policy: "unset", functionAt: 2, singular: true, result: "map-error" },
] as const;

for (const backend of ["memory", "sqlite"] as const) {
  for (const joins of [false, true]) {
    for (const scenario of cloneCases) {
      for (const entry of ["native", "http"] as const) {
        test(`${backend} Team invitation ${joins ? "native" : "fallback"} join ${entry} preserves ${scenario.name} Function output`, async () => {
          const fixture = await setup(backend, seedFields, { joins });
          const events: Events = [];
          let nameOutputs = 0;
          const visibleName = () => {
            events.push(["team.name", "called"]);
            return "Visible Team A";
          };
          try {
            const secondTeamId = scenario.singular ? "team-b" : "team-a";
            await seedInvitationFixture(fixture, secondTeamId);
            const additionalFields: Policies = scenario.policy === "hidden" ? { name: { type: "string", returned: false } } : {};
            const teamFields: Policies = {
              name: { type: "string" },
              organizationId: { type: "string", transform: { output(value) {
                events.push(["team.organizationId", "output", value]);
                return "visible-organization";
              } } },
            };
            // JavaScript plugins can return Function values outside the DBPrimitive declaration.
            Object.defineProperty(teamFields.name!, "transform", { enumerable: true, value: { output(value: unknown) {
              events.push(["team.name", "output", value]);
              return ++nameOutputs >= scenario.functionAt ? visibleName : value;
            } } });
            const auth = betterAuth({
              ...fixture.options,
              rateLimit: { enabled: false },
              advanced: { database: { ...fixture.options.advanced?.database, defaultFindManyLimit: 2 } },
              plugins: [organization({
                teams: { enabled: true, maximumMembersPerTeam: async ({ organizationId, teamId, session }) => {
                  events.push(["limit", "callback", [organizationId, teamId, session.user.id]]);
                  return 3;
                } },
                ...(scenario.policy === "unset" ? {} : { schema: { team: { additionalFields } } }),
              }), {
                id: "ordinary-team-invitation-function-fields",
                schema: {
                  team: { fields: teamFields },
                  teamMember: { fields: memberFields(events, "id", scenario.singular) },
                  invitation: { fields: invitationDateFields() },
                },
              }],
            });
            const baseURL = "http://team-member-fields.test";
            const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-token", fixture.options.secret!)).split(";", 1)[0];
            const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
            const body = { email: "invited@team-member-fields.test", role: "member", organizationId: "organization", teamId: "team-a" } as const;
            const invitation = {
              id: "invitation-a", organizationId: "organization", email: body.email, role: "member", teamId: "team-a",
              status: "pending", inviterId: "user-a", createdAt: date(0), expiresAt: date(30),
            };
            const accepted = scenario.result === "success";
            if (entry === "native") {
              if (accepted) expect(await auth.api.createInvitation({ headers, body })).toStrictEqual(invitation);
              else {
                let caught: unknown;
                try { await auth.api.createInvitation({ headers, body }); }
                catch (error) { caught = error; }
                if (scenario.result === "clone-error") expect(caught).toMatchObject({
                  name: "DataCloneError", message: "The object can not be cloned.",
                });
                else {
                  console.info("Team invitation singular membership error", { backend, joins, error: caught });
                  expect(caught).toBeInstanceOf(TypeError);
                  expect(caught).toMatchObject({ name: "TypeError" });
                }
              }
            } else {
              const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/invite-member`, {
                method: "POST", headers, body: JSON.stringify(body),
              }));
              expect(response.status).toBe(accepted ? 200 : 500);
              if (accepted) expect(await response.json()).toStrictEqual({
                ...invitation, createdAt: date(0).toISOString(), expiresAt: date(30).toISOString(),
              });
              else expect(await response.text()).toBe("");
            }
            const parentEvents = [["team.name", "output", "Team A"], ["team.organizationId", "output", "organization"]];
            expect(events).toStrictEqual([
              ...parentEvents,
              ...(scenario.functionAt === 1 ? [] : [
                ...parentEvents,
                ...memberEvents(backend, "team-a", "user-a"),
                ...(scenario.singular ? [] : memberEvents(backend, "team-a", "user-b")),
              ]),
              ...(accepted ? [["limit", "callback", ["organization", "team-a", "user-a"]]] : []),
            ]);
            expect(fixture.rawInvitations()).toStrictEqual(accepted ? [fixture.stored(invitation)] : []);
            expect(fixture.rawMembers()).toStrictEqual([
              physicalMember("member-a", "team-a", "user-a"), physicalMember("member-b", secondTeamId, "user-b"),
            ].map(row => fixture.stored(row)));
            expect(fixture.rawTeams()).toStrictEqual([
              fixture.stored(team("team-a", "Team A", scenario.singular ? 1 : 2)),
              fixture.stored(team("team-b", "Team B", scenario.singular ? 1 : 0)),
            ]);
          } finally { fixture.close(); }
        });
      }
    }
  }
}
