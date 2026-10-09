import "./organization-team-default-callback-contract";
import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { date, setup, team, type Backend, type Events, type Policies } from "./organization-team-member-contract";
import { memberEvents, memberFields, physicalMember, publicTeam, seedFields, seedMember } from "./organization-team-details-contract";

type Fixture = Awaited<ReturnType<typeof setup>>;
type Route = "update" | "remove" | "active" | "members" | "list" | "user-list" | "create";
type Scenario = {
  name: string; route: Route; mode: "scope" | "owner-unset" | "owner-empty" | "clone" | "guard-clone" | "page"; joins?: boolean;
};
const cases: Scenario[] = [
  { name: "scope-update", route: "update", mode: "scope" },
  { name: "scope-remove", route: "remove", mode: "scope" },
  { name: "scope-active", route: "active", mode: "scope" },
  { name: "owner-update-unset", route: "update", mode: "owner-unset" },
  { name: "owner-update-empty", route: "update", mode: "owner-empty" },
  { name: "owner-remove-unset", route: "remove", mode: "owner-unset" },
  { name: "owner-remove-empty", route: "remove", mode: "owner-empty" },
  { name: "clone-active", route: "active", mode: "clone" },
  { name: "clone-members", route: "members", mode: "clone" },
  { name: "clone-list", route: "list", mode: "clone" },
  { name: "clone-user-list-fallback", route: "user-list", mode: "clone", joins: false },
  { name: "clone-user-list-native", route: "user-list", mode: "clone", joins: true },
  { name: "guard-create-clone", route: "create", mode: "guard-clone" },
  { name: "guard-remove-clone", route: "remove", mode: "guard-clone" },
  { name: "page-create", route: "create", mode: "page" },
  { name: "page-remove", route: "remove", mode: "page" },
];
const baseURL = "http://team-member-fields.test";
const where = (...pairs: [string, string][]) => pairs.map(([field, value]) => ({ field, value }));
const query = (operation: string, model: string, ...pairs: [string, string][]) => ["query", operation, model, where(...pairs)];
const teamOutput = (name: string) => [["team.name", "output", name], ["team.organizationId", "output", "organization"]];

function traceAdapter(adapter: Fixture["context"]["adapter"], events: Events) {
  for (const operation of ["findOne", "findMany", "count", "create", "update", "updateMany", "delete", "deleteMany", "consumeOne", "incrementOne"] as const) {
    const original = adapter[operation];
    Object.defineProperty(adapter, operation, { value: new Proxy(original, {
      apply(target, receiver, args) {
        const [input] = args;
        if (operation === "findOne" || operation === "findMany" || operation === "count") {
          if (["team", "teamMember", "member", "organization"].includes(input.model)) {
            events.push(["query", operation, input.model, input.where]);
          }
        } else events.push(["write", operation, input.model]);
        return Reflect.apply(target, receiver, args);
      },
    }) });
  }
}

async function seed(fixture: Fixture, organizationId: string) {
  await seedMember(fixture, "member-a", "team-a", "user-a");
  if (organizationId !== "organization") await fixture.context.adapter.create({ model: "organization", forceAllowId: true, data: {
    id: organizationId, name: "Other Organization", slug: organizationId, logo: null, metadata: "{}", createdAt: date(0),
  } });
  await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: {
    id: "owner-member", userId: "user-a", organizationId, role: "owner", createdAt: date(0),
  } });
  await fixture.context.adapter.create({ model: "session", forceAllowId: true, data: {
    id: "session-a", userId: "user-a", token: "route-token", createdAt: date(0), updatedAt: date(0),
    expiresAt: new Date("2100-01-01T00:00:00.000Z"), ipAddress: null, userAgent: null,
    activeOrganizationId: organizationId, activeTeamId: null,
  } });
}

async function state(fixture: Fixture) {
  const rows = await Promise.all(["organization", "member", "session"].map(model => fixture.context.adapter.findMany({ model })));
  return { organizations: rows[0], members: rows[1], sessions: rows[2] };
}

function routeFields(scenario: Scenario, events: Events): Policies {
  let outputs = 0;
  const visibleName = () => { events.push(["team.name", "called"]); return "Visible Team A"; };
  const fields: Policies = {
    name: { type: "string" },
    organizationId: { type: "string", transform: {
      input(value) { events.push(["team.organizationId", "input", value]); return value; },
      output(value) {
        events.push(["team.organizationId", "output", value]);
        return scenario.mode === "scope" ? "wrong-organization" : scenario.mode.startsWith("owner-") ? "visible-organization" : value;
      },
    } },
    createdAt: { type: "date", transform: { input(value) {
      expect(value).toBeInstanceOf(Date); events.push(["team.createdAt", "input", "native-date"]); return date(0);
    } } },
    updatedAt: { type: "date", transform: { input(value) {
      expect(value).toBeInstanceOf(Date); events.push(["team.updatedAt", "input", "native-date"]); return date(0);
    } } },
  };
  // JavaScript plugins can return Function values outside the DBPrimitive declaration.
  Object.defineProperty(fields.name!, "transform", { enumerable: true, value: { output(value: unknown) {
    events.push(["team.name", "output", value]);
    outputs++;
    return scenario.mode === "page" || scenario.name === "guard-remove-clone" && outputs === 1 ? value : visibleName;
  } } });
  return fields;
}

function routeAuth(fixture: Fixture, scenario: Scenario, events: Events) {
  return betterAuth({
    ...fixture.options,
    rateLimit: { enabled: false },
    advanced: { database: {
      ...fixture.options.advanced?.database,
      generateId: ({ model }) => model === "team" ? "team-c" : `${model}-a`,
      ...(scenario.mode === "page" || scenario.name === "guard-remove-clone" ? { defaultFindManyLimit: 1 } : {}),
    } },
    plugins: [organization({
      teams: { enabled: true, maximumTeams: async ({ organizationId, session }) => {
        events.push(["maximumTeams", "callback", [organizationId, session?.user.id]]);
        return 2;
      } },
      ...(scenario.mode === "owner-unset" ? {} : { schema: { team: { additionalFields: {} } } }),
      organizationHooks: {
        beforeCreateTeam({ team }) { events.push(["beforeCreateTeam", "hook", team]); return Promise.resolve(); },
        afterCreateTeam({ team }) { events.push(["afterCreateTeam", "hook", team]); return Promise.resolve(); },
        beforeUpdateTeam() { events.push(["beforeUpdateTeam", "hook"]); return Promise.resolve(); },
        afterUpdateTeam() { events.push(["afterUpdateTeam", "hook"]); return Promise.resolve(); },
        beforeDeleteTeam() { events.push(["beforeDeleteTeam", "hook"]); return Promise.resolve(); },
        afterDeleteTeam() { events.push(["afterDeleteTeam", "hook"]); return Promise.resolve(); },
      },
    }), { id: "ordinary-team-route-projection", schema: {
      team: { fields: routeFields(scenario, events) }, teamMember: { fields: memberFields(events) },
      member: { fields: { role: { type: "string", transform: { output(value) {
        events.push(["member.role", "output", value]); return value;
      } } } } },
      organization: { fields: { name: { type: "string", transform: { output(value) {
        events.push(["organization.name", "output", value]); return value;
      } } } } },
    } }],
  });
}

function nativeCall(auth: ReturnType<typeof routeAuth>, route: Route, headers: Headers, organizationId: string) {
  switch (route) {
    case "update": return auth.api.updateTeam({ headers, body: { teamId: "team-a", data: { name: "Updated", organizationId } } });
    case "remove": return auth.api.removeTeam({ headers, body: { teamId: "team-a", organizationId } });
    case "active": return auth.api.setActiveTeam({ headers, body: { teamId: "team-a" } });
    case "members": return auth.api.listTeamMembers({ headers, query: { teamId: "team-a" } });
    case "list": return auth.api.listOrganizationTeams({ headers, query: { organizationId } });
    case "user-list": return auth.api.listUserTeams({ headers });
    case "create": return auth.api.createTeam({ headers, body: { name: "Team C", organizationId } });
  }
}

function httpRequest(route: Route, headers: Headers, organizationId: string) {
  const paths: Record<Route, string> = {
    update: "update-team", remove: "remove-team", active: "set-active-team", members: "list-team-members",
    list: "list-teams", "user-list": "list-user-teams", create: "create-team",
  };
  const url = new URL(`${baseURL}/api/auth/organization/${paths[route]}`);
  if (route === "list") url.searchParams.set("organizationId", organizationId);
  if (route === "members") url.searchParams.set("teamId", "team-a");
  if (["list", "user-list", "members"].includes(route)) return new Request(url, { headers });
  const body = route === "update" ? { teamId: "team-a", data: { name: "Updated", organizationId } }
    : route === "create" ? { name: "Team C", organizationId }
    : route === "remove" ? { teamId: "team-a", organizationId } : { teamId: "team-a" };
  return new Request(url, { method: "POST", headers, body: JSON.stringify(body) });
}

function expectedEvents(scenario: Scenario, backend: Backend, organizationId: string): Events {
  const events: Events = [];
  if (["update", "remove", "list", "create"].includes(scenario.route)) {
    events.push(query("findOne", "member", ["userId", "user-a"], ["organizationId", organizationId]));
    events.push(["member.role", "output", "owner"]);
  }
  if (scenario.route === "user-list") return [
    query("findMany", "teamMember", ["userId", "user-a"]), ...memberEvents(backend, "team-a", "user-a"), ...teamOutput("Team A"),
  ];
  if (["update", "remove", "active", "members"].includes(scenario.route)) {
    events.push(query("findOne", "team", ["id", "team-a"], ...(scenario.route === "members" ? [] : [["organizationId", organizationId] as [string, string]])));
    if (scenario.mode === "scope") return events;
    events.push(...teamOutput("Team A"));
    if (scenario.mode !== "page" && scenario.name !== "guard-remove-clone") return events;
  }
  events.push(query("findMany", "team", ["organizationId", organizationId]));
  if (scenario.mode === "page" || scenario.name === "guard-remove-clone") events.push(...teamOutput("Team A"));
  else events.push(
    ["team.name", "output", "Team A"], ["team.name", "output", "Team B"],
    ["team.organizationId", "output", "organization"], ["team.organizationId", "output", "organization"],
  );
  if (scenario.name === "page-create") events.push(
    ["maximumTeams", "callback", ["organization", "user-a"]],
    query("findOne", "organization", ["id", "organization"]),
    ["organization.name", "output", "Organization"],
    ["beforeCreateTeam", "hook", { name: "Team C", organizationId: "organization" }],
    ["write", "create", "team"], ["team.organizationId", "input", "organization"],
    ["team.createdAt", "input", "native-date"], ["team.updatedAt", "input", "native-date"],
    ...teamOutput("Team C"), ["afterCreateTeam", "hook", publicTeam("team-c", "Team C")],
  );
  return events;
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const scenario of cases) {
    for (const entry of ["native", "http"] as const) {
      test(`${backend} Team route ${entry} preserves ${scenario.name}`, async () => {
        const fixture = await setup(backend, seedFields, { joins: scenario.joins ?? false });
        const events: Events = [];
        const organizationId = scenario.mode === "scope" ? "wrong-organization" : "organization";
        try {
          await seed(fixture, organizationId);
          const before = await state(fixture);
          const auth = routeAuth(fixture, scenario, events);
          traceAdapter((await auth.$context).adapter, events);
          const cookie = (await serializeSignedCookie("better-auth.session_token", "route-token", fixture.options.secret!)).split(";", 1)[0];
          const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
          const success = scenario.name === "page-create";
          const business = scenario.mode === "scope" || scenario.mode === "owner-unset" || scenario.name === "page-remove";
          const body = scenario.name === "page-remove"
            ? { code: "UNABLE_TO_REMOVE_LAST_TEAM", message: "Unable to remove last team" }
            : { code: "TEAM_NOT_FOUND", message: "Team not found" };
          if (entry === "native") {
            if (success) expect(await nativeCall(auth, scenario.route, headers, organizationId)).toStrictEqual(publicTeam("team-c", "Team C"));
            else {
              let caught: unknown;
              try { await nativeCall(auth, scenario.route, headers, organizationId); } catch (error) { caught = error; }
              expect(caught).toMatchObject(business ? { name: "APIError", statusCode: 400, body }
                : { name: "DataCloneError", message: "The object can not be cloned." });
            }
          } else {
            const response = await auth.handler(httpRequest(scenario.route, headers, organizationId));
            expect(response.status).toBe(success ? 200 : business ? 400 : 500);
            if (success) expect(await response.json()).toStrictEqual({
              ...publicTeam("team-c", "Team C"), createdAt: date(0).toISOString(), updatedAt: date(0).toISOString(),
            });
            else if (business) expect(await response.json()).toStrictEqual(body);
            else expect(await response.text()).toBe("");
          }
          expect(events).toStrictEqual(expectedEvents(scenario, backend, organizationId));
          expect(fixture.rawMembers()).toStrictEqual([fixture.stored(physicalMember("member-a", "team-a", "user-a"))]);
          expect(fixture.rawTeams()).toStrictEqual([
            fixture.stored(team("team-a", "Team A", 1)), fixture.stored(team("team-b", "Team B")),
            ...(success ? [fixture.stored(team("team-c", "Team C"))] : []),
          ]);
          expect(fixture.rawInvitations()).toStrictEqual([]);
          expect(await state(fixture)).toStrictEqual(before);
        } finally { fixture.close(); }
      });
    }
  }
}
