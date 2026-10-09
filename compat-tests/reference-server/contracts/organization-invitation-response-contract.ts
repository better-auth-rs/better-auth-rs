import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { date, storedDate, team, type Backend, type Events, type Fields, type Policies } from "./organization-team-member-contract";

type Route = "get" | "list" | "list-user" | "accept" | "reject" | "cancel";
type Scenario = { name: string; route: Route; joins?: boolean; undefinedName?: boolean; cloneError?: boolean };
const cases: Scenario[] = [
  { name: "get-collision", route: "get" },
  { name: "get-clone-before-inviter", route: "get", cloneError: true },
  { name: "list", route: "list" },
  { name: "list-user-function-fallback", route: "list-user" },
  { name: "list-user-function-native", route: "list-user", joins: true },
  { name: "list-user-undefined", route: "list-user", undefinedName: true },
  { name: "accept", route: "accept" },
  { name: "reject", route: "reject" },
  { name: "cancel", route: "cancel" },
];
const baseURL = "http://team-member-fields.test";
const models = ["user", "session", "account", "verification", "organization", "member", "invitation", "team", "teamMember"] as const;
const user = (id: string) => ({
  id, name: id, email: `${id}@team-member-fields.test`, emailVerified: true,
  image: null, createdAt: date(0), updatedAt: date(0),
});
const invitation = (status = "pending") => ({
  id: "invitation-a", organizationId: "organization", email: user("user-b").email, role: "member",
  teamId: null, status, expiresAt: date(30), createdAt: date(0), inviterId: "user-a",
});
const member = (id: string, userId: string, role: string) => ({
  id, organizationId: "organization", userId, role, createdAt: date(0),
});

async function setup(backend: Backend, scenario: Scenario) {
  const memory: Record<string, Fields[]> = Object.fromEntries(models.map(model => [model, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options: BetterAuthOptions = {
    database: database ?? memoryAdapter(memory), baseURL,
    secret: "invitation-response-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    advanced: { database: { joins: scenario.joins ?? false, generateId: ({ model }) => `${model}-a` } },
    plugins: [organization({ teams: { enabled: true } })],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const context = await betterAuth(options).$context;
  const create = (model: string, data: Fields) => context.adapter.create({ model, data, forceAllowId: true });
  for (const id of ["user-a", "user-b"]) await create("user", user(id));
  await create("organization", {
    id: "organization", name: "Organization", slug: "organization", logo: null, metadata: "{}", createdAt: date(0),
  });
  for (const row of [team("team-a", "Team A"), team("team-b", "Team B")]) await create("team", row);
  await create("member", member("owner-member", "user-a", "owner"));
  await create("invitation", invitation());
  const actor = scenario.route === "list" || scenario.route === "cancel" ? "user-a" : "user-b";
  await create("session", {
    id: "session-a", userId: actor, token: "invitation-response-token", createdAt: date(0), updatedAt: date(0),
    expiresAt: new Date("2100-01-01T00:00:00.000Z"), ipAddress: null, userAgent: null,
    activeOrganizationId: null, activeTeamId: null,
  });
  return {
    options,
    snapshot: () => Object.fromEntries(models.map(model => [model, structuredClone(database
      ? database.query(`SELECT * FROM "${model}" ORDER BY id`).all()
      : memory[model].toSorted((left, right) => String(left.id).localeCompare(String(right.id))))])) as Record<string, Fields[]>,
    stored: (row: Fields) => Object.fromEntries(Object.entries(row).map(([key, value]) => [
      key, backend === "sqlite" && value instanceof Date ? value.toISOString() : value,
    ])),
    close: () => database?.close(),
  };
}

function outputField(name: string, events: Events, output: (value: unknown) => unknown, attributes: DBFieldAttribute): DBFieldAttribute {
  // JavaScript plugins can return Function values outside the declared DBPrimitive type.
  Object.defineProperty(attributes, "transform", { enumerable: true, value: { output(value: unknown) {
    events.push([name, "output", value]);
    return output(value);
  } } });
  return attributes;
}

function nativeValues(events: Events) {
  const invitationFunction = () => { events.push(["invitation.createdAt", "called"]); return "invitation-function"; };
  const memberFunction = () => { events.push(["member.probeFunction", "called"]); return "member-function"; };
  const organizationFunction = () => { events.push(["organization.name", "called"]); return "organization-function"; };
  return { invitationFunction, memberFunction, organizationFunction };
}
type NativeValues = ReturnType<typeof nativeValues>;

function responseAuth(options: BetterAuthOptions, scenario: Scenario, events: Events, values: NativeValues) {
  const invitationFields: Policies = {
    createdAt: outputField("invitation.createdAt", events, () => values.invitationFunction, { type: "date" }),
  };
  for (const [name, value] of [
    ["probeUndefined", undefined], ["probeNull", null], ["organizationName", "shadow-name"],
    ["organizationSlug", "shadow-slug"], ["inviterEmail", "shadow-email"],
  ] as const) invitationFields[name] = outputField(`invitation.${name}`, events, () => value, {
    type: "string", required: false, fieldName: "role",
  });
  const memberFields: Policies = {
    createdAt: { type: "date", transform: {
      input(value) {
        expect(value).toBeInstanceOf(Date);
        events.push(["member.createdAt", "input", "native-date"]);
        return date(0);
      },
      output(value) { events.push(["member.createdAt", "output", value]); return date(0); },
    } },
  };
  for (const [name, value] of [
    ["probeUndefined", undefined], ["probeNull", null], ["probeFunction", values.memberFunction],
  ] as const) memberFields[name] = outputField(`member.${name}`, events, () => value, {
    type: "string", required: false, fieldName: "role",
  });
  const organizationFields: Policies = {
    name: outputField("organization.name", events, value => scenario.cloneError ? values.organizationFunction
      : scenario.route === "list-user" ? scenario.undefinedName ? undefined : values.organizationFunction : value, { type: "string" }),
    ...(scenario.route === "get" ? { slug: outputField("organization.slug", events, () => null, { type: "string" }) } : {}),
  };
  return betterAuth({
    ...options,
    plugins: [organization({
      teams: { enabled: true },
      schema: {
        organization: { additionalFields: { name: { type: "string", returned: false } } },
        invitation: { additionalFields: { createdAt: { type: "date", returned: false } } },
        member: { additionalFields: { createdAt: { type: "date", returned: false } } },
      },
      organizationHooks: {
        beforeAcceptInvitation(data) { events.push(["beforeAcceptInvitation", "hook", data]); return Promise.resolve(); },
        afterAcceptInvitation(data) { events.push(["afterAcceptInvitation", "hook", data]); return Promise.resolve(); },
        beforeRejectInvitation(data) { events.push(["beforeRejectInvitation", "hook", data]); return Promise.resolve(); },
        afterRejectInvitation(data) { events.push(["afterRejectInvitation", "hook", data]); return Promise.resolve(); },
        beforeCancelInvitation(data) { events.push(["beforeCancelInvitation", "hook", data]); return Promise.resolve(); },
        afterCancelInvitation(data) { events.push(["afterCancelInvitation", "hook", data]); return Promise.resolve(); },
      },
    }), { id: "ordinary-invitation-response-fields", schema: {
      invitation: { fields: invitationFields }, member: { fields: memberFields }, organization: { fields: organizationFields },
      session: { fields: { updatedAt: { type: "date", onUpdate: () => date(0), transform: { input(value) {
        expect(value).toBeInstanceOf(Date);
        events.push(["session.updatedAt", "input", "native-date"]);
        return date(0);
      } } } } },
    } }],
  });
}

function visibleInvitation(values: NativeValues, status = "pending") {
  return {
    organizationId: "organization", email: user("user-b").email, role: "member", teamId: null, status,
    expiresAt: date(30), createdAt: values.invitationFunction, inviterId: "user-a",
    probeUndefined: undefined, probeNull: null, organizationName: "shadow-name", organizationSlug: "shadow-slug",
    inviterEmail: "shadow-email", id: "invitation-a",
  };
}
function visibleMember(values: NativeValues) {
  return {
    organizationId: "organization", userId: "user-b", role: "member", createdAt: date(0),
    probeUndefined: undefined, probeNull: null, probeFunction: values.memberFunction, id: "member-a",
  };
}
function expectedResponse(scenario: Scenario, values: NativeValues) {
  switch (scenario.route) {
    case "get": return { ...visibleInvitation(values), organizationName: undefined, organizationSlug: null, inviterEmail: user("user-a").email };
    case "list": return [visibleInvitation(values)];
    case "list-user": return [{ ...visibleInvitation(values), organizationName: scenario.undefinedName ? undefined : values.organizationFunction }];
    case "accept": return { invitation: visibleInvitation(values, "accepted"), member: visibleMember(values) };
    case "reject": return { invitation: visibleInvitation(values, "rejected"), member: null };
    case "cancel": return visibleInvitation(values, "canceled");
  }
}

function outputEvents(backend: Backend, model: "invitation" | "member", role = "member") {
  return [
    [`${model}.createdAt`, "output", storedDate(backend, 0)],
    ...["probeUndefined", "probeNull", ...(model === "invitation"
      ? ["organizationName", "organizationSlug", "inviterEmail"] : ["probeFunction"])]
      .map(name => [`${model}.${name}`, "output", role]),
  ];
}
function expectedEvents(backend: Backend, scenario: Scenario, values: NativeValues) {
  const invitationEvents = outputEvents(backend, "invitation");
  const organizationEvents = [["organization.name", "output", "Organization"]];
  const organization = { slug: "organization", logo: null, createdAt: date(0), metadata: "{}", id: "organization" };
  const beforeHook = { invitation: visibleInvitation(values), user: user("user-b"), organization };
  switch (scenario.route) {
    case "get": return [...invitationEvents, ...organizationEvents, ["organization.slug", "output", "organization"],
      ...(scenario.cloneError ? [] : outputEvents(backend, "member", "owner"))];
    case "list": return [...outputEvents(backend, "member", "owner"), ...invitationEvents];
    case "list-user": return [...invitationEvents, ...organizationEvents];
    case "accept": return [
      ...invitationEvents, ...organizationEvents, ["beforeAcceptInvitation", "hook", beforeHook], ...invitationEvents,
      ["member.createdAt", "input", "native-date"], ...outputEvents(backend, "member"),
      ["session.updatedAt", "input", "native-date"],
      ["afterAcceptInvitation", "hook", { invitation: visibleInvitation(values, "accepted"), member: visibleMember(values), user: user("user-b"), organization }],
    ];
    case "reject": return [
      ...invitationEvents, ...organizationEvents, ["beforeRejectInvitation", "hook", beforeHook], ...invitationEvents,
      ["afterRejectInvitation", "hook", { ...beforeHook, invitation: visibleInvitation(values, "rejected") }],
    ];
    case "cancel": return [
      ...invitationEvents, ...outputEvents(backend, "member", "owner"), ...organizationEvents,
      ["beforeCancelInvitation", "hook", { invitation: visibleInvitation(values), cancelledBy: user("user-a"), organization }],
      ...invitationEvents,
      ["afterCancelInvitation", "hook", { invitation: visibleInvitation(values, "canceled"), cancelledBy: user("user-a"), organization }],
    ];
  }
}

function expectOrdered(actual: unknown, expected: unknown) {
  expect(actual).toStrictEqual(expected);
  if (typeof expected === "function") expect(actual).toBe(expected);
  if (expected === null || typeof expected !== "object" || expected instanceof Date) return;
  expect(Object.keys(actual as object)).toStrictEqual(Object.keys(expected));
  for (const [name, value] of Object.entries(expected)) expectOrdered(Reflect.get(actual as object, name), value);
}

function nativeCall(auth: ReturnType<typeof responseAuth>, route: Route, headers: Headers) {
  switch (route) {
    case "get": return auth.api.getInvitation({ headers, query: { id: "invitation-a" } });
    case "list": return auth.api.listInvitations({ headers, query: { organizationId: "organization" } });
    case "list-user": return auth.api.listUserInvitations({ headers });
    case "accept": return auth.api.acceptInvitation({ headers, body: { invitationId: "invitation-a" } });
    case "reject": return auth.api.rejectInvitation({ headers, body: { invitationId: "invitation-a" } });
    case "cancel": return auth.api.cancelInvitation({ headers, body: { invitationId: "invitation-a" } });
  }
}
function httpRequest(route: Route, headers: Headers) {
  const path = route === "get" ? "get-invitation?id=invitation-a"
    : route === "list" ? "list-invitations?organizationId=organization"
    : route === "list-user" ? "list-user-invitations" : `${route}-invitation`;
  return new Request(`${baseURL}/api/auth/organization/${path}`, {
    headers, ...(route === "get" || route === "list" || route === "list-user" ? {} : {
      method: "POST", body: JSON.stringify({ invitationId: "invitation-a" }),
    }),
  });
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const scenario of cases) {
    for (const entry of ["native", "http"] as const) {
      test(`${backend} Invitation response ${entry} preserves ${scenario.name}`, async () => {
        const fixture = await setup(backend, scenario);
        const events: Events = [];
        const values = nativeValues(events);
        try {
          const before = fixture.snapshot();
          const auth = responseAuth(fixture.options, scenario, events, values);
          const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", fixture.options.secret!)).split(";", 1)[0];
          const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
          const expected = expectedResponse(scenario, values);
          if (entry === "native") {
            if (scenario.cloneError) {
              let caught: unknown;
              try { await nativeCall(auth, scenario.route, headers); } catch (error) { caught = error; }
              expect(caught).toMatchObject({ name: "DataCloneError", message: "The object can not be cloned." });
            } else expectOrdered(await nativeCall(auth, scenario.route, headers), expected);
          }
          else {
            const response = await auth.handler(httpRequest(scenario.route, headers));
            expect(response.status).toBe(scenario.cloneError ? 500 : 200);
            if (scenario.cloneError) expect(await response.text()).toBe("");
            else {
              expect(response.headers.get("content-type")).toContain("application/json");
              expect(await response.text()).toBe(JSON.stringify(expected));
            }
          }
          expect(events).toStrictEqual(expectedEvents(backend, scenario, values));
          if (scenario.route === "accept" || scenario.route === "reject" || scenario.route === "cancel") {
            const status = scenario.route === "accept" ? "accepted" : scenario.route === "reject" ? "rejected" : "canceled";
            before.invitation = [fixture.stored(invitation(status))];
          }
          if (scenario.route === "accept") {
            before.member = [fixture.stored(member("member-a", "user-b", "member")), ...before.member];
            before.session = before.session.map(session => ({ ...session, activeOrganizationId: "organization" }));
          }
          expect(fixture.snapshot()).toStrictEqual(before);
        } finally { fixture.close(); }
      });
    }
  }
}
