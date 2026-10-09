import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
type Backend = "memory" | "sqlite";
type Fields = Record<string, unknown>;
type Policies = Record<string, DBFieldAttribute>;
type Events = unknown[][];
const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);
const storedDate = (backend: Backend, offset: number) => backend === "sqlite" ? date(offset).toISOString() : date(offset);
const membershipKey = (teamId: string, userId: string) => createHash("sha256").update(JSON.stringify([teamId, userId])).digest("base64url");
const team = (id: string, name: string, memberCount = 0) => ({
  id, name, memberCount, organizationId: "organization", createdAt: date(0), updatedAt: date(0),
});

async function setup(backend: Backend, fields: Policies, config: {
  order?: "before" | "after"; joins?: boolean; teamFields?: Policies; memberId?: string;
} = {}) {
  const memory: Record<string, Fields[]> = Object.fromEntries([
    "user", "session", "account", "verification", "organization", "member", "invitation", "team", "teamMember",
  ].map(model => [model, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const organizationOptions = { teams: { enabled: true } };
  const own = organization(organizationOptions);
  const custom = { id: "ordinary-team-member-fields", schema: {
    teamMember: { fields }, ...(config.teamFields ? { team: { fields: config.teamFields } } : {}),
  } };
  const options: BetterAuthOptions = {
    database: database ?? memoryAdapter(memory), baseURL: "http://team-member-fields.test",
    secret: "team-member-field-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins: config.joins, generateId: ({ model }) => model === "teamMember" ? config.memberId ?? "member-a" : `${model}-a` } },
    plugins: config.order === "before" ? [custom, own] : [own, custom],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const context = await betterAuth(options).$context;
  for (const id of ["user-a", "user-b"]) await context.adapter.create({ model: "user", forceAllowId: true, data: {
    id, name: id, email: `${id}@team-member-fields.test`, emailVerified: true, image: null, createdAt: date(0), updatedAt: date(0),
  } });
  await context.adapter.create({ model: "organization", forceAllowId: true, data: {
    id: "organization", name: "Organization", slug: "organization", logo: null, metadata: "{}", createdAt: date(0),
  } });
  for (const row of [team("team-a", "Team A"), team("team-b", "Team B")]) {
    await context.adapter.create({ model: "team", forceAllowId: true, data: row });
  }
  return {
    org: getOrgAdapter(context, organizationOptions),
    async reader(readerFields: Policies, teamFields: Policies) {
      const reader = await betterAuth({ ...options, plugins: [organization(organizationOptions), {
        id: "ordinary-team-member-reader-fields", schema: { teamMember: { fields: readerFields }, team: { fields: teamFields } },
      }] }).$context;
      return getOrgAdapter(reader, organizationOptions);
    },
    rawMembers: () => structuredClone(database ? database.query("SELECT * FROM teamMember ORDER BY id").all() : memory.teamMember),
    rawTeams: () => structuredClone(database ? database.query("SELECT * FROM team ORDER BY id").all() : memory.team),
    stored: (row: Fields) => Object.fromEntries(Object.entries(row).map(([key, value]) => [
      key, backend === "sqlite" && value instanceof Date ? value.toISOString() : value,
    ])),
    close: () => database?.close(),
  };
}

function identity(field: string, events: Events): DBFieldAttribute {
  return { type: "string", transform: {
    input(value) { events.push([field, "input", value]); return value; },
    output(value) { events.push([field, "output", value]); return value; },
  } };
}

function assertServiceDates(values: unknown[], started: number, ended: number) {
  for (const value of values) {
    expect(value).toBeInstanceOf(Date);
    expect((value as Date).getTime()).toBeGreaterThanOrEqual(started);
    expect((value as Date).getTime()).toBeLessThanOrEqual(ended);
  }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const order of ["before", "after"] as const) {
    test(`${backend} TeamMember public projections follow ordinary plugin order: ${order}`, async () => {
      const events: Events = [];
      const inputDates: unknown[] = [];
      const fixture = await setup(backend, {
        teamId: identity("teamId", events),
        membershipKey: { type: "string", transform: {
          input(value) { events.push(["membershipKey", "input", value]); return `stored:${value}`; },
          output(value) { events.push(["membershipKey", "output", value]); return `visible:${value}`; },
        } },
        createdAt: { type: "date", transform: {
          input(value) { inputDates.push(value); events.push(["createdAt", "input", "native-date"]); return date(3); },
          output(value) { events.push(["createdAt", "output", value]); return 7; },
        } },
        probe: { type: "string", fieldName: "membershipKey", defaultValue: " Default ", transform: {
          input(value) { events.push(["probe", "input", value]); return String(value).trim(); },
          output(value) { events.push(["probe", "output", value]); return undefined; },
        } },
        stamp: { type: "date", fieldName: "createdAt", defaultValue: date(5), transform: {
          input(value) { events.push(["stamp", "input", value]); return value; },
          output(value) { events.push(["stamp", "output", value]); return date(6); },
        } },
      }, { order });
      const output = {
        teamId: "team-a", userId: "user-a", createdAt: order === "after" ? 7 : date(5),
        probe: undefined, stamp: date(6), id: "member-a",
      };
      const outputEvents = [
        ...(order === "after" ? [
          ["teamId", "output", "team-a"], ["membershipKey", "output", "Default"], ["createdAt", "output", storedDate(backend, 5)],
        ] : []),
        ["probe", "output", "Default"], ["stamp", "output", storedDate(backend, 5)],
      ];
      const rows = [fixture.stored({ id: "member-a", teamId: "team-a", userId: "user-a", membershipKey: "Default", createdAt: date(5) })];
      const teams = (count: number) => [fixture.stored(team("team-a", "Team A", count)), fixture.stored(team("team-b", "Team B"))];
      try {
        const started = Date.now();
        expect(await fixture.org.findOrCreateTeamMember({ teamId: "team-a", userId: "user-a" })).toStrictEqual(output);
        assertServiceDates(inputDates, started, Date.now());
        expect(inputDates.length).toBe(order === "after" ? 1 : 0);
        expect(events.splice(0)).toStrictEqual([
          ...(order === "after" ? [
            ["teamId", "input", "team-a"], ["membershipKey", "input", membershipKey("team-a", "user-a")], ["createdAt", "input", "native-date"],
          ] : []),
          ["probe", "input", " Default "], ["stamp", "input", date(5)], ...outputEvents,
        ]);
        expect(fixture.rawMembers()).toStrictEqual(rows);
        expect(fixture.rawTeams()).toStrictEqual(teams(1));
        expect(await fixture.org.findTeamMember({ teamId: "team-a", userId: "user-a" })).toStrictEqual(output);
        expect(events.splice(0)).toStrictEqual(outputEvents);
        expect(await fixture.org.listTeamMembers({ teamId: "team-a" })).toStrictEqual([output]);
        expect(events.splice(0)).toStrictEqual(outputEvents);
        expect(await fixture.org.findOrCreateTeamMember({ teamId: "team-a", userId: "user-a" })).toStrictEqual(output);
        expect(events.splice(0)).toStrictEqual(outputEvents);
        expect(await fixture.org.countTeamMembers({ teamId: "team-a" })).toBe(1);
        expect(await fixture.org.addTeamMemberWithLimit({ teamId: "team-a", userId: "user-b", maximumMembersPerTeam: 1 }))
          .toStrictEqual({ status: "limitReached" });
        expect(events.splice(0)).toStrictEqual([]);
        expect(await fixture.org.addTeamMemberWithLimit({ teamId: "team-a", userId: "user-a", maximumMembersPerTeam: 0 }))
          .toStrictEqual({ status: "added", member: output });
        expect(events.splice(0)).toStrictEqual(outputEvents);
        expect(fixture.rawMembers()).toStrictEqual(rows);
        expect(fixture.rawTeams()).toStrictEqual(teams(1));
        for (let attempt = 0; attempt < 2; attempt++) {
          expect(await fixture.org.removeTeamMember({ teamId: "team-a", userId: "user-a" })).toBeUndefined();
          expect(events.splice(0)).toStrictEqual([]);
          expect(fixture.rawMembers()).toStrictEqual([]);
          expect(fixture.rawTeams()).toStrictEqual(teams(0));
        }
      } finally { fixture.close(); }
    });
  }

  for (const limited of [false, true]) {
    for (const mode of ["once-key", "once-pair", "persistent", "input"] as const) {
      test(`${backend} TeamMember ${limited ? "limited" : "unlimited"} creation preserves ${mode} recovery and quota`, async () => {
        const events: Events = [];
        const inputDates: unknown[] = [];
        const failure = new Error(`team-member-${mode === "input" ? "input" : "output"}-failed`);
        let outputs = 0;
        const fixture = await setup(backend, {
          teamId: identity("teamId", events), userId: identity("userId", events),
          membershipKey: { type: "string", transform: {
            input(value) {
              events.push(["membershipKey", "input", value]);
              if (mode === "input") throw failure;
              return mode === "once-pair" ? "alternate-key" : value;
            },
            output(value) {
              events.push(["membershipKey", "output", value]);
              outputs++;
              if (mode === "persistent" || outputs === 1) {
                if (mode === "once-pair") return Promise.reject(failure);
                throw failure;
              }
              return `visible:${value}`;
            },
          } },
          createdAt: { type: "date", transform: {
            input(value) { inputDates.push(value); events.push(["createdAt", "input", "native-date"]); return date(0); },
            output(value) { events.push(["createdAt", "output", value]); return date(1); },
          } },
        });
        const key = mode === "once-pair" ? "alternate-key" : membershipKey("team-a", "user-a");
        const inputEvents = [
          ["teamId", "input", "team-a"], ["userId", "input", "user-a"], ["membershipKey", "input", membershipKey("team-a", "user-a")],
        ];
        const partialOutputEvents = [["teamId", "output", "team-a"], ["userId", "output", "user-a"], ["membershipKey", "output", key]];
        const output = { teamId: "team-a", userId: "user-a", createdAt: date(1), id: "member-a" };
        try {
          const started = Date.now();
          const operation = limited
            ? fixture.org.addTeamMemberWithLimit({ teamId: "team-a", userId: "user-a", maximumMembersPerTeam: 1 })
            : fixture.org.findOrCreateTeamMember({ teamId: "team-a", userId: "user-a" });
          if (mode === "input" || mode === "persistent") await expect(operation).rejects.toBe(failure);
          else expect(await operation).toStrictEqual(limited ? { status: "added", member: output } : output);
          assertServiceDates(inputDates, started, Date.now());
          expect(inputDates.length).toBe(mode === "input" ? 0 : 1);
          expect(events).toStrictEqual(mode === "input" ? inputEvents : [
            ...inputEvents, ["createdAt", "input", "native-date"], ...partialOutputEvents, ...partialOutputEvents,
            ...(mode === "persistent" ? [] : [["createdAt", "output", storedDate(backend, 0)]]),
          ]);
          expect(fixture.rawMembers()).toStrictEqual(mode === "input" || mode === "persistent" ? [] : [fixture.stored({
            id: "member-a", teamId: "team-a", userId: "user-a", membershipKey: key, createdAt: date(0),
          })]);
          expect(fixture.rawTeams()).toStrictEqual([fixture.stored(team("team-a", "Team A")), fixture.stored(team("team-b", "Team B"))]);
        } finally { fixture.close(); }
      });
    }
  }

  for (const mode of ["key-priority", "pair-fallback"] as const) {
    test(`${backend} TeamMember existing lookup preserves ${mode}`, async () => {
      const events: Events = [];
      const sourceTeam = mode === "key-priority" ? "team-b" : "team-a";
      const sourceUser = mode === "key-priority" ? "user-b" : "user-a";
      const key = mode === "key-priority" ? membershipKey("team-a", "user-a") : "alternate-key";
      const fixture = await setup(backend, {
        teamId: identity("teamId", events), userId: identity("userId", events),
        membershipKey: { type: "string", transform: {
          input() { return key; }, output(value) { events.push(["membershipKey", "output", value]); return `visible:${value}`; },
        } },
        createdAt: { type: "date", transform: {
          input() { return date(0); }, output(value) { events.push(["createdAt", "output", value]); return date(1); },
        } },
      });
      const output = { teamId: sourceTeam, userId: sourceUser, createdAt: date(1), id: "member-a" };
      try {
        expect(await fixture.org.findOrCreateTeamMember({ teamId: sourceTeam, userId: sourceUser })).toStrictEqual(output);
        events.splice(0);
        const rows = [fixture.stored({ id: "member-a", teamId: sourceTeam, userId: sourceUser, membershipKey: key, createdAt: date(0) })];
        const teams = [fixture.stored(team("team-a", "Team A", Number(sourceTeam === "team-a"))), fixture.stored(team("team-b", "Team B", Number(sourceTeam === "team-b")))];
        for (const limited of [false, true]) {
          const result = limited
            ? await fixture.org.addTeamMemberWithLimit({ teamId: "team-a", userId: "user-a", maximumMembersPerTeam: 0 })
            : await fixture.org.findOrCreateTeamMember({ teamId: "team-a", userId: "user-a" });
          expect(result).toStrictEqual(limited ? { status: "added", member: output } : output);
          expect(events.splice(0)).toStrictEqual([
            ["teamId", "output", sourceTeam], ["userId", "output", sourceUser], ["membershipKey", "output", key], ["createdAt", "output", storedDate(backend, 0)],
          ]);
          expect(fixture.rawMembers()).toStrictEqual(rows);
          expect(fixture.rawTeams()).toStrictEqual(teams);
        }
      } finally { fixture.close(); }
    });
  }

  for (const outputError of [false, true]) {
    test(`${backend} TeamMember removal preserves committed effects after ${outputError ? "Team output failure" : "success"}`, async () => {
      const events: Events = [];
      const failure = new Error("team-remove-output-failed");
      let removing = false;
      const fixture = await setup(backend, {
        createdAt: { type: "date", transform: { input() { return date(0); } } },
      }, { teamFields: {
        name: { type: "string", transform: { output(value) { events.push(["team.name", "output", value]); return value; } } },
        memberCount: { type: "number", transform: { output(value) {
          events.push(["team.memberCount", "output", value]);
          if (removing && outputError) throw failure;
          return value;
        } } },
        createdAt: { type: "date", transform: { output(value) { events.push(["team.createdAt", "output", value]); return date(0); } } },
      } });
      try {
        expect(await fixture.org.findOrCreateTeamMember({ teamId: "team-a", userId: "user-a" })).toStrictEqual({
          teamId: "team-a", userId: "user-a", createdAt: date(0), id: "member-a",
        });
        events.splice(0);
        removing = true;
        const operation = fixture.org.removeTeamMember({ teamId: "team-a", userId: "user-a" });
        if (outputError) await expect(operation).rejects.toBe(failure);
        else expect(await operation).toBeUndefined();
        expect(events.splice(0)).toStrictEqual([
          ["team.name", "output", "Team A"], ["team.memberCount", "output", 0],
          ...(outputError ? [] : [["team.createdAt", "output", storedDate(backend, 0)]]),
        ]);
        const teams = [fixture.stored(team("team-a", "Team A")), fixture.stored(team("team-b", "Team B"))];
        expect(fixture.rawMembers()).toStrictEqual([]);
        expect(fixture.rawTeams()).toStrictEqual(teams);
        expect(await fixture.org.removeTeamMember({ teamId: "team-a", userId: "user-a" })).toBeUndefined();
        expect(events).toStrictEqual([]);
        expect(fixture.rawMembers()).toStrictEqual([]);
        expect(fixture.rawTeams()).toStrictEqual(teams);
      } finally { fixture.close(); }
    });
  }

  for (const joins of [false, true]) {
    test(`${backend} TeamMember ${joins ? "native" : "fallback"} joins project parent fields before the team`, async () => {
      const events: Events = [];
      let reading = false;
      const fixture = await setup(backend, {
        teamId: { type: "string", references: { model: "team", field: "id" }, transform: {
          output(value) { events.push(["teamId", "output", value]); return reading ? "team-b" : value; },
        } },
        userId: { type: "string", transform: { output(value) { events.push(["userId", "output", value]); return value; } } },
        membershipKey: { type: "string", transform: { output(value) { events.push(["membershipKey", "output", value]); return `visible:${value}`; } } },
        createdAt: { type: "date", transform: {
          input() { return date(0); }, output(value) { events.push(["createdAt", "output", value]); return date(1); },
        } },
      }, { joins, teamFields: { name: { type: "string", transform: {
        output(value) { events.push(["team.name", "output", value]); return `Visible ${value}`; },
      } } } });
      try {
        await fixture.org.findOrCreateTeamMember({ teamId: "team-a", userId: "user-a" });
        events.splice(0);
        reading = true;
        const selected = joins ? "A" : "B";
        expect(await fixture.org.listTeamsByUser({ userId: "user-a" })).toStrictEqual([{
          id: `team-${selected.toLowerCase()}`, name: `Visible Team ${selected}`, organizationId: "organization", createdAt: date(0), updatedAt: date(0),
        }]);
        expect(events).toStrictEqual([
          ["teamId", "output", "team-a"], ["userId", "output", "user-a"], ["membershipKey", "output", membershipKey("team-a", "user-a")],
          ["createdAt", "output", storedDate(backend, 0)], ["team.name", "output", `Team ${selected}`],
        ]);
        expect(fixture.rawMembers()).toStrictEqual([fixture.stored({
          id: "member-a", teamId: "team-a", userId: "user-a", membershipKey: membershipKey("team-a", "user-a"), createdAt: date(0),
        })]);
        expect(fixture.rawTeams()).toStrictEqual([fixture.stored(team("team-a", "Team A", 1)), fixture.stored(team("team-b", "Team B"))]);
      } finally { fixture.close(); }
    });

    for (const relation of ["missing", "many", "many-first-error"] as const) {
      test(`${backend} TeamMember ${joins ? "native" : "fallback"} joins preserve ${relation} replacement relations`, async () => {
        const events: Events = [];
        const memberId = relation === "missing" ? "member-a" : "organization";
        const failure = new Error("team-member-team-name-failed");
        const fields: Policies = {
          teamId: identity("teamId", events), userId: identity("userId", events),
          membershipKey: { type: "string", transform: { output(value) { events.push(["membershipKey", "output", value]); return `visible:${value}`; } } },
          createdAt: { type: "date", transform: {
            input() { return date(0); }, output(value) { events.push(["createdAt", "output", value]); return date(1); },
          } },
        };
        const fixture = await setup(backend, fields, { joins, memberId });
        try {
          expect(await fixture.org.findOrCreateTeamMember({ teamId: "team-a", userId: "user-a" })).toStrictEqual({
            teamId: "team-a", userId: "user-a", createdAt: date(1), id: memberId,
          });
          const reader = await fixture.reader({
            ...fields,
            ...(relation === "missing" ? { userId: { ...fields.userId, references: { model: "team", field: "id" } } } : {}),
          }, {
            name: { type: "string", transform: { output(value) {
              events.push(["team.name", "output", value]);
              if (relation === "many-first-error" && value === "Team A") throw failure;
              return `Visible ${value}`;
            } } },
            createdAt: { type: "date", transform: { output(value) { events.push(["team.createdAt", "output", value]); return value; } } },
            ...(relation !== "missing" ? { organizationId: { type: "string" as const, references: { model: "teamMember", field: "id" } } } : {}),
          });
          events.splice(0);
          if (relation === "missing") {
            let caught: unknown;
            try { await reader.listTeamsByUser({ userId: "user-a" }); } catch (error) { caught = error; }
            console.info("TeamMember missing join error", {
              backend, joins, error: caught,
              ...(caught instanceof Error ? { class: caught.name, message: caught.message } : {}),
            });
            expect(caught).toBeInstanceOf(TypeError);
          } else if (relation === "many-first-error") {
            await expect(reader.listTeamsByUser({ userId: "user-a" })).rejects.toBe(failure);
          } else {
            expect(await reader.listTeamsByUser({ userId: "user-a" })).toStrictEqual([{
              0: { ...team("team-a", "Visible Team A", 1) },
              1: { ...team("team-b", "Visible Team B") },
            }]);
          }
          expect(events).toStrictEqual([
            ["teamId", "output", "team-a"], ["userId", "output", "user-a"], ["membershipKey", "output", membershipKey("team-a", "user-a")],
            ["createdAt", "output", storedDate(backend, 0)],
            ...(relation === "missing" ? [] : [["team.name", "output", "Team A"]]),
            ...(relation === "many" ? [
              ["team.createdAt", "output", storedDate(backend, 0)], ["team.name", "output", "Team B"], ["team.createdAt", "output", storedDate(backend, 0)],
            ] : []),
          ]);
          expect(fixture.rawMembers()).toStrictEqual([fixture.stored({
            id: memberId, teamId: "team-a", userId: "user-a", membershipKey: membershipKey("team-a", "user-a"), createdAt: date(0),
          })]);
          expect(fixture.rawTeams()).toStrictEqual([fixture.stored(team("team-a", "Team A", 1)), fixture.stored(team("team-b", "Team B"))]);
        } finally { fixture.close(); }
      });
    }
  }
}
