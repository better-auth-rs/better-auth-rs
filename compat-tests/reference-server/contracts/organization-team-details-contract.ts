import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import {
  date, storedDate, membershipKey, setup, team,
  type Backend, type Events, type Fields, type Policies,
} from "./organization-team-member-contract";

export const seedFields: Policies = {
  createdAt: { type: "date", transform: { input() { return date(0); } } },
};

export const publicMember = (id: string, teamId: string, userId: string, offset = 1) => ({
  id, teamId, userId, createdAt: date(offset),
});

export const physicalMember = (id: string, teamId: string, userId: string) => ({
  ...publicMember(id, teamId, userId, 0), membershipKey: membershipKey(teamId, userId),
});

export const publicTeam = (id: string, name: string, members?: Fields[]) => {
  const { memberCount: _, ...output } = team(id, name);
  return { ...output, ...(members === undefined ? {} : { members }) };
};

export function parentFields(events: Events, remap = false): Policies {
  return { name: { type: "string", transform: { output(value) {
    events.push(["team.name", "output", value]);
    return remap ? "team-b" : value;
  } } } };
}

export function memberFields(events: Events, reference = "id", unique = false, failure?: Error): Policies {
  return Object.fromEntries(["teamId", "userId", "membershipKey", "createdAt"].map(name => [name, {
    type: name === "createdAt" ? "date" : "string",
    ...(name === "teamId" ? { references: { model: "team", field: reference }, unique } : {}),
    transform: { output(value) {
      events.push([name, "output", value]);
      if (failure && name === "userId") throw failure;
      return name === "createdAt" ? date(1) : value;
    } },
  } satisfies DBFieldAttribute]));
}

export function memberEvents(backend: Backend, teamId: string, userId: string) {
  return [
    ["teamId", "output", teamId], ["userId", "output", userId],
    ["membershipKey", "output", membershipKey(teamId, userId)],
    ["createdAt", "output", storedDate(backend, 0)],
  ];
}

type Fixture = Awaited<ReturnType<typeof setup>>;

export async function seedMember(fixture: Fixture, id: string, teamId: string, userId: string) {
  const writer = await fixture.reader(seedFields, {}, { memberId: id });
  expect(await writer.findOrCreateTeamMember({ teamId, userId })).toStrictEqual(publicMember(id, teamId, userId, 0));
}

function assertStorage(fixture: Fixture, members: Fields[], counts: [number, number], name = "Team A") {
  expect(fixture.rawMembers()).toStrictEqual(members.map(row => fixture.stored(row)));
  expect(fixture.rawTeams()).toStrictEqual([
    fixture.stored(team("team-a", name, counts[0])), fixture.stored(team("team-b", "Team B", counts[1])),
  ]);
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const joins of [false, true]) {
    test(`${backend} Team details ${joins ? "native" : "fallback"} preserve scoped queries before output`, async () => {
      const fixture = await setup(backend, seedFields, { joins });
      const events: Events = [];
      try {
        await seedMember(fixture, "member-a", "team-a", "user-a");
        const reader = await fixture.reader(memberFields(events, "id", false, new Error("unexpected-child-output")), {
          ...parentFields(events),
          organizationId: { type: "string", transform: {
            input(value) { events.push(["team.organizationId", "input", value]); return String(value).trim(); },
            output(value) { events.push(["team.organizationId", "output", value]); return "visible-organization"; },
          } },
        });
        for (const [teamId, organizationId] of [["missing-team", "organization"], ["team-a", "wrong-organization"]]) {
          expect(await reader.findTeamById({ teamId, organizationId, includeTeamMembers: true })).toBeNull();
          expect(events.splice(0)).toStrictEqual([["team.organizationId", "input", organizationId]]);
        }
        for (const organizationId of [" organization ", undefined, ""]) {
          expect(await reader.findTeamById({ teamId: "team-a", organizationId, includeTeamMembers: false })).toStrictEqual({
            ...publicTeam("team-a", "Team A"), organizationId: "visible-organization",
          });
          expect(events.splice(0)).toStrictEqual([
            ...(organizationId === " organization " ? [["team.organizationId", "input", organizationId]] : []),
            ["team.name", "output", "Team A"], ["team.organizationId", "output", "organization"],
          ]);
        }
        const withoutRelationship = await fixture.reader({ ...memberFields(events), teamId: { type: "string" } }, parentFields(events));
        expect(await withoutRelationship.findTeamById({ teamId: "team-a", organizationId: "organization", includeTeamMembers: false })).toStrictEqual(publicTeam("team-a", "Team A"));
        expect(events.splice(0)).toStrictEqual([["team.name", "output", "Team A"]]);
        assertStorage(fixture, [physicalMember("member-a", "team-a", "user-a")], [1, 0]);
      } finally { fixture.close(); }
    });

    test(`${backend} Team details ${joins ? "native" : "fallback"} use the selected parent before membership output`, async () => {
      const fixture = await setup(backend, seedFields, { joins });
      const events: Events = [];
      try {
        await seedMember(fixture, "member-a", "team-a", "user-a");
        await seedMember(fixture, "member-b", "team-b", "user-b");
        await fixture.org.updateTeam("team-a", { name: "team-a", updatedAt: date(0) });
        const reader = await fixture.reader(memberFields(events, "name"), parentFields(events, true));
        const [id, teamId, userId] = joins ? ["member-a", "team-a", "user-a"] as const : ["member-b", "team-b", "user-b"] as const;
        expect(await reader.findTeamById({ teamId: "team-a", organizationId: "organization", includeTeamMembers: true })).toStrictEqual(
          publicTeam("team-a", "team-b", [publicMember(id, teamId, userId)]),
        );
        expect(events).toStrictEqual([["team.name", "output", "team-a"], ...memberEvents(backend, teamId, userId)]);
        assertStorage(fixture, [physicalMember("member-a", "team-a", "user-a"), physicalMember("member-b", "team-b", "user-b")], [1, 1], "team-a");
      } finally { fixture.close(); }
    });

    for (const fail of [false, true]) {
      test(`${backend} Team details ${joins ? "native" : "fallback"} preserve ${fail ? "child output failure" : "membership page limit"}`, async () => {
        const fixture = await setup(backend, seedFields, { joins });
        const events: Events = [];
        const failure = new Error("team-details-member-output-failed");
        try {
          await seedMember(fixture, "member-a", "team-a", "user-a");
          await seedMember(fixture, "member-b", "team-a", "user-b");
          const reader = await fixture.reader(memberFields(events, "id", false, fail ? failure : undefined), parentFields(events), { limit: fail ? undefined : 1 });
          const operation = reader.findTeamById({ teamId: "team-a", organizationId: "organization", includeTeamMembers: true });
          if (fail) await expect(operation).rejects.toBe(failure);
          else expect(await operation).toStrictEqual(publicTeam("team-a", "Team A", [publicMember("member-a", "team-a", "user-a")]));
          expect(events).toStrictEqual([
            ["team.name", "output", "Team A"],
            ...(fail ? [["teamId", "output", "team-a"], ["userId", "output", "user-a"]] : memberEvents(backend, "team-a", "user-a")),
          ]);
          assertStorage(fixture, [physicalMember("member-a", "team-a", "user-a"), physicalMember("member-b", "team-a", "user-b")], [2, 0]);
        } finally { fixture.close(); }
      });
    }

    test(`${backend} Team details ${joins ? "native" : "fallback"} preserve singular membership values`, async () => {
      const fixture = await setup(backend, seedFields, { joins });
      const events: Events = [];
      try {
        await seedMember(fixture, "member-a", "team-a", "user-a");
        const reader = await fixture.reader(memberFields(events, "id", true), parentFields(events));
        let caught: unknown;
        try { await reader.findTeamById({ teamId: "team-a", organizationId: "organization", includeTeamMembers: true }); }
        catch (error) { caught = error; }
        console.info("Team details singular membership error", { backend, joins, error: caught,
          ...(caught instanceof Error ? { class: caught.name, message: caught.message } : {}),
        });
        expect(caught).toBeInstanceOf(TypeError);
        expect(events.splice(0)).toStrictEqual([["team.name", "output", "Team A"], ...memberEvents(backend, "team-a", "user-a")]);
        expect(await reader.findTeamById({ teamId: "team-b", organizationId: "organization", includeTeamMembers: true })).toStrictEqual(publicTeam("team-b", "Team B", []));
        expect(events).toStrictEqual([["team.name", "output", "Team B"]]);
        assertStorage(fixture, [physicalMember("member-a", "team-a", "user-a")], [1, 0]);
      } finally { fixture.close(); }
    });
  }
}
