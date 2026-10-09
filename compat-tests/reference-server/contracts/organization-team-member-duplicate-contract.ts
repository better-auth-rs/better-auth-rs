import { expect, test } from "bun:test";
import { setup, team, type Events } from "./organization-team-member-contract";
import {
  seedFields, physicalMember, publicTeam,
  memberFields, parentFields, memberEvents,
} from "./organization-team-details-contract";

for (const backend of ["memory", "sqlite"] as const) {
  for (const joins of [false, true]) {
    test(`${backend} TeamMember ${joins ? "native" : "fallback"} preserves duplicate primary-key behavior`, async () => {
      const fixture = await setup(backend, seedFields, { joins });
      const events: Events = [];
      try {
        expect(await fixture.createMember(physicalMember("member-a", "team-a", "user-a"))).toStrictEqual(physicalMember("member-a", "team-a", "user-a"));
        const operation = fixture.createMember(physicalMember("member-a", "team-b", "user-a"));
        const memory = backend === "memory";
        if (memory) expect(await operation).toStrictEqual(physicalMember("member-a", "team-b", "user-a"));
        else {
          let caught: unknown;
          try { await operation; } catch (error) { caught = error; }
          console.info("TeamMember duplicate SQLite primary key", { error: caught,
            ...(caught instanceof Error ? { class: caught.name, message: caught.message } : {}),
          });
          expect(caught).toBeInstanceOf(Error);
          expect(String(caught)).toContain("UNIQUE constraint failed: teamMember.id");
        }
        const reader = await fixture.reader(memberFields(events), parentFields(events));
        expect(await reader.listTeamsByUser({ userId: "user-a" })).toStrictEqual(
          memory && joins ? [publicTeam("team-b", "Team B")]
            : memory ? [publicTeam("team-a", "Team A"), publicTeam("team-b", "Team B")]
              : [publicTeam("team-a", "Team A")],
        );
        const first = memberEvents(backend, "team-a", "user-a");
        const second = memberEvents(backend, "team-b", "user-a");
        expect(events).toStrictEqual([
          ...(memory && !joins ? first.flatMap((event, index) => [event, second[index]]) : first),
          ...(memory && !joins ? [["team.name", "output", "Team A"]] : []),
          ["team.name", "output", memory ? "Team B" : "Team A"],
        ]);
        expect(fixture.rawMembers()).toStrictEqual([
          fixture.stored(physicalMember("member-a", "team-a", "user-a")),
          ...(memory ? [fixture.stored(physicalMember("member-a", "team-b", "user-a"))] : []),
        ]);
        expect(fixture.rawTeams()).toStrictEqual([fixture.stored(team("team-a", "Team A")), fixture.stored(team("team-b", "Team B"))]);
      } finally { fixture.close(); }
    });
  }
}
