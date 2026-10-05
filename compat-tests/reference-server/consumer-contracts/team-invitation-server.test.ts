import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureTeamInvitationServer } from "../contracts/team-invitation-server-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} Team counters and Team/Invitation columns match upstream`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/team-invitation-${backend}-server-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureTeamInvitationServer(backend)).toEqual(fixture);
  });
}
