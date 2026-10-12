import { expect, test } from "bun:test";
import { writeObservation } from "./write-observation.mjs";
import { captureInvitationClaimSelectorUpdates, captureOrganizationUniqueIdAliasJoins } from "./organization-query-id-alias-capture.mjs";

const emit = (contract: string) => async (captured: unknown) => {
  await writeObservation(`${JSON.stringify({ contract, version: "1.7.6", backend: "memory", case: captured })}\n`);
};

test("An explicit unique Member reference preserves singular first-ID-alias joins", async () => {
  const observation = await captureOrganizationUniqueIdAliasJoins(emit("organization-query-id-alias-unique"));
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual([
    "member-user-fallback-unique", "member-user-native-unique",
  ]);
  for (const captured of observation.cases) {
    const step = captured.steps[0];
    expect(step.returned).toBe(true);
    expect(step.result.user).toStrictEqual({
      id: "canonical-user", name: "Alias owner", email: "canonical-user@organization-query-id.test", image: null,
    });
    expect(step.events).toStrictEqual([
      ["output", "member.role", "member"], ["output", "user.name", "Alias owner"],
    ]);
    expect(step.after).toStrictEqual(step.before);
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/organization-query-id-alias-unique-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});

test("Invitation claims can update their selected ID column within one atomic write", async () => {
  const observation = await captureInvitationClaimSelectorUpdates(emit("invitation-claim-selector-update"));
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual([
    "invitation-own-selector-update-id", "invitation-own-selector-update-lookup",
  ]);
  for (const captured of observation.cases) {
    const step = captured.steps[0];
    expect(step.returned).toBe(true);
    expect(step.result.status).toBe("accepted");
    expect(step.result.claimLookup).toBe("claimed-alias");
    expect(step.result.id).toBe(captured.column === "id" ? "claimed-alias" : "canonical-invitation");
    expect(step.events).toStrictEqual([["onUpdate", "invitation.claimLookup", "claimed-alias"]]);
    expect(step.after.invitation).toStrictEqual(step.before.invitation.map(row => ({
      ...row, status: "accepted", [captured.column]: "claimed-alias",
    })));
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/invitation-claim-selector-update-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});
