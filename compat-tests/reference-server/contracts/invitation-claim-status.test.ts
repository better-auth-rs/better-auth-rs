import { expect, test } from "bun:test";
import { writeObservation } from "./write-observation.mjs";
import { captureInvitationClaimStatusPolicies } from "./organization-query-id-alias-capture.mjs";

test("Invitation claims apply declared status query and write policies", async () => {
  const observation = await captureInvitationClaimStatusPolicies(async captured => {
    await writeObservation(`${JSON.stringify({ contract: "invitation-claim-status", version: "1.7.6", backend: "memory", case: captured })}\n`);
  });
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual([
    "invitation-claim-status-json", "invitation-claim-status-string",
    "invitation-claim-status-boolean", "invitation-claim-status-nan",
  ]);
  for (const captured of observation.cases) {
    const step = captured.steps[0];
    expect(step.returned).toBe(true);
    if (captured.type === "json") {
      expect(step.result).toBeNull();
      expect(step.events).toStrictEqual([["input", "invitation.status", "accepted"]]);
      expect(step.after).toStrictEqual(step.before);
      expect(captured.steps).toHaveLength(1);
      continue;
    }
    const status = captured.type === "string" ? "claimed" : captured.type === "boolean" ? true : { type: "number", value: "NaN" };
    expect(step.result.status).toStrictEqual(status);
    expect(step.events).toStrictEqual([
      ["input", "invitation.status", "accepted"], ["output", "invitation.status", status],
    ]);
    expect(step.after).toStrictEqual({
      ...step.before,
      invitation: step.before.invitation.map(row => ({
        ...row, stored_status: status,
      })),
    });
    const restore = captured.steps[1];
    expect(restore.returned).toBe(true);
    expect(restore.result).toBeNull();
    expect(restore.events).toStrictEqual([["input", "invitation.status", "pending"]]);
    expect(restore.before).toStrictEqual(step.after);
    expect(restore.after).toStrictEqual(step.after);
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/invitation-claim-status-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});
