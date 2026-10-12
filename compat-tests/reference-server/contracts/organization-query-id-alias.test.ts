import { expect, setSystemTime, test } from "bun:test";
import { writeObservation } from "./write-observation.mjs";
import { captureOrganizationQueryIdAliases, organizationQueryIdAliasScenarios } from "./organization-query-id-alias-capture.mjs";

test("Organization queries retain first-ID aliases across direct, joined and atomic operations", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/organization-query-id-alias-1.7.6.json", import.meta.url)).json();
  let observation;
  try {
    observation = await captureOrganizationQueryIdAliases(async captured => {
      await writeObservation(`${JSON.stringify({ contract: "organization-query-id-alias", version: "1.7.6", backend: "memory", case: captured })}\n`);
    }, scenario => {
      if (scenario === "team-update" || scenario === "organizationRole-update") {
        const captured = fixture.cases.find(value => value.scenario === scenario);
        expect(captured.steps[0].result.updatedAt.type).toBe("date");
        // Replay the captured clock while preserving the native onUpdate callback and every observed field.
        setSystemTime(new Date(captured.steps[0].result.updatedAt.value));
      } else {
        setSystemTime();
      }
    });
  } finally {
    setSystemTime();
  }
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual(organizationQueryIdAliasScenarios);
  for (const captured of observation.cases) {
    expect(captured.steps.every(step => step.returned)).toBe(true);
    if (captured.operation === "delete") {
      expect(captured.steps[0].after[captured.model].map(row => row.id)).toStrictEqual([captured.alias]);
    } else if (captured.operation) {
      expect(captured.steps.map(step => step.result.id)).toStrictEqual([captured.canonical, captured.canonical, captured.alias]);
    } else if (captured.scenario.startsWith("member-user-")) {
      expect(captured.steps[0].result.user).toStrictEqual({
        id: { type: "undefined" }, name: { type: "undefined" },
        email: { type: "undefined" }, image: { type: "undefined" },
      });
      expect(captured.steps[0].events).toStrictEqual([
        ["output", "member.role", "member"], ["output", "user.name", "Alias owner"],
      ]);
      expect(captured.steps[0].after).toStrictEqual(captured.steps[0].before);
    } else {
      const step = captured.steps[0];
      if (captured.mutate) {
        expect(step.result).toBeNull();
        expect(step.after.invitation).toStrictEqual(step.before.invitation.map((row, index) => index === 0 ? { ...row, lookup: "changed-alias" } : row));
      } else {
        expect(step.result.id).toBe("canonical-invitation");
        expect(step.after.invitation).toStrictEqual(step.before.invitation.map((row, index) => index === 0 ? { ...row, status: "accepted" } : row));
      }
    }
  }
  expect(observation).toStrictEqual(fixture);
});
