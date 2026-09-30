import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";
import { trace } from "../organization-callbacks/helpers";

compatScenario("custom default-team creation persists the returned identity between team hooks", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "custom-team-owner", "Owner");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Custom", slug: ctx.uniqueToken("custom-team") }));
  const teams = asArray(await call("owner", `list-teams?organizationId=${org.id}`)).map(asRecord);
  expect(teams).toHaveLength(1);
  expect(teams[0]!.name).toBe("custom:hook:Custom");
  const members = asArray(await call("owner", `list-team-members?teamId=${teams[0]!.id}`)).map(asRecord);
  expect(members).toHaveLength(1);
  expect(members[0]!.userId).toBe(owner.signup.data!.user.id);
  const events = await trace(ctx);
  expect(events.map((event) => event.event)).toEqual([
    "allowCreate", "organizationLimit", "beforeCreateOrganization", "beforeAddMember", "afterAddMember", "beforeCreateTeam", "createDefaultTeam", "afterCreateTeam", "afterCreateOrganization",
  ]);
  observations.push(events);
  return observations;
});
