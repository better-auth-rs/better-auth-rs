import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("replacement team IDs preserve truthiness, hook inputs and adapter joining", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "team-input-owner", "Owner");
  const { call, observations } = requests(ctx);
  for (const [index, teamId] of [0, ""].entries()) {
    const organization = asRecord(await call("owner", "create", { name: "Team Inputs", slug: ctx.uniqueToken(`team-input-${index}`) }));
    const invitation = asRecord(await call("owner", "invite-member", {
      organizationId: organization.id, email: ctx.uniqueEmail(`team-input-${index}`), role: "member", teamId,
    }));
    expect(invitation.teamId).toBe(teamId === 0 ? null : "");
    expect(invitation.hookState).toEqual({ inviterId: owner.signup.data!.user.id, teamIds: teamId === 0 ? 0 : [""], ...(teamId === "" ? { teamId: "" } : {}) });
    const invitations = asArray(await call("owner", `list-invitations?organizationId=${organization.id}`));
    expect(invitations).toHaveLength(1);
    expect(asRecord(invitations[0]).teamId).toEqual(invitation.teamId);
    expect(asRecord(invitations[0]).hookState).toEqual(invitation.hookState);
  }
  const organization = asRecord(await call("owner", "create", { name: "Invalid Teams", slug: ctx.uniqueToken("invalid-teams") }));
  const invalid = await call("owner", "invite-member", { organizationId: organization.id, email: ctx.uniqueEmail("invalid-team"), role: "member", teamId: [7] }, 500);
  expect(invalid).toBeNull();
  expect(asArray(await call("owner", `list-invitations?organizationId=${organization.id}`))).toHaveLength(0);
  const team = asRecord(await call("owner", "create-team", { organizationId: organization.id, name: "Valid Team" }));
  const invitation = asRecord(await call("owner", "invite-member", { organizationId: organization.id, email: ctx.uniqueEmail("valid-team"), role: "member", teamId: team.id }));
  expect(invitation.teamId).toBe(team.id);
  expect(invitation.hookState).toEqual({ inviterId: owner.signup.data!.user.id, teamIds: [team.id], teamId: team.id });
  return observations;
});
