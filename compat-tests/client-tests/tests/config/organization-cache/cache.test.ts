import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("organization cache snapshots preserve upstream mutation timing and explicit refresh", async (ctx) => {
  await signUpUser(ctx, "owner", "cache-owner", "Owner");
  const member = await signUpUser(ctx, "member", "cache-member", "Member");
  const { call, observations } = requests(ctx);
  async function session(actor: string, fresh = false) {
    const result = await ctx.rawRequest({ actor, path: `/api/auth/get-session${fresh ? "?disableCookieCache=true" : ""}` });
    expect(result.status).toBe(200);
    observations.push(result);
    return asRecord(asRecord(result.body).session);
  }
  const org = asRecord(await call("owner", "create", { name: "Cached Organization", slug: ctx.uniqueToken("cached") }));
  const organizationId = org.id;
  const defaults = asArray(await call("owner", `list-teams?organizationId=${organizationId}`));
  const defaultTeamId = asRecord(defaults[0]).id;
  const cachedOwner = await session("owner");
  expect(cachedOwner.activeTeamId).toBeNull();
  expect(cachedOwner.activeOrganizationId).toBeNull();
  const freshOwner = await session("owner", true);
  expect(freshOwner.activeTeamId).toBe(defaultTeamId);
  expect(freshOwner.activeOrganizationId).toBe(organizationId);
  const team = asRecord(await call("owner", "create-team", { organizationId, name: "Invitation Team" }));
  const teamId = team.id;
  const invitation = asRecord(await call("owner", "invite-member", { organizationId, teamId, email: member.email, role: "member" }));
  await call("member", "accept-invitation", { invitationId: invitation.id });
  const cachedMember = await session("member");
  expect(cachedMember.activeTeamId).toBe(teamId);
  expect(cachedMember.activeOrganizationId).toBeNull();
  const freshMember = await session("member", true);
  expect(freshMember.activeTeamId).toBe(teamId);
  expect(freshMember.activeOrganizationId).toBe(organizationId);
  await call("member", "set-active", { organizationId });
  await call("member", "set-active-team", { teamId: null });
  expect((await session("member")).activeTeamId).toBeNull();
  await call("member", "set-active-team", { teamId });
  const selected = await session("member");
  expect(selected.activeTeamId).toBe(teamId);
  expect(selected.activeOrganizationId).toBe(organizationId);
  return observations;
});
