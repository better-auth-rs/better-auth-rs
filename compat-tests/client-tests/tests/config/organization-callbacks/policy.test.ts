import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";
import { configure, trace } from "./helpers";

compatScenario("asynchronous organization policies control every limit and retain actor context", async (ctx) => {
  await signUpUser(ctx, "owner", "policy-owner", "Owner");
  const recipient = await signUpUser(ctx, "recipient", "policy-recipient", "Recipient");
  const { call, observations } = requests(ctx);
  for (const limits of [{ allowCreate: false }, { organizationLimit: true }]) {
    await configure(ctx, { limits });
    await call("owner", "create", { name: "Blocked", slug: ctx.uniqueToken("blocked") }, 403);
    observations.push(await trace(ctx));
  }
  await configure(ctx);
  const org = asRecord(await call("owner", "create", { name: "Policy", slug: ctx.uniqueToken("policy") }));
  const organizationId = org.id;
  const team = asRecord(await call("owner", "create-team", { organizationId, name: "Empty" }));
  const input = { organizationId, email: recipient.email, role: "member" };
  for (const [limits, route, body, status, expected] of [
    [{ maximumTeams: 1 }, "create-team", { organizationId, name: "Denied" }, 400, "maximumTeams"],
    [{ maximumRoles: 0 }, "create-role", { organizationId, role: "denied", permission: {} }, 400, "maximumRoles"],
    [{ invitationLimit: 0 }, "invite-member", input, 403, "invitationLimit"],
    [{ maximumMembersPerTeam: 0 }, "invite-member", { ...input, teamId: team.id }, 403, "maximumMembersPerTeam"],
  ] as const) {
    await configure(ctx, { limits });
    await call("owner", route, body, status);
    const events = await trace(ctx);
    expect(events.some((event) => event.event === expected)).toBe(true);
    expect(events.some((event) => String(event.event).startsWith("before"))).toBe(false);
    observations.push(events);
  }
  await configure(ctx, { limits: { maximumTeams: 0 } });
  await call("owner", "create-team", { organizationId, name: "Unlimited" });
  observations.push(await trace(ctx));
  await configure(ctx);
  const invited = asRecord(await call("owner", "invite-member", { ...input, teamId: team.id }));
  await configure(ctx, { limits: { membershipLimit: 0 } });
  await call("recipient", "accept-invitation", { invitationId: invited.id }, 403);
  observations.push(await trace(ctx));
  await configure(ctx, { limits: { maximumMembersPerTeam: 0 } });
  await call("recipient", "accept-invitation", { invitationId: invited.id }, 403);
  const pending = asArray(await call("owner", `list-invitations?organizationId=${organizationId}`)).map(asRecord);
  expect(pending.find((invitation) => invitation.id === invited.id)?.status).toBe("pending");
  observations.push(await trace(ctx));
  await configure(ctx);
  await call("recipient", "accept-invitation", { invitationId: invited.id });
  const members = asArray(await call("recipient", `list-team-members?teamId=${team.id}`));
  expect(members).toHaveLength(1);
  expect(asRecord(members[0]).userId).toBe(recipient.signup.data!.user.id);
  observations.push(await trace(ctx));
  await configure(ctx, { limits: { membershipLimit: 1 } });
  const full = asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`));
  expect(asArray(full.members)).toHaveLength(2);
  const listed = asRecord(await call("owner", `list-members?organizationId=${organizationId}`));
  expect(asArray(listed.members)).toHaveLength(2);
  const limited = asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}&membersLimit=1`));
  expect(asArray(limited.members)).toHaveLength(1);
  expect(await trace(ctx)).toEqual([]);
  return observations;
});
