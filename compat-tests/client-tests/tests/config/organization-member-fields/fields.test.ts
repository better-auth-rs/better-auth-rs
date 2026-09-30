import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("member schemas replace role validation and persist raw roles after array joining", async (ctx) => {
  await signUpUser(ctx, "owner", "member-fields-owner", "Owner");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "Members", slug: ctx.uniqueToken("members") }));
  const organizationId = organization.id;
  for (const [index, role] of [7, null, { custom: true }, ["member", null, 7], undefined].entries()) {
    const target = await signUpUser(ctx, `target-${index}`, `member-target-${index}`, "Target");
    const result = await ctx.rawRequest({ actor: "owner", path: "/__test/organization-add-member", method: "POST", json: { organizationId, userId: target.signup.data!.user.id, role } });
    expect(result.status, JSON.stringify(result.body)).toBe(200);
    const member = asRecord(result.body);
    expect(member.role).toEqual(role === undefined ? "member" : Array.isArray(role) ? "member,,7" : role);
    observations.push(result);
    const listed = asRecord(await call("owner", `list-members?organizationId=${organizationId}`));
    const persisted = asArray(listed.members).map(asRecord).find((entry) => entry.id === member.id);
    expect(persisted?.role).toEqual(member.role);
  }
  return observations;
});

compatScenario("invitation schemas run before email and role operations and preserve empty roles", async (ctx) => {
  await signUpUser(ctx, "owner", "invite-fields-owner", "Owner");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "Invitations", slug: ctx.uniqueToken("invitations") }));
  const organizationId = organization.id;
  for (const [index, role] of ["", [], ["member", null]].entries()) {
    const invitation = asRecord(await call("owner", "invite-member", { organizationId, email: ctx.uniqueEmail(`valid-${index}`), role }));
    expect(invitation.role).toBe(Array.isArray(role) ? role.join(",") : role);
  }
  for (const email of [7, null, undefined]) {
    await call("owner", "invite-member", { organizationId, email, role: "member" }, 500);
  }
  for (const role of [7, null, undefined, { custom: true }]) {
    await call("owner", "invite-member", { organizationId, email: ctx.uniqueEmail("invalid-role"), role }, 500);
  }
  await call("owner", "invite-member", { organizationId, email: "not-an-email", role: "member" }, 400);
  const invitations = asArray(await call("owner", `list-invitations?organizationId=${organizationId}`));
  expect(invitations).toHaveLength(3);
  return observations;
});

compatScenario("replacement ID schemas reach real database lookups without string-only rejection", async (ctx) => {
  await signUpUser(ctx, "owner", "lookup-owner", "Owner");
  const target = await signUpUser(ctx, "target", "lookup-target", "Target");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "Lookups", slug: ctx.uniqueToken("lookups") }));
  const valid = { organizationId: organization.id, userId: target.signup.data!.user.id, role: "member" };
  for (const [patch, code] of [
    [{ userId: 42 }, "USER_NOT_FOUND"],
    [{ userId: null }, "USER_NOT_FOUND"],
    [{ userId: undefined }, "USER_NOT_FOUND"],
    [{ userId: false }, "USER_NOT_FOUND"],
    [{ userId: 0 }, "USER_NOT_FOUND"],
    [{ organizationId: 42 }, "ORGANIZATION_NOT_FOUND"],
    [{ teamId: 42 }, "TEAM_NOT_FOUND"],
  ] as const) {
    const result = await ctx.rawRequest({ actor: "owner", path: "/__test/organization-add-member", method: "POST", json: { ...valid, ...patch } });
    expect(result.status, JSON.stringify(result.body)).toBe(400);
    expect(asRecord(result.body).code).toBe(code);
    observations.push(result);
  }
  await call("owner", "invite-member", { organizationId: 42, email: ctx.uniqueEmail("unknown-org"), role: "member" }, 400);
  const members = asRecord(await call("owner", `list-members?organizationId=${organization.id}`));
  expect(asArray(members.members)).toHaveLength(1);
  const team = asRecord(await call("owner", "create-team", { organizationId: organization.id, name: "Members" }));
  const added = await ctx.rawRequest({ actor: "owner", path: "/__test/organization-add-member", method: "POST", json: { ...valid, teamId: team.id } });
  expect(added.status).toBe(200);
  expect(asRecord(added.body).teamId).toBe(team.id);
  observations.push(added);
  const teamMembers = asArray(await call("target", `list-team-members?teamId=${team.id}`));
  expect(teamMembers).toHaveLength(1);
  expect(asRecord(teamMembers[0]).userId).toBe(target.signup.data!.user.id);
  return observations;
});

compatScenario("invitation custom fields override adapter defaults while hooks receive the authenticated inviter", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "override-owner", "Owner");
  const target = await signUpUser(ctx, "target", "override-target", "Target");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "Overrides", slug: ctx.uniqueToken("overrides") }));
  const input = { status: "custom-state", createdAt: "custom-created", expiresAt: "custom-expires", inviterId: target.signup.data!.user.id };
  const invitation = asRecord(await call("owner", "invite-member", { organizationId: organization.id, email: ctx.uniqueEmail("override"), role: "member", ...input }));
  for (const [key, value] of Object.entries(input)) expect(invitation[key]).toBe(value);
  expect(invitation.hookState).toEqual({ ...input, inviterId: owner.signup.data!.user.id });
  const persisted = asArray(await call("owner", `list-invitations?organizationId=${organization.id}`)).map(asRecord).find((entry) => entry.id === invitation.id);
  for (const [key, value] of Object.entries(input)) expect(persisted?.[key]).toBe(value);
  expect(persisted?.hookState).toEqual(invitation.hookState);
  const clearedOrganization = asRecord(await call("owner", "create", { name: "Cleared", slug: ctx.uniqueToken("cleared") }));
  const cleared = asRecord(await call("owner", "invite-member", { organizationId: clearedOrganization.id, email: ctx.uniqueEmail("cleared"), role: "member", status: null, createdAt: null, expiresAt: null, inviterId: null }));
  for (const key of ["status", "createdAt", "expiresAt", "inviterId"]) expect(cleared[key]).toBeNull();
  expect(cleared.hookState).toEqual({ status: null, createdAt: null, expiresAt: null, inviterId: owner.signup.data!.user.id });
  const clearedInvitations = asArray(await call("owner", `list-invitations?organizationId=${clearedOrganization.id}`));
  expect(clearedInvitations).toHaveLength(1);
  const clearedRead = clearedInvitations.map(asRecord).find((entry) => entry.id === cleared.id);
  for (const key of ["status", "createdAt", "expiresAt", "inviterId"]) expect(clearedRead?.[key]).toBeNull();
  return observations;
});

compatScenario("invitation expiration comparisons retain JavaScript coercion after date type replacement", async (ctx) => {
  await signUpUser(ctx, "owner", "expiry-owner", "Owner");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "Expiration", slug: ctx.uniqueToken("expiration") }));
  for (const [index, [expiresAt, accepted]] of [["2000-01-01T00:00:00.000Z", true], ["not-a-date", true], ["1e20", true], ["0", false], [null, false]].entries()) {
    const actor = `recipient-${index}`;
    const recipient = await signUpUser(ctx, actor, `expiry-recipient-${index}`, "Recipient");
    const invitation = asRecord(await call("owner", "invite-member", { organizationId: organization.id, email: recipient.email, role: "member", expiresAt }));
    const response = await call(actor, "accept-invitation", { invitationId: invitation.id }, accepted ? 200 : 400);
    if (accepted) {
      expect(asRecord(asRecord(response).invitation).status).toBe("accepted");
      expect(asRecord(asRecord(response).member).userId).toBe(recipient.signup.data!.user.id);
    }
  }
  const members = asRecord(await call("owner", `list-members?organizationId=${organization.id}`));
  expect(asArray(members.members)).toHaveLength(4);
  return observations;
});

compatScenario("merged schemas aggregate every validation issue in field definition order", async (ctx) => {
  await signUpUser(ctx, "owner", "validation-owner", "Owner");
  const target = await signUpUser(ctx, "target", "validation-target", "Target");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "Validation", slug: ctx.uniqueToken("validation") }));
  const result = await call("owner", "invite-member", {
    organizationId: organization.id, email: target.email, role: "member", resend: [], teamId: 7,
    alphaCount: "invalid", zetaText: 1, status: 7,
  }, 400);
  expect(asRecord(result).message).toBe("[body.resend] Invalid input: expected boolean, received array; [body.teamId] Invalid input; [body.status] Invalid input: expected string, received number; [body.zetaText] Invalid input: expected string, received number; [body.alphaCount] Invalid input: expected number, received string");
  const added = await ctx.rawRequest({ actor: "owner", path: "/__test/organization-add-member", method: "POST", json: {
    organizationId: organization.id, userId: target.signup.data!.user.id, role: "member", alphaCount: "invalid", zetaText: 1,
  } });
  expect(added.status).toBe(400);
  expect(asRecord(added.body).message).toBe("[body.zetaText] Invalid input: expected string, received number; [body.alphaCount] Invalid input: expected number, received string");
  observations.push(added);
  expect(asArray(await call("owner", `list-invitations?organizationId=${organization.id}`))).toHaveLength(0);
  expect(asArray(asRecord(await call("owner", `list-members?organizationId=${organization.id}`)).members)).toHaveLength(1);
  return observations;
});
