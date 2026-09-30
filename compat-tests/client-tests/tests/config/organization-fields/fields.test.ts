import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

const required = { requiredTag: "required", implicitTag: "implicit" };

compatScenario("failed team acceptance compensates invitation fields without adding membership", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "failed-fields-owner", "Owner");
  const recipient = await signUpUser(ctx, "recipient", "failed-fields-recipient", "Recipient");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Capacity", slug: ctx.uniqueToken("capacity"), ...required }));
  const organizationId = org.id;
  const team = asRecord(await call("owner", "create-team", { organizationId, name: "One member" }));
  const invitation = asRecord(await call("owner", "invite-member", { organizationId, teamId: team.id, email: recipient.email, role: "member" }));
  expect(invitation.marker).toBe("created");
  await call("owner", "add-team-member", { organizationId, teamId: team.id, userId: owner.signup.data!.user.id });
  await call("recipient", "accept-invitation", { invitationId: invitation.id }, 403);
  const persisted = asRecord(await call("recipient", `get-invitation?id=${invitation.id}`));
  expect(persisted.status).toBe("pending");
  expect(persisted.marker).toBe("updated");
  const members = asArray(asRecord(await call("owner", `list-members?organizationId=${organizationId}`)).members);
  expect(members).toHaveLength(1);
  expect(asRecord(members[0]).userId).toBe(owner.signup.data!.user.id);
  const teamMembers = asArray(await call("owner", `list-team-members?teamId=${team.id}`));
  expect(teamMembers).toHaveLength(1);
  expect(asRecord(teamMembers[0]).userId).toBe(owner.signup.data!.user.id);
  return observations;
});

compatScenario("organization deletion preserves the independent API key lifecycle", async (ctx) => {
  await signUpUser(ctx, "owner", "delete-fields-owner", "Owner");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Deleted", slug: ctx.uniqueToken("deleted"), ...required }));
  const created = await ctx.rawRequest({ actor: "owner", path: "/api/auth/api-key/create", method: "POST", json: {
    configId: "organization", organizationId: org.id, name: "Independent key",
  } });
  expect(created.status, JSON.stringify(created.body)).toBe(200);
  const key = asRecord(created.body);
  expect(key.referenceId).toBe(org.id);
  expect(key.key).toBeString();
  expect((key.key as string).length).toBe(64);
  expect((key.key as string).startsWith(key.start as string)).toBe(true);
  observations.push({ ...created, body: { ...key, key: "<generated-key>", start: "<generated-prefix>" } });
  await call("owner", "delete", { organizationId: org.id });
  expect(asArray(await call("owner", "list"))).toHaveLength(0);
  const verified = await ctx.rawRequest({ path: "/__test/api-key/verify", method: "POST", json: { key: key.key, configId: "organization" } });
  expect(verified.status).toBe(200);
  expect(asRecord(verified.body).valid).toBe(true);
  expect(asRecord(asRecord(verified.body).key).referenceId).toBe(org.id);
  const verification = asRecord(verified.body);
  expect(asRecord(verification.key).start).toBe(key.start);
  observations.push({ ...verified, body: { ...verification, key: { ...asRecord(verification.key), start: "<generated-prefix>" } } });
  return observations;
});

compatScenario("organization fields validate input and preserve adapter defaults and transforms", async (ctx) => {
  await signUpUser(ctx, "owner", "fields-owner", "Owner");
  const { call, observations } = requests(ctx);
  const input = { name: "Fields", slug: ctx.uniqueToken("fields"), ...required };
  await call("owner", "create", { ...input, requiredTag: undefined }, 400);
  await call("owner", "create", { ...input, implicitTag: undefined }, 400);
  await call("owner", "create", { ...input, requiredTag: null }, 400);
  await call("owner", "create", { ...input, score: "1" }, 400);
  await call("owner", "create", { ...input, tags: [1] }, 400);
  await call("owner", "create", { ...input, joinedAt: "2020-01-02T03:04:05.000Z" }, 400);
  const org = asRecord(await call("owner", "create", {
    ...input, label: "explicit", protected: "attacker", secret: "private", score: -1,
    category: "unlisted", tags: ["a", "b"], payload: { literal: "value:in", nested: [null, 1] }, unknown: "discard",
  }));
  expect(org.label).toBe("explicit:in:out");
  expect(org.protected).toBe("server");
  expect(org.score).toBe(-1);
  expect(org.category).toBe("unlisted");
  expect(org.joinedAt).toBe("2020-01-02T03:04:05.000Z");
  expect(org.payload).toEqual({ literal: "value:in", nested: [null, 1] });
  expect(org.marker).toBe("created");
  expect(org).not.toHaveProperty("secret");
  expect(org).not.toHaveProperty("unknown");
  expect(org).not.toHaveProperty("physical_label");
  const organizationId = org.id;
  const full = asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`));
  const member = asRecord(asArray(full.members)[0]);
  const defaultTeam = asRecord(asArray(full.teams)[0]);
  for (const record of [member, defaultTeam]) {
    expect(record.label).toBe("guest:in:out");
    expect(record.tags).toEqual(["starter"]);
    expect(record.payload).toEqual({ theme: "system" });
    expect(record).not.toHaveProperty("secret");
  }
  const updated = asRecord(await call("owner", "update", { organizationId, data: { label: "changed", protected: "attacker" } }));
  expect(updated.label).toBe("changed:in:out");
  expect(updated.marker).toBe("updated");
  expect(updated.protected).toBe("server");
  expect(updated.requiredTag).toBe("required");
  expect(updated.implicitTag).toBe("implicit");
  expect(updated.score).toBe(-1);
  const listed = asArray(await call("owner", "list"));
  expect(asRecord(listed[0]).label).toBe("changed:in:out");
  const cleared = asRecord(await call("owner", "update", { organizationId, data: { label: null, tags: null, payload: null, score: null } }));
  expect(cleared.label).toBe("null:in:out");
  expect(cleared.tags).toBeNull();
  expect(cleared.payload).toBeNull();
  expect(cleared.score).toBeNull();
  return observations;
});

compatScenario("member and team fields preserve hidden storage and filter full organization output", async (ctx) => {
  await signUpUser(ctx, "owner", "member-fields-owner", "Owner");
  const target = await signUpUser(ctx, "target", "member-fields-target", "Target");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Members", slug: ctx.uniqueToken("members"), ...required }));
  const organizationId = org.id;
  const team = asRecord(await call("owner", "create-team", { organizationId, name: "Team", label: "team", secret: "team-private", score: -2 }));
  expect(team.label).toBe("team:in:out");
  expect(team.score).toBe(-2);
  expect(team).not.toHaveProperty("secret");
  const response = await ctx.rawRequest({ actor: "owner", path: "/__test/organization-add-member", method: "POST", json: {
    organizationId, teamId: team.id, userId: target.signup.data!.user.id, role: "member", label: "member", secret: "member-private", protected: "attacker", score: -3,
  } });
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  observations.push(response);
  const member = asRecord(response.body);
  expect(member.label).toBe("member:in:out");
  expect(member.secret).toBe("member-private");
  expect(member.protected).toBe("server");
  expect(member.score).toBe(-3);
  const changed = asRecord(await call("owner", "update-member-role", { organizationId, memberId: member.id, role: "admin" }));
  expect(changed.marker).toBe("updated");
  expect(changed.secret).toBe("member-private");
  const members = asArray(asRecord(await call("owner", `list-members?organizationId=${organizationId}`)).members);
  expect(asRecord(members.find((entry) => asRecord(entry).id === member.id)).secret).toBe("member-private");
  const filtered = asRecord(await call("owner", `list-members?organizationId=${organizationId}&filterField=label&filterValue=member%3Ain`));
  expect(filtered.total).toBe(1);
  expect(asRecord(asArray(filtered.members)[0]).id).toBe(member.id);
  const untransformed = asRecord(await call("owner", `list-members?organizationId=${organizationId}&filterField=label&filterValue=member`));
  expect(untransformed.total).toBe(0);
  const numeric = asRecord(await call("owner", `list-members?organizationId=${organizationId}&filterField=score&filterValue=0&filterOperator=lt&sortBy=score&sortDirection=asc&limit=1`));
  expect(numeric.total).toBe(1);
  expect(asRecord(asArray(numeric.members)[0]).id).toBe(member.id);
  const containsNumber = asRecord(await call("owner", `list-members?organizationId=${organizationId}&filterField=score&filterValue=-3e0&filterOperator=contains`));
  expect(containsNumber.total).toBe(1);
  expect(asRecord(asArray(containsNumber.members)[0]).id).toBe(member.id);
  const changedTeam = asRecord(await call("owner", "update-team", { teamId: team.id, data: { organizationId, label: "changed-team" } }));
  expect(changedTeam.label).toBe("changed-team:in:out");
  expect(changedTeam.marker).toBe("updated");
  expect(changedTeam).not.toHaveProperty("secret");
  const memberships = asArray(await call("target", `list-team-members?teamId=${team.id}`));
  expect(memberships).toHaveLength(1);
  expect(asRecord(memberships[0])).not.toHaveProperty("membershipKey");
  const full = asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`));
  const nestedMember = asRecord(asArray(full.members).find((entry) => asRecord(entry).id === member.id));
  expect(nestedMember.label).toBe("member:in:out");
  expect(nestedMember).not.toHaveProperty("secret");
  for (const entry of asArray(full.teams)) expect(asRecord(entry)).not.toHaveProperty("secret");
  return observations;
});

compatScenario("invitation fields apply defaults and update callbacks across invitation transitions", async (ctx) => {
  await signUpUser(ctx, "owner", "invitation-fields-owner", "Owner");
  const acceptedUser = await signUpUser(ctx, "accepted", "invitation-fields-accepted", "Accepted");
  const rejectedUser = await signUpUser(ctx, "rejected", "invitation-fields-rejected", "Rejected");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Invitations", slug: ctx.uniqueToken("invitations"), ...required }));
  const organizationId = org.id;
  const invitation = asRecord(await call("owner", "invite-member", {
    organizationId, email: acceptedUser.email, role: "member", label: "invitation", secret: "invitation-private", protected: "attacker", score: -4,
  }));
  expect(invitation.label).toBe("invitation:in:out");
  expect(invitation.secret).toBe("invitation-private");
  expect(invitation.protected).toBe("server");
  expect(invitation.marker).toBe("created");
  const resent = asRecord(await call("owner", "invite-member", { organizationId, email: acceptedUser.email, role: "member", resend: true, label: "ignored" }));
  expect(resent.id).toBe(invitation.id);
  expect(resent.label).toBe("invitation:in:out");
  expect(resent.marker).toBe("created");
  const persisted = asRecord(await call("accepted", `get-invitation?id=${invitation.id}`));
  expect(persisted.marker).toBe("updated");
  expect(persisted.secret).toBe("invitation-private");
  const full = asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`));
  expect(asRecord(asArray(full.invitations)[0])).not.toHaveProperty("secret");
  const accepted = asRecord(await call("accepted", "accept-invitation", { invitationId: invitation.id }));
  expect(asRecord(accepted.invitation).marker).toBe("updated");
  expect(asRecord(accepted.member).label).toBe("guest:in:out");
  expect(asRecord(accepted.member).secret).toBe("hidden");
  const rejected = asRecord(await call("owner", "invite-member", { organizationId, email: rejectedUser.email, role: "member" }));
  const rejectedResult = asRecord(await call("rejected", "reject-invitation", { invitationId: rejected.id }));
  expect(asRecord(rejectedResult.invitation).marker).toBe("updated");
  expect(rejectedResult.member).toBeNull();
  const cancelled = asRecord(await call("owner", "invite-member", { organizationId, email: ctx.uniqueEmail("cancelled"), role: "member" }));
  const cancelledResult = asRecord(await call("owner", "cancel-invitation", { invitationId: cancelled.id }));
  expect(cancelledResult.marker).toBe("updated");
  await call("owner", `list-invitations?organizationId=${organizationId}`);
  return observations;
});

compatScenario("role fields preserve the create schema and partial update adapter behavior", async (ctx) => {
  await signUpUser(ctx, "owner", "role-fields-owner", "Owner");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Roles", slug: ctx.uniqueToken("roles"), ...required }));
  const organizationId = org.id;
  const input = { organizationId, role: "custom", permission: { team: ["create"] } };
  await call("owner", "create-role", { ...input, additionalFields: null }, 400);
  await call("owner", "create-role", { ...input, additionalFields: {} }, 400);
  const defaulted = asRecord(asRecord(await call("owner", "create-role", { ...input, role: "defaulted" })).roleData);
  expect(defaulted.roleRequired).toBe("role-default");
  expect(defaulted.label).toBe("guest:in:out");
  expect(defaulted.secret).toBe("hidden");
  const created = asRecord(asRecord(await call("owner", "create-role", { ...input, additionalFields: {
    roleRequired: "provided", label: "role", secret: "role-private", protected: "attacker", score: -5,
  } })).roleData);
  expect(created.label).toBe("role:in:out");
  expect(created.secret).toBe("role-private");
  expect(created.protected).toBe("server");
  const updated = asRecord(asRecord(await call("owner", "update-role", { organizationId, roleId: created.id, data: { label: "role-updated" } })).roleData);
  expect(updated.label).toBe("role-updated");
  expect(updated.marker).toBe("created");
  expect(updated.roleRequired).toBe("provided");
  await call("owner", "create-role", { ...input, role: "still-required", additionalFields: {} }, 400);
  const persisted = asRecord(await call("owner", `get-role?organizationId=${organizationId}&roleId=${created.id}`));
  expect(persisted.label).toBe("role-updated:in:out");
  expect(persisted.marker).toBe("updated");
  const cleared = asRecord(asRecord(await call("owner", "update-role", { organizationId, roleId: created.id, data: { roleRequired: null } })).roleData);
  expect(cleared.roleRequired).toBeNull();
  const storedNull = asRecord(await call("owner", `get-role?organizationId=${organizationId}&roleId=${created.id}`));
  expect(storedNull.roleRequired).toBeNull();
  await call("owner", `list-roles?organizationId=${organizationId}`);
  return observations;
});
