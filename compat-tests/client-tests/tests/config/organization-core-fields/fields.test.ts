import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("organization core fields preserve transforms, defaults, null and route precedence", async (ctx) => {
  await signUpUser(ctx, "owner", "core-fields-owner", "Owner");
  const { call, observations } = requests(ctx);
  const id = ctx.uniqueToken("chosen-org");
  const org = asRecord(await call("owner", "create", { id, name: "", slug: ctx.uniqueToken("core-fields") }));
  expect(org.id).toBe(id);
  expect(org.name).toBe(":in:out");
  expect(org.logo).toBe("default-logo");
  expect(org).not.toHaveProperty("createdAt");
  const organizationId = org.id;
  for (const data of [{ name: null }, { slug: null }, { name: "" }, { slug: "" }]) {
    await call("owner", "update", { organizationId, data }, 400);
  }
  const updated = asRecord(await call("owner", "update", { organizationId, data: { name: "Changed", logo: "client-logo" } }));
  expect(updated.name).toBe("Changed:in:out");
  expect(updated.logo).toBe("client-logo");
  expect(updated).not.toHaveProperty("createdAt");
  const read = asRecord(await call("owner", `get-organization?organizationId=${organizationId}`));
  expect(read.name).toBe("Changed:in:out");
  const cleared = asRecord(await call("owner", "update", { organizationId, data: { logo: null } }));
  expect(cleared.logo).toBeNull();
  const explicitNull = asRecord(await call("owner", "create", { name: "Null logo", logo: null, slug: ctx.uniqueToken("null-logo") }));
  expect(explicitNull.logo).toBeNull();
  const explicitLogo = asRecord(await call("owner", "create", { name: "Client logo", logo: "client", slug: ctx.uniqueToken("client-logo") }));
  expect(explicitLogo.logo).toBe("client");
  await call("owner", "list");
  return observations;
});

compatScenario("core member roles remain visible to authorization and hidden in full organization", async (ctx) => {
  await signUpUser(ctx, "owner", "core-members-owner", "Owner");
  const target = await signUpUser(ctx, "target", "core-members-target", "Target");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Members", slug: ctx.uniqueToken("core-members") }));
  const organizationId = org.id;
  const members = asArray(asRecord(await call("owner", `list-members?organizationId=${organizationId}`)).members);
  expect(asRecord(members[0]).role).toBe("owner,member,admin");
  const full = asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`));
  expect(asRecord(asArray(full.members)[0])).not.toHaveProperty("role");
  const added = await ctx.rawRequest({ actor: "owner", path: "/__test/organization-add-member", method: "POST", json: {
    organizationId, userId: target.signup.data!.user.id, role: "member",
  } });
  expect(added.status, JSON.stringify(added.body)).toBe(200);
  expect(asRecord(added.body).role).toBe("member,member,admin");
  observations.push(added);
  const changed = asRecord(await call("owner", "update-member-role", { organizationId, memberId: asRecord(added.body).id, role: "admin" }));
  expect(changed.role).toBe("admin,member,admin");
  const invitationId = ctx.uniqueToken("chosen-invitation");
  const invitation = asRecord(await call("owner", "invite-member", { id: invitationId, organizationId, email: ctx.uniqueEmail("core-invite"), role: "member" }));
  expect(invitation.id).toBe(invitationId);
  expect(invitation.role).toBe("member,member,admin");
  await call("owner", `list-invitations?organizationId=${organizationId}`);
  await call("owner", "cancel-invitation", { invitationId: invitation.id });
  return observations;
});

compatScenario("team timestamp policy replaces the built-in update generator", async (ctx) => {
  await signUpUser(ctx, "owner", "core-teams-owner", "Owner");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Teams", slug: ctx.uniqueToken("core-teams") }));
  const organizationId = org.id;
  const teamId = ctx.uniqueToken("chosen-team");
  const team = asRecord(await call("owner", "create-team", { id: teamId, organizationId, name: "Initial" }));
  expect(team.id).toBe(teamId);
  expect(team.name).toBe("Initial:team-in:team-out");
  await call("owner", "update-team", { teamId: team.id, data: { organizationId, name: null } }, 400);
  await call("owner", "update-team", { teamId: team.id, data: { organizationId: null } }, 400);
  const changed = asRecord(await call("owner", "update-team", { teamId: team.id, data: { organizationId, name: "Changed" } }));
  expect(changed.name).toBe("Changed:team-in:team-out");
  expect(changed.updatedAt).toBe("2020-01-02T03:04:05.000Z");
  await call("owner", `list-teams?organizationId=${organizationId}`);
  return observations;
});

compatScenario("dynamic role core policy transforms persisted values once", async (ctx) => {
  await signUpUser(ctx, "owner", "core-roles-owner", "Owner");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Roles", slug: ctx.uniqueToken("core-roles") }));
  const organizationId = org.id;
  const created = asRecord(asRecord(await call("owner", "create-role", { organizationId, role: "custom", permission: { team: ["create"] } })).roleData);
  expect(created.role).toBe("custom_stored_visible");
  const updated = asRecord(asRecord(await call("owner", "update-role", { organizationId, roleId: created.id, data: { roleName: "changed" } })).roleData);
  expect(updated.role).toBe("changed");
  const persisted = asRecord(await call("owner", `get-role?organizationId=${organizationId}&roleId=${created.id}`));
  expect(persisted.role).toBe("changed_stored_visible");
  return observations;
});
