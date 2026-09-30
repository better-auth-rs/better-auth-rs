import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";
import { configure, trace } from "./helpers";

compatScenario("all organization hooks observe persisted identity, upstream subjects and override order", async (ctx) => {
  await signUpUser(ctx, "owner", "hook-owner", "Owner");
  const recipient = await signUpUser(ctx, "recipient", "hook-recipient", "Recipient");
  expect(recipient.signup.data!.user).not.toHaveProperty("secretNote");
  const rejector = await signUpUser(ctx, "rejector", "hook-rejector", "Rejector");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Original", slug: ctx.uniqueToken("hooks") }));
  expect(org.name).toBe("hook:Original");
  const organizationId = org.id;
  const creation = await trace(ctx);
  expect(creation.map((event) => event.event)).toEqual([
    "allowCreate", "organizationLimit", "beforeCreateOrganization", "beforeAddMember", "afterAddMember", "beforeCreateTeam", "afterCreateTeam", "afterCreateOrganization",
  ]);
  const defaults = asArray(await call("owner", `list-teams?organizationId=${organizationId}`)).map(asRecord);
  expect(defaults[0]!.name).toBe("team:hook:Original");
  const team = asRecord(await call("owner", "create-team", { organizationId, name: "Engineering" }));
  expect(team.name).toBe("team:Engineering");
  const updatedTeam = asRecord(await call("owner", "update-team", { teamId: team.id, data: { name: "Platform" } }));
  expect(updatedTeam.name).toBe("updated:Platform");
  const invited = asRecord(await call("owner", "invite-member", { organizationId, email: recipient.email, role: "member" }));
  expect(invited.role).toBe("admin");
  const accepted = asRecord(await call("recipient", "accept-invitation", { invitationId: invited.id }));
  const memberId = asRecord(accepted.member).id;
  expect(asRecord(accepted.member).role).toBe("admin");
  const teamMember = asRecord(await call("owner", "add-team-member", { organizationId, teamId: team.id, userId: recipient.signup.data!.user.id }));
  expect(teamMember.userId).toBe(recipient.signup.data!.user.id);
  await call("owner", "remove-team-member", { organizationId, teamId: team.id, userId: recipient.signup.data!.user.id });
  const role = asRecord(await call("owner", "update-member-role", { organizationId, memberId, role: "admin" }));
  expect(role.role).toBe("member");
  await call("owner", "remove-member", { organizationId, memberIdOrEmail: recipient.email });
  const rejected = asRecord(await call("owner", "invite-member", { organizationId, email: rejector.email, role: "member" }));
  await call("rejector", "reject-invitation", { invitationId: rejected.id });
  const canceled = asRecord(await call("owner", "invite-member", { organizationId, email: ctx.uniqueEmail("hook-canceled"), role: "member" }));
  await call("owner", "cancel-invitation", { invitationId: canceled.id });
  await call("owner", "remove-team", { organizationId, teamId: team.id });
  const updated = asRecord(await call("owner", "update", { organizationId, data: { name: "Renamed" } }));
  expect(updated.name).toBe("updated:Renamed");
  await call("owner", "delete", { organizationId });
  const events = await trace(ctx);
  const databaseSubjects = new Set(["RemoveMember", "UpdateMemberRole", "AddTeamMember", "RemoveTeamMember"]
    .flatMap((name) => [`before${name}`, `after${name}`]));
  for (const event of events) {
    if (databaseSubjects.has(String(event.event))) {
      expect(asRecord(event.user).id).toBe(recipient.signup.data!.user.id);
      expect(asRecord(event.user).secretNote).toBe("hidden");
    } else if (event.user) {
      expect(asRecord(event.user)).not.toHaveProperty("secretNote");
    }
    if (event.session) expect(asRecord(asRecord(event.session).user)).not.toHaveProperty("secretNote");
  }
  const actual = [...new Set(events.map((event) => String(event.event)).filter((name) => /^(before|after)/.test(name)))].sort();
  const expected = ["CreateOrganization", "UpdateOrganization", "DeleteOrganization", "AddMember", "RemoveMember", "UpdateMemberRole", "CreateInvitation", "AcceptInvitation", "RejectInvitation", "CancelInvitation", "CreateTeam", "UpdateTeam", "DeleteTeam", "AddTeamMember", "RemoveTeamMember"].flatMap((name) => [`before${name}`, `after${name}`]).sort();
  expect(actual).toEqual(expected);
  observations.push(events);
  return observations;
});

compatScenario("hook rejection preserves upstream before and after persistence boundaries", async (ctx) => {
  await signUpUser(ctx, "owner", "failure-owner", "Owner");
  const { call, observations } = requests(ctx);
  const beforeSlug = ctx.uniqueToken("before");
  await configure(ctx, { fail: "beforeCreateOrganization" });
  await call("owner", "create", { name: "Rejected", slug: beforeSlug }, 403);
  expect(asRecord(await call("owner", "check-slug", { slug: beforeSlug })).status).toBe(true);
  observations.push(await trace(ctx));
  await configure(ctx, { fail: "afterCreateOrganization" });
  const afterSlug = ctx.uniqueToken("after");
  await call("owner", "create", { name: "Persisted", slug: afterSlug }, 403);
  const organizations = asArray(await call("owner", "list")).map(asRecord);
  expect(organizations).toHaveLength(1);
  expect(organizations[0]!.name).toBe("hook:Persisted");
  observations.push(await trace(ctx));
  const organizationId = organizations[0]!.id;
  const team = asRecord(asArray(await call("owner", `list-teams?organizationId=${organizationId}`))[0]);
  await configure(ctx, { fail: "beforeUpdateTeam" });
  await call("owner", "update-team", { teamId: team.id, data: { organizationId, name: "Before" } }, 403);
  expect(asRecord(asArray(await call("owner", `list-teams?organizationId=${organizationId}`))[0]).name).toBe(team.name);
  observations.push(await trace(ctx));
  await configure(ctx, { fail: "afterUpdateTeam" });
  await call("owner", "update-team", { teamId: team.id, data: { organizationId, name: "After" } }, 403);
  expect(asRecord(asArray(await call("owner", `list-teams?organizationId=${organizationId}`))[0]).name).toBe("updated:After");
  observations.push(await trace(ctx));
  return observations;
});

compatScenario("organization logo can be cleared by a hook override and an explicit null update", async (ctx) => {
  await signUpUser(ctx, "owner", "logo-owner", "Owner");
  const { call, observations } = requests(ctx);
  const logo = "https://example.com/logo.png";
  const org = asRecord(await call("owner", "create", { name: "Logo", slug: ctx.uniqueToken("logo"), logo }));
  expect(org.logo).toBe(logo);
  const organizationId = org.id;
  await configure(ctx, { clearLogo: true });
  expect(asRecord(await call("owner", "update", { organizationId, data: { name: "Cleared" } })).logo).toBeNull();
  expect(asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`)).logo).toBeNull();
  observations.push(await trace(ctx));
  await configure(ctx);
  expect(asRecord(await call("owner", "update", { organizationId, data: { logo } })).logo).toBe(logo);
  expect(asRecord(await call("owner", "update", { organizationId, data: { logo: null } })).logo).toBeNull();
  expect(asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`)).logo).toBeNull();
  observations.push(await trace(ctx));
  return observations;
});
