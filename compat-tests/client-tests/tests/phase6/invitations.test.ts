import { compatScenario } from "../../support/scenario";
import { signUpUser } from "./helpers";

compatScenario("organization invitation happy path covers list and accept flows", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-invite-owner", "Owner");
  const invitee = await signUpUser(ctx, "invitee", "phase6-invite-invitee", "Invitee");
  const slug = ctx.uniqueToken("phase6-invite-org");

  const organization = await owner.orgClient.organization.create({
    name: "Invite Org",
    slug,
  });
  const invitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: invitee.email,
    role: "member",
  });
  const getInvitation = await invitee.orgClient.organization.getInvitation({
    query: {
      id: invitation.data?.id ?? "",
    },
  });
  const listInvitations = await owner.orgClient.organization.listInvitations({
    query: {
      organizationId: organization.data?.id,
    },
  });
  const listUserInvitations = await invitee.orgClient.organization.listUserInvitations();
  const acceptInvitation = await invitee.orgClient.organization.acceptInvitation({
    invitationId: invitation.data?.id ?? "",
  });
  const fullOrganizationAfterAccept =
    await invitee.orgClient.organization.getFullOrganization();

  return {
    organization: ctx.snapshot(organization),
    invitation: ctx.snapshot(invitation),
    getInvitation: ctx.snapshot(getInvitation),
    listInvitations: ctx.snapshot(listInvitations),
    listUserInvitations: ctx.snapshot(listUserInvitations),
    acceptInvitation: ctx.snapshot(acceptInvitation),
    fullOrganizationAfterAccept: ctx.snapshot(fullOrganizationAfterAccept),
  };
});

compatScenario("organization invitation validation, reject, and cancel flows match TS", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-validate-owner", "Owner");
  const admin = await signUpUser(ctx, "admin", "phase6-validate-admin", "Admin");
  const rejectUser = await signUpUser(ctx, "reject-user", "phase6-reject-user", "Reject User");
  const cancelUser = await signUpUser(ctx, "cancel-user", "phase6-cancel-user", "Cancel User");
  const slug = ctx.uniqueToken("phase6-validate-org");

  const organization = await owner.orgClient.organization.create({
    name: "Validation Org",
    slug,
  });

  const adminInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: admin.email,
    role: "admin",
  });
  const acceptedAdmin = await admin.orgClient.organization.acceptInvitation({
    invitationId: adminInvitation.data?.id ?? "",
  });
  const adminInvitingOwner = await admin.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: ctx.uniqueEmail("phase6-owner-role"),
    role: "owner",
  });
  const invalidRoleInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: ctx.uniqueEmail("phase6-invalid-role"),
    role: "super-invalid-role-123" as never,
  });

  const rejectInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: rejectUser.email,
    role: "member",
  });
  const rejected = await rejectUser.orgClient.organization.rejectInvitation({
    invitationId: rejectInvitation.data?.id ?? "",
  });

  const cancelInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: cancelUser.email,
    role: "member",
  });
  const canceled = await owner.orgClient.organization.cancelInvitation({
    invitationId: cancelInvitation.data?.id ?? "",
  });

  return {
    organization: ctx.snapshot(organization),
    adminInvitation: ctx.snapshot(adminInvitation),
    acceptedAdmin: ctx.snapshot(acceptedAdmin),
    adminInvitingOwner: ctx.snapshot(adminInvitingOwner),
    invalidRoleInvitation: ctx.snapshot(invalidRoleInvitation),
    rejectInvitation: ctx.snapshot(rejectInvitation),
    rejected: ctx.snapshot(rejected),
    cancelInvitation: ctx.snapshot(cancelInvitation),
    canceled: ctx.snapshot(canceled),
  };
});
