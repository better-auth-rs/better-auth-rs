import { compatScenario } from "../../support/scenario";
import { asArray, asRecord, signUpUser } from "./helpers";

compatScenario("organization member queries reflect non-public add-member and active member endpoints", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-members-owner", "Owner");
  const member = await signUpUser(ctx, "member", "phase6-members-user", "Member");
  const multiRoleMember = await signUpUser(
    ctx,
    "multi-role",
    "phase6-members-multi-role",
    "Multi Role Member",
  );
  const slug = ctx.uniqueToken("phase6-members-org");

  const organization = await owner.orgClient.organization.create({
    name: "Members Org",
    slug,
  });

  const addMember = await ctx.rawRequest({
    actor: "owner",
    path: "/api/auth/organization/add-member",
    method: "POST",
    json: {
      organizationId: organization.data?.id,
      userId: member.signup.data?.user.id,
      role: "member",
    },
  });
  const addMultiRoleMember = await ctx.rawRequest({
    actor: "owner",
    path: "/api/auth/organization/add-member",
    method: "POST",
    json: {
      organizationId: organization.data?.id,
      userId: multiRoleMember.signup.data?.user.id,
      role: ["admin", "member"],
    },
  });

  const invitedMember = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: member.email,
    role: "member",
  });
  const acceptedMember = await member.orgClient.organization.acceptInvitation({
    invitationId: invitedMember.data?.id ?? "",
  });
  const invitedMultiRoleMember = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: multiRoleMember.email,
    role: ["admin", "member"] as never,
  });
  const acceptedMultiRoleMember =
    await multiRoleMember.orgClient.organization.acceptInvitation({
      invitationId: invitedMultiRoleMember.data?.id ?? "",
    });

  const listMembers = await owner.orgClient.organization.listMembers({
    query: {
      organizationId: organization.data?.id,
      limit: 1,
      offset: 1,
    },
  });
  const getActiveMember = await owner.orgClient.organization.getActiveMember();
  const getActiveMemberRole = await owner.orgClient.organization.getActiveMemberRole();
  const getOtherMemberRole = await owner.orgClient.organization.getActiveMemberRole({
    query: {
      organizationId: organization.data?.id,
      userId: member.signup.data?.user.id,
    },
  });

  return {
    organization: ctx.snapshot(organization),
    addMember: ctx.snapshot(addMember),
    addMultiRoleMember: ctx.snapshot(addMultiRoleMember),
    invitedMember: ctx.snapshot(invitedMember),
    acceptedMember: ctx.snapshot(acceptedMember),
    invitedMultiRoleMember: ctx.snapshot(invitedMultiRoleMember),
    acceptedMultiRoleMember: ctx.snapshot(acceptedMultiRoleMember),
    listMembers: ctx.snapshot(listMembers),
    getActiveMember: ctx.snapshot(getActiveMember),
    getActiveMemberRole: ctx.snapshot(getActiveMemberRole),
    getOtherMemberRole: ctx.snapshot(getOtherMemberRole),
  };
});

compatScenario("organization list members supports sort and filter queries", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-list-owner", "Owner");
  const member = await signUpUser(ctx, "member", "phase6-list-member", "Member");
  const admin = await signUpUser(ctx, "admin", "phase6-list-admin", "Admin");
  const slug = ctx.uniqueToken("phase6-list-org");

  const organization = await owner.orgClient.organization.create({
    name: "List Org",
    slug,
  });

  const invitedMember = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: member.email,
    role: "member",
  });
  await member.orgClient.organization.acceptInvitation({
    invitationId: invitedMember.data?.id ?? "",
  });

  const invitedAdmin = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: admin.email,
    role: "admin",
  });
  await admin.orgClient.organization.acceptInvitation({
    invitationId: invitedAdmin.data?.id ?? "",
  });

  const filteredMembers = await owner.orgClient.organization.listMembers({
    query: {
      organizationId: organization.data?.id,
      filterField: "role",
      filterOperator: "ne",
      filterValue: "owner",
    },
  });
  const sortedMembers = await owner.orgClient.organization.listMembers({
    query: {
      organizationId: organization.data?.id,
      sortBy: "createdAt",
      sortDirection: "desc",
    },
  });

  return {
    organization: ctx.snapshot(organization),
    filteredMembers: ctx.snapshot(filteredMembers),
    sortedMembers: ctx.snapshot(sortedMembers),
  };
});

compatScenario("organization membership mutations cover permissions, role updates, removal, and leave", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-mutations-owner", "Owner");
  const member = await signUpUser(ctx, "member", "phase6-mutations-member", "Member");
  const removable = await signUpUser(ctx, "removable", "phase6-mutations-removable", "Removable");
  const slug = ctx.uniqueToken("phase6-mutations-org");

  const organization = await owner.orgClient.organization.create({
    name: "Mutation Org",
    slug,
  });

  const invitedMember = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: member.email,
    role: "member",
  });
  const acceptedMember = await member.orgClient.organization.acceptInvitation({
    invitationId: invitedMember.data?.id ?? "",
  });
  const invitedRemovable = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: removable.email,
    role: "member",
  });
  const acceptedRemovable = await removable.orgClient.organization.acceptInvitation({
    invitationId: invitedRemovable.data?.id ?? "",
  });

  const ownerPermissions = await owner.orgClient.organization.hasPermission({
    organizationId: organization.data?.id,
    permissions: {
      invitation: ["create"],
      member: ["update"],
    },
  });

  const memberSetActive = await member.orgClient.organization.setActive({
    organizationId: organization.data?.id ?? "",
  });
  const memberPermissionsBeforeRoleUpdate =
    await member.orgClient.organization.hasPermission({
      permissions: {
        member: ["delete"],
      },
    });

  const updateMemberRole = await owner.orgClient.organization.updateMemberRole({
    organizationId: organization.data?.id ?? "",
    memberId: acceptedMember.data?.member.id ?? "",
    role: ["admin", "member"],
  });
  const removeMember = await owner.orgClient.organization.removeMember({
    organizationId: organization.data?.id ?? "",
    memberIdOrEmail: removable.email,
  });
  const leaveOrganization = await member.orgClient.organization.leave({
    organizationId: organization.data?.id ?? "",
  });

  return {
    organization: ctx.snapshot(organization),
    invitedMember: ctx.snapshot(invitedMember),
    acceptedMember: ctx.snapshot(acceptedMember),
    invitedRemovable: ctx.snapshot(invitedRemovable),
    acceptedRemovable: ctx.snapshot(acceptedRemovable),
    ownerPermissions: ctx.snapshot(ownerPermissions),
    memberSetActive: ctx.snapshot(memberSetActive),
    memberPermissionsBeforeRoleUpdate: ctx.snapshot(memberPermissionsBeforeRoleUpdate),
    updateMemberRole: ctx.snapshot(updateMemberRole),
    removeMember: ctx.snapshot(removeMember),
    leaveOrganization: ctx.snapshot(leaveOrganization),
  };
});
