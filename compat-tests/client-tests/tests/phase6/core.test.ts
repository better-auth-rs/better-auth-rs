import { compatScenario } from "../../support/scenario";
import { signUpUser } from "./helpers";

compatScenario("organization core lifecycle matches TS", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-core-owner", "Org Owner");
  const firstSlug = ctx.uniqueToken("phase6-first-org");
  const secondSlug = ctx.uniqueToken("phase6-second-org");
  const availableSlug = ctx.uniqueToken("phase6-available-org");

  const checkAvailable = await owner.orgClient.organization.checkSlug({
    slug: availableSlug,
  });

  const firstOrganization = await owner.orgClient.organization.create({
    name: "Alpha Org",
    slug: firstSlug,
  });
  const secondOrganization = await owner.orgClient.organization.create({
    name: "Beta Org",
    slug: secondSlug,
  });

  const checkTaken = await owner.orgClient.organization.checkSlug({
    slug: firstSlug,
  });

  const listedOrganizations = await owner.orgClient.organization.list();
  const updateFirst = await owner.orgClient.organization.update({
    organizationId: firstOrganization.data?.id ?? "",
    data: {
      name: "Alpha Org Renamed",
      metadata: {
        tier: "gold",
      },
    },
  });
  const activeSecondBySlug = await owner.orgClient.organization.setActive({
    organizationSlug: secondSlug,
  });
  const fullOrganizationBySlugPrecedence =
    await owner.orgClient.organization.getFullOrganization({
      query: {
        organizationId: firstOrganization.data?.id,
        organizationSlug: secondSlug,
      },
    });
  const clearActiveOrganization = await owner.orgClient.organization.setActive({
    organizationId: null,
  });
  const fullOrganizationWithoutActive =
    await owner.orgClient.organization.getFullOrganization();

  return {
    checkAvailable: ctx.snapshot(checkAvailable),
    firstOrganization: ctx.snapshot(firstOrganization),
    secondOrganization: ctx.snapshot(secondOrganization),
    checkTaken: ctx.snapshot(checkTaken),
    listedOrganizations: ctx.snapshot(listedOrganizations),
    updateFirst: ctx.snapshot(updateFirst),
    activeSecondBySlug: ctx.snapshot(activeSecondBySlug),
    fullOrganizationBySlugPrecedence: ctx.snapshot(fullOrganizationBySlugPrecedence),
    clearActiveOrganization: ctx.snapshot(clearActiveOrganization),
    fullOrganizationWithoutActive: ctx.snapshot(fullOrganizationWithoutActive),
  };
});

for (const { label, metadata } of [
  { label: "omitted", metadata: undefined },
  { label: "empty", metadata: {} },
  {
    label: "populated",
    metadata: { nested: { enabled: true, limit: 0 }, tier: "gold" },
  },
]) {
  compatScenario(`organization ${label} metadata matches TS during create and update`, async (ctx) => {
    const owner = await signUpUser(ctx, "owner", `phase6-metadata-${label}`, "Owner");
    const created = await owner.orgClient.organization.create({
      name: "Metadata Org",
      slug: ctx.uniqueToken(`phase6-metadata-${label}`),
      ...(metadata === undefined ? {} : { metadata }),
    });
    const organizationId = created.data?.id ?? "";

    // TS omits absent metadata in create/update responses, but preserves {}.
    const updatedWithoutMetadata = await owner.orgClient.organization.update({
      organizationId,
      data: { name: "Metadata Org Renamed" },
    });
    // Read endpoints expose the stored JSON string (or null), even though
    // create/update return the parsed object.
    const fullOrganization = await owner.orgClient.organization.getFullOrganization({
      query: { organizationId },
    });
    const activeOrganization = await owner.orgClient.organization.setActive({
      organizationId,
    });
    const listedOrganizations = await owner.orgClient.organization.list();
    const deletedOrganization = await owner.orgClient.organization.delete({
      organizationId,
    });

    return {
      created: ctx.snapshot(created),
      updatedWithoutMetadata: ctx.snapshot(updatedWithoutMetadata),
      fullOrganization: ctx.snapshot(fullOrganization),
      activeOrganization: ctx.snapshot(activeOrganization),
      listedOrganizations: ctx.snapshot(listedOrganizations),
      deletedOrganization: ctx.snapshot(deletedOrganization),
    };
  });
}

compatScenario("organization metadata updates replace objects and preserve empty objects", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-metadata-update", "Owner");
  const created = await owner.orgClient.organization.create({
    name: "Metadata Update Org",
    slug: ctx.uniqueToken("phase6-metadata-update"),
    metadata: { original: true, tier: "gold" },
  });
  const organizationId = created.data?.id ?? "";
  const replacedMetadata = await owner.orgClient.organization.update({
    organizationId,
    data: { metadata: { nested: { enabled: false }, tier: "silver" } },
  });
  const fullAfterReplacement = await owner.orgClient.organization.getFullOrganization({
    query: { organizationId },
  });
  const emptiedMetadata = await owner.orgClient.organization.update({
    organizationId,
    data: { metadata: {} },
  });
  const updatedWithoutMetadata = await owner.orgClient.organization.update({
    organizationId,
    data: { name: "Metadata Update Org Renamed" },
  });
  const fullAfterEmptying = await owner.orgClient.organization.getFullOrganization({
    query: { organizationId },
  });

  return {
    created: ctx.snapshot(created),
    replacedMetadata: ctx.snapshot(replacedMetadata),
    fullAfterReplacement: ctx.snapshot(fullAfterReplacement),
    emptiedMetadata: ctx.snapshot(emptiedMetadata),
    updatedWithoutMetadata: ctx.snapshot(updatedWithoutMetadata),
    fullAfterEmptying: ctx.snapshot(fullAfterEmptying),
  };
});

compatScenario("organization metadata preserves key order through its lifecycle", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-metadata-order", "Owner");
  const created = await owner.orgClient.organization.create({
    name: "Metadata Order Org",
    slug: ctx.uniqueToken("phase6-metadata-order"),
    metadata: {
      z: 1,
      a: 2,
      nested: { y: true, b: false, "10": "ten", "2": "two" },
      items: [{ z: "last", a: "first" }],
      "10": "ten",
      "2": "two",
    },
  });
  const organizationId = created.data?.id ?? "";
  const fullAfterCreate = await owner.orgClient.organization.getFullOrganization({
    query: { organizationId },
  });
  const listedAfterCreate = await owner.orgClient.organization.list();
  const activeAfterCreate = await owner.orgClient.organization.setActive({
    organizationId,
  });

  const replacedMetadata = await owner.orgClient.organization.update({
    organizationId,
    data: {
      metadata: {
        y: "replacement",
        b: "value",
        nested: { z: 3, a: 4 },
        items: [{ y: true, b: false, "10": "ten", "2": "two" }],
        "20": "twenty",
        "3": "three",
      },
    },
  });
  const fullAfterReplacement = await owner.orgClient.organization.getFullOrganization({
    query: { organizationId },
  });
  const updatedWithoutMetadata = await owner.orgClient.organization.update({
    organizationId,
    data: { name: "Metadata Order Org Renamed" },
  });
  const fullAfterOmittedUpdate = await owner.orgClient.organization.getFullOrganization({
    query: { organizationId },
  });
  const listedAfterOmittedUpdate = await owner.orgClient.organization.list();
  const activeAfterOmittedUpdate = await owner.orgClient.organization.setActive({
    organizationId,
  });
  const deletedOrganization = await owner.orgClient.organization.delete({
    organizationId,
  });

  return {
    created: ctx.snapshot(created),
    // Snapshot normalization sorts object keys. Serialize parsed metadata here
    // so create/update key order is checked alongside the stored read strings.
    createdMetadata: JSON.stringify(created.data?.metadata),
    fullAfterCreate: ctx.snapshot(fullAfterCreate),
    listedAfterCreate: ctx.snapshot(listedAfterCreate),
    activeAfterCreate: ctx.snapshot(activeAfterCreate),
    replacedMetadata: ctx.snapshot(replacedMetadata),
    replacementMetadata: JSON.stringify(replacedMetadata.data?.metadata),
    fullAfterReplacement: ctx.snapshot(fullAfterReplacement),
    updatedWithoutMetadata: ctx.snapshot(updatedWithoutMetadata),
    metadataAfterOmittedUpdate: JSON.stringify(updatedWithoutMetadata.data?.metadata),
    fullAfterOmittedUpdate: ctx.snapshot(fullAfterOmittedUpdate),
    listedAfterOmittedUpdate: ctx.snapshot(listedAfterOmittedUpdate),
    activeAfterOmittedUpdate: ctx.snapshot(activeAfterOmittedUpdate),
    deletedOrganization: ctx.snapshot(deletedOrganization),
  };
});

compatScenario("organization delete returns the deleted org and clears active state", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-delete-owner", "Delete Owner");
  const slug = ctx.uniqueToken("phase6-delete-org");

  const created = await owner.orgClient.organization.create({
    name: "Delete Me",
    slug,
  });
  const deleted = await owner.orgClient.organization.delete({
    organizationId: created.data?.id ?? "",
  });
  const fullOrganizationAfterDelete = await owner.orgClient.organization.getFullOrganization();

  return {
    created: ctx.snapshot(created),
    deleted: ctx.snapshot(deleted),
    fullOrganizationAfterDelete: ctx.snapshot(fullOrganizationAfterDelete),
  };
});

compatScenario("organization create can keep the current active org and full organization honors membersLimit", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-keep-active-owner", "Owner");
  const member = await signUpUser(ctx, "member", "phase6-keep-active-member", "Member");
  const firstSlug = ctx.uniqueToken("phase6-keep-active-first");
  const secondSlug = ctx.uniqueToken("phase6-keep-active-second");

  const firstOrganization = await owner.orgClient.organization.create({
    name: "Keep Active First",
    slug: firstSlug,
  });
  const initialSession = await owner.client.getSession();
  const secondOrganization = await owner.orgClient.organization.create({
    name: "Keep Active Second",
    slug: secondSlug,
    keepCurrentActiveOrganization: true,
  });
  const sessionAfterSecondCreate = await owner.client.getSession();

  const invitation = await owner.orgClient.organization.inviteMember({
    organizationId: firstOrganization.data?.id ?? "",
    email: member.email,
    role: "member",
  });
  const acceptedInvitation = await member.orgClient.organization.acceptInvitation({
    invitationId: invitation.data?.id ?? "",
  });
  const limitedOrganization = await owner.orgClient.organization.getFullOrganization({
    query: {
      organizationId: firstOrganization.data?.id,
      membersLimit: 1,
    },
  });

  return {
    firstOrganization: ctx.snapshot(firstOrganization),
    initialSession: ctx.snapshot(initialSession),
    secondOrganization: ctx.snapshot(secondOrganization),
    sessionAfterSecondCreate: ctx.snapshot(sessionAfterSecondCreate),
    invitation: ctx.snapshot(invitation),
    acceptedInvitation: ctx.snapshot(acceptedInvitation),
    limitedOrganization: ctx.snapshot(limitedOrganization),
  };
});
