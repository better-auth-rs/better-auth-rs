import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("explicit empty organization roles do not restore default owner permissions", async (ctx) => {
  await signUpUser(ctx, "owner", "empty-roles-owner", "Owner");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "No permissions", slug: ctx.uniqueToken("empty-roles") }));
  const permission = asRecord(await call("owner", "has-permission", { organizationId: organization.id, permissions: { organization: ["update", "delete"] } }));
  expect(permission.success).toBe(false);
  const update = asRecord(await call("owner", "update", { organizationId: organization.id, data: { name: "Unexpected mutation" } }, 403));
  expect(update.code).toBe("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION");
  const invite = asRecord(await call("owner", "invite-member", { organizationId: organization.id, email: ctx.uniqueEmail("empty-role-recipient"), role: "member" }, 403));
  expect(invite.code).toBe("YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION");
  await call("owner", "delete", { organizationId: organization.id }, 403);
  const stored = asRecord(await call("owner", `get-organization?organizationId=${organization.id}`));
  expect(stored.id).toBe(organization.id);
  expect(stored.name).toBe("No permissions");
  return observations;
});
