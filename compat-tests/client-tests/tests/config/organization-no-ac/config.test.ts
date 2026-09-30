import { compatScenario } from "../../../support/scenario";
import { asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("dynamic role writes require an explicit access-control definition", async (ctx) => {
  await signUpUser(ctx, "owner", "no-ac-owner", "Owner");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "No AC Organization", slug: ctx.uniqueToken("no-ac") }));
  await call("owner", "create-role", { organizationId: org.id, role: "custom", permission: {} }, 501);
  await call("owner", "update-role", { organizationId: org.id, roleName: "custom", data: { permission: {} } }, 501);
  return observations;
});
