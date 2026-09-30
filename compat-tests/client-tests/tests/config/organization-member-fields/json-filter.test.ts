import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("JSON member filters compare adapter storage values without input transforms", async (ctx) => {
  await signUpUser(ctx, "owner", "json-filter-owner", "Owner");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: "JSON filters", slug: "json-filters" }));
  const query = (value: string, operator = "eq") => `list-members?organizationId=${organization.id}&filterField=role&filterValue=${encodeURIComponent(value)}&filterOperator=${operator}`;
  const stored = asRecord(await call("owner", query('"owner"')));
  expect(stored.total).toBe(1);
  expect(asRecord(asArray(stored.members)[0]).role).toBe("owner");
  expect(asRecord(await call("owner", query("owner"))).total).toBe(0);
  expect(asRecord(await call("owner", query('"owner"', "contains"))).total).toBe(1);
  expect(asRecord(await call("owner", query("owner", "ne"))).total).toBe(1);
  const target = await signUpUser(ctx, "target", "json-filter-target", "Target");
  const added = await ctx.rawRequest({ actor: "owner", path: "/__test/organization-add-member", method: "POST", json: { organizationId: organization.id, userId: target.signup.data!.user.id, role: { custom: true } } });
  expect(added.status).toBe(200); observations.push(added);
  const object = asRecord(await call("owner", query('{"custom":true}')));
  expect(object.total).toBe(1);
  expect(asRecord(asArray(object.members)[0]).id).toBe(asRecord(added.body).id);
  expect(asRecord(await call("owner", query("custom", "contains"))).total).toBe(1);
  return observations;
});
