import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";
import { configure, trace } from "./helpers";

compatScenario("server-only member creation enforces callback session requirements and rolls back failed team additions", async (ctx) => {
  await signUpUser(ctx, "owner", "server-owner", "Owner");
  const target = await signUpUser(ctx, "target", "server-target", "Target");
  expect(target.signup.data!.user).not.toHaveProperty("secretNote");
  const { call, observations } = requests(ctx);
  const org = asRecord(await call("owner", "create", { name: "Server", slug: ctx.uniqueToken("server-member") }));
  const organizationId = org.id;
  const team = asRecord(await call("owner", "create-team", { organizationId, name: "Server Team" }));
  const input = { organizationId, teamId: team.id, userId: target.signup.data!.user.id, role: "member" };
  const add = async (actor: string, status: number) => {
    const response = await ctx.rawRequest({ actor, path: "/__test/organization-add-member", method: "POST", json: input });
    expect(response.status, JSON.stringify(response.body)).toBe(status);
    observations.push(response);
    return response.body;
  };
  await configure(ctx);
  await add("anonymous", 401);
  const anonymousTrace = await trace(ctx);
  expect(anonymousTrace.map((event) => event.event)).toEqual(["membershipLimit", "beforeAddMember"]);
  expect(asArray(asRecord(await call("owner", `list-members?organizationId=${organizationId}`)).members)).toHaveLength(1);
  observations.push(anonymousTrace);
  await configure(ctx, { limits: { maximumMembersPerTeam: 0 } });
  await add("owner", 403);
  const fullTrace = await trace(ctx);
  expect(fullTrace.map((event) => event.event)).toEqual(["membershipLimit", "beforeAddMember", "maximumMembersPerTeam"]);
  expect(asArray(asRecord(await call("owner", `list-members?organizationId=${organizationId}`)).members)).toHaveLength(1);
  observations.push(fullTrace);
  await configure(ctx);
  const member = asRecord(await add("owner", 200));
  expect(member.role).toBe("admin");
  expect(member.userId).toBe(target.signup.data!.user.id);
  const success = await trace(ctx);
  expect(success.map((event) => event.event)).toEqual(["membershipLimit", "beforeAddMember", "maximumMembersPerTeam", "afterAddMember"]);
  for (const event of [...anonymousTrace, ...fullTrace, ...success]) {
    if (event.user) {
      expect(asRecord(event.user).id).toBe(target.signup.data!.user.id);
      expect(asRecord(event.user).secretNote).toBe("hidden");
    }
    if (event.session) expect(asRecord(asRecord(event.session).user)).not.toHaveProperty("secretNote");
  }
  observations.push(success);
  return observations;
});
