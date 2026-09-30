import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";

compatScenario("organization builtin replacement types retain null, omission and raw date strings", async (ctx) => {
  await signUpUser(ctx, "owner", "dynamic-owner", "Owner");
  const { call, observations } = requests(ctx);
  for (const [index, input] of [{ name: 7, logo: true }, { name: null }, {}, { name: 99 }].entries()) {
    const organization = asRecord(await call("owner", "create", { ...input, slug: ctx.uniqueToken(`dynamic-${index}`) }));
    expect(organization.createdAt).toBe("2000-01-02T03:04:05+02:00");
    expect(organization.updatedAt).toBe("public-updated");
    if (input.name === 99) expect(organization).not.toHaveProperty("name");
    else expect(organization.name).toBe(input.name ?? null);
    const read = asRecord(await call("owner", `get-organization?organizationId=${organization.id}`));
    expect(read.name).toBe(organization.name);
    expect(read.createdAt).toBe(organization.createdAt);
    expect(read.updatedAt).toBe(organization.updatedAt);
    await call("owner", "update", { organizationId: organization.id, data: { name: 8 } }, 400);
    await call("owner", "update", { organizationId: organization.id, data: { logo: true } }, 400);
  }
  await call("owner", "list");
  await call("owner", "create", { name: "invalid", slug: ctx.uniqueToken("invalid") }, 400);
  return observations;
});

compatScenario("team dynamic names preserve the internal membership counter contract", async (ctx) => {
  await signUpUser(ctx, "owner", "dynamic-team-owner", "Owner");
  const { call, observations } = requests(ctx);
  const organization = asRecord(await call("owner", "create", { name: 1, slug: ctx.uniqueToken("teams") }));
  const organizationId = organization.id;
  for (const name of [{ label: "structured" }, ["array", 1], null]) {
    const team = asRecord(await call("owner", "create-team", { organizationId, name, createdAt: "custom-created" }));
    expect(team.name).toEqual(name);
    expect(team.createdAt).toBe("custom-created");
    expect(team).not.toHaveProperty("memberCount");
    expect(team.updatedAt).toBe("2000-01-02T03:04:05+02:00");
    const updated = asRecord(await call("owner", "update-team", { teamId: team.id, data: { name: 1 } }));
    expect(updated.name).toBe(1);
    const cleared = asRecord(await call("owner", "update-team", { teamId: team.id, data: { name: null } }));
    expect(cleared.name).toBeNull();
  }
  const full = asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`));
  for (const team of asArray(full.teams)) expect(asRecord(team).memberCount).toBe(0);
  const teams = asArray(await call("owner", `list-teams?organizationId=${organizationId}`));
  for (const team of teams) expect(asRecord(team)).not.toHaveProperty("memberCount");
  return observations;
});
