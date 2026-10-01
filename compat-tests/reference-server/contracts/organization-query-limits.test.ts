import { expect, test } from "bun:test";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(new URL("../package.json", import.meta.url));
const { betterAuth } = await import(require.resolve("better-auth"));
const { memoryAdapter } = await import(require.resolve("better-auth/adapters/memory"));
const { organization } = await import(require.resolve("better-auth/plugins"));
const { getOrgAdapter } = await import(join(dirname(require.resolve("better-auth")), "plugins/organization/adapter.mjs"));

async function fixture(membershipLimit?: number | (() => number), defaultLimit?: number) {
  const now = new Date();
  const database = {
    user: ["u2", "u1"].map(id => ({ id, name: id, email: `${id}@example.test`, emailVerified: false, createdAt: now, updatedAt: now })),
    organization: [{ id: "org", name: "Organization", slug: "organization", createdAt: now }],
    member: ["u1", "u2"].map((userId, index) => ({ id: `m${index}`, userId, organizationId: "org", role: "member", createdAt: now })),
    invitation: [],
    team: [],
  };
  const options = { membershipLimit };
  const auth = betterAuth({
    secret: "organization-limit-oracle-secret-long-enough",
    baseURL: "http://organization.test",
    logger: { disabled: true },
    database: memoryAdapter(database),
    advanced: { database: { defaultFindManyLimit: defaultLimit } },
    plugins: [organization(options)],
  });
  const context = await auth.$context;
  return { database, adapter: getOrgAdapter(context, options) };
}

test("member lists override the database default and preserve member order", async () => {
  const { adapter } = await fixture(undefined, 0);
  const result = await adapter.listMembers({ organizationId: "org" });
  expect(result.members.map(member => member.user.id)).toEqual(["u1", "u2"]);
  expect(result.total).toBe(2);
});

for (const membershipLimit of [undefined, 0, () => 1]) {
  test(`full organization user lookup uses static truthy membership limit: ${String(membershipLimit)}`, async () => {
    const { adapter } = await fixture(membershipLimit);
    const result = await adapter.findFullOrganization({ organizationId: "org" });
    expect(result.members.map(member => member.user.id)).toEqual(["u1", "u2"]);
  });
}

test("full organization throws when the user page omits a member", async () => {
  const { adapter } = await fixture(1);
  await expect(adapter.findFullOrganization({ organizationId: "org" }))
    .rejects.toThrow("Unexpected error: User not found for member");
});

test("full organization member joins use the database default before the user lookup", async () => {
  const { adapter } = await fixture(undefined, 1);
  const result = await adapter.findFullOrganization({ organizationId: "org" });
  expect(result.members.map(member => member.user.id)).toEqual(["u1"]);
  const explicit = await adapter.findFullOrganization({ organizationId: "org", membersLimit: 2 });
  expect(explicit.members.map(member => member.user.id)).toEqual(["u1", "u2"]);
});

for (const full of [false, true]) {
  test(`${full ? "full organization" : "member list"} rejects an orphaned member`, async () => {
    const { adapter, database } = await fixture();
    database.user.splice(0, 1);
    const result = full
      ? adapter.findFullOrganization({ organizationId: "org" })
      : adapter.listMembers({ organizationId: "org" });
    await expect(result).rejects.toThrow("Unexpected error: User not found for member");
  });
}
