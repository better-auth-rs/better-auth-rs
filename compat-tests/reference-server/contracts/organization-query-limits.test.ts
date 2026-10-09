import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
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

test("member equality filters do not coerce objects and retain the organization constraint", async () => {
  const { adapter, database } = await fixture();
  database.organization.push({ ...database.organization[0], id: "other", slug: "other" });
  database.member.push({ ...database.member[0], id: "outside", organizationId: "other" });
  const before = JSON.stringify(database);
  const filter = { field: "role", value: { toString: null } };
  const equal = await adapter.listMembers({ organizationId: "org", filter: { ...filter, operator: "eq" } });
  expect(equal.members).toStrictEqual([]);
  expect(equal.total).toBe(0);
  const unequal = await adapter.listMembers({ organizationId: "org", filter: { ...filter, operator: "ne" } });
  expect(unequal.members.map(member => [member.id, member.organizationId, member.user.id])).toStrictEqual([
    ["m0", "org", "u1"], ["m1", "org", "u2"],
  ]);
  expect(unequal.total).toBe(2);
  for (const operator of ["gt", "gte", "lt", "lte"]) {
    await expect(adapter.listMembers({ organizationId: "org", filter: { ...filter, operator } }))
      .rejects.toBeInstanceOf(TypeError);
  }
  expect(JSON.stringify(database)).toBe(before);
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


const pendingPast = new Date("2000-01-01T00:00:00.000Z");
const pendingFuture = new Date("2100-01-01T00:00:00.000Z");
const pendingLater = new Date("2100-01-02T00:00:00.000Z");

async function pendingFixture(backend: "memory" | "sqlite", limit?: number) {
  const memory: Record<string, Record<string, unknown>[]> = { invitation: [] };
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  database?.exec(`CREATE TABLE invitation (id TEXT PRIMARY KEY NOT NULL, organizationId TEXT NOT NULL,
    email TEXT NOT NULL, role TEXT, status TEXT NOT NULL, inviterId TEXT NOT NULL, teamId TEXT,
    expiresAt TEXT NOT NULL, createdAt TEXT NOT NULL);`);
  const events: string[] = [];
  const state: { replacement: unknown; failLater: boolean } = { replacement: pendingLater, failLater: false };
  const options = (fields: Record<string, unknown> = {}) => ({
    database: database ?? memoryAdapter(memory),
    secret: "pending-invitation-query-secret-at-least-32-characters",
    baseURL: "http://pending.test", logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { defaultFindManyLimit: limit } },
    plugins: [organization({ schema: { invitation: { additionalFields: fields } } })],
  });
  const writer = await betterAuth(options()).$context;
  const stored: Record<string, unknown>[] = [];
  for (const [id, organizationId, email, expiresAt, status] of [
    ["first", "organization", "recipient@pending.test", pendingPast, "pending"],
    ["second", "organization", "recipient@pending.test", pendingFuture, "pending"],
    ["third", "organization", "other@pending.test", pendingLater, "pending"],
    ["canceled", "organization", "recipient@pending.test", pendingLater, "canceled"],
    ["outside", "outside", "UPPER@pending.test", pendingLater, "pending"],
  ]) {
    stored.push(await writer.adapter.create({ model: "invitation", forceAllowId: true,
      data: { id, organizationId, email, expiresAt, status, role: "member", inviterId: "inviter", teamId: null, createdAt: pendingPast },
    }));
  }
  const raw = () => structuredClone(database ? database.query("SELECT * FROM invitation ORDER BY rowid").all() : memory.invitation);
  const before = raw();
  const reader = await betterAuth(options({
    status: { type: "string", transform: { output() { return "canceled"; } } },
    expiresAt: { type: "date", transform: { output(value: Date) {
      const milliseconds = value.getTime();
      const name = milliseconds === pendingPast.getTime() ? "first" : milliseconds === pendingFuture.getTime() ? "second" : "third";
      events.push(name);
      if (state.failLater) {
        if (name === "second") throw new Error("later-invitation-output-failed");
        return pendingLater;
      }
      return name === "first" ? state.replacement : name === "second" ? "invalid-expiry" : value;
    } } },
  })).$context;
  return { adapter: getOrgAdapter(reader, {}), state, events, stored, before, raw, close: () => database?.close() };
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const limit of [undefined, 0, 1]) {
    test(`${backend} pending invitations project the complete page before expiry and quota: ${limit}`, async () => {
      const fixture = await pendingFixture(backend, limit);
      const { adapter, state, events, stored } = fixture;
      try {
        for (const [label, replacement, active, failure] of [
          ["date", pendingLater, true, false],
          ["text", pendingLater.toISOString(), true, false],
          ["number", pendingLater.getTime(), true, false],
          ["null", null, false, false],
          ["undefined", undefined, false, false],
          ["invalid", "invalid-expiry", false, false],
          ["invalid-date", new Date(NaN), false, false],
          ["object", { toString: null }, false, true],
        ] as const) {
          state.replacement = replacement;
          const first = adapter.findPendingInvitation({ organizationId: "organization", email: "RECIPIENT@pending.test" });
          if (failure && limit !== 0) await expect(first).rejects.toEqual(new TypeError("No default value"));
          else {
            const result = await first;
            expect(result).toStrictEqual(active && limit !== 0 ? [{ ...stored[0], expiresAt: replacement, status: "canceled" }] : []);
          }
          expect(events.splice(0), `${label}: getter output page`).toStrictEqual(limit === 0 ? [] : limit === 1 ? ["first"] : ["first", "second"]);
          const all = adapter.findPendingInvitations({ organizationId: "organization" });
          if (failure && limit !== 0) await expect(all).rejects.toEqual(new TypeError("No default value"));
          else {
            const result = await all;
            expect(result.length).toBe(limit === 0 ? 0 : Number(active) + Number(limit !== 1));
            expect(result).toStrictEqual(limit === 0 ? [] : [
              ...(active ? [{ ...stored[0], expiresAt: replacement, status: "canceled" }] : []),
              ...(limit === 1 ? [] : [{ ...stored[2], status: "canceled" }]),
            ]);
          }
          expect(events.splice(0), `${label}: quota output page`).toStrictEqual(limit === 0 ? [] : limit === 1 ? ["first"] : ["first", "second", "third"]);
          expect(await adapter.findPendingInvitation({ organizationId: "outside", email: "UPPER@pending.test" })).toStrictEqual([]);
          expect(events.splice(0)).toStrictEqual([]);
        }
        state.failLater = true;
        for (const operation of [
          () => adapter.findPendingInvitation({ organizationId: "organization", email: "recipient@pending.test" }),
          () => adapter.findPendingInvitations({ organizationId: "organization" }),
        ]) {
          if (limit === undefined) await expect(operation()).rejects.toEqual(new Error("later-invitation-output-failed"));
          else await operation();
        }
        expect(fixture.raw()).toStrictEqual(fixture.before);
      } finally { fixture.close(); }
    });
  }
}
