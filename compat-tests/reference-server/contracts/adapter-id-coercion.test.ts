import { expect, test } from "bun:test";
import { createAdapterFactory } from "@better-auth/core/db/adapter";

function observe(generateId: "serial" | "uuid" | false, supportsUUIDs = true, account = {}, supportsJSON = true) {
  const calls: { method: string; data?: Record<string, unknown>; where?: { value: unknown }[] }[] = [];
  const adapter = createAdapterFactory({
    config: { adapterId: "id-contract", supportsUUIDs, supportsJSON },
    adapter: () => ({
      async create(input) { calls.push({ method: "create", ...input }); return { id: "database-default", ...input.data }; },
      async findOne(input) { calls.push({ method: "findOne", ...input }); return null; },
      async findMany(input) { calls.push({ method: "findMany", ...input }); return []; },
      async update(input) { calls.push({ method: "update", ...input, data: input.update }); return { id: 1, ...input.update }; },
      async updateMany() { return 0; },
      async delete() {},
      async deleteMany() { return 0; },
      async count() { return 0; },
    }),
  })({ advanced: { database: { generateId } }, account, logger: { disabled: true } });
  return { adapter, calls };
}

test("forced UUIDs require canonical hyphenated v1-v5 syntax before database insertion", async () => {
  const canonical = "63747488-4175-41a0-a68e-153881808aec";
  for (const supportsUUIDs of [false, true]) {
    const { adapter, calls } = observe("uuid", supportsUUIDs);
    for (const id of [canonical, canonical.toUpperCase(), canonical.replaceAll("-", ""), `{${canonical}}`, `urn:uuid:${canonical}`, canonical.replace("41a0", "71a0")]) {
      const row = await adapter.create({ model: "user", data: { id, name: "Owner", email: "owner@example.test" }, forceAllowId: true });
      const valid = id === canonical || id === canonical.toUpperCase();
      expect(calls.at(-1)?.data?.id).toBe(valid ? id : undefined);
      expect(row.id).toBe(valid ? id : "database-default");
    }
  }
});

test("serial IDs and references use Number for where and write", async () => {
  const { adapter, calls } = observe("serial");
  for (const [input, expected] of [["1e0", 1], [" 1 ", 1], ["0x10", 16], ["0o10", 8], ["0b10", 2], ["", 0], ["\uFEFF", 0], ["1.5", 1.5], ["invalid", NaN]] as const) {
    await adapter.findOne({ model: "user", where: [{ field: "id", value: input }] });
    expect(calls.at(-1)?.where?.[0]?.value).toBe(expected);
    await adapter.findMany({ model: "session", where: [{ field: "userId", value: input }] });
    expect(calls.at(-1)?.where?.[0]?.value).toBe(expected);
    await adapter.create({ model: "account", data: { userId: input, accountId: "subject", providerId: "fixture" } });
    expect(calls.at(-1)?.data?.userId).toBe(expected);
    await adapter.update({ model: "account", where: [{ field: "id", value: "1e0" }], update: { userId: input } });
    expect(calls.at(-1)?.where?.[0]?.value).toBe(1);
    expect(calls.at(-1)?.data?.userId).toBe(expected);
  }
  await adapter.create({ model: "account", data: { userId: null, accountId: "null", providerId: "fixture" } });
  expect(calls.at(-1)?.data?.userId).toBeNull();
  await adapter.findMany({ model: "user", where: [{ field: "id", operator: "in", value: ["1e0", "0x10", null] }] });
  expect(calls.at(-1)?.where?.[0]?.value).toEqual([1, 16, 0]);
});

test("database-generated mode preserves string IDs and references", async () => {
  const { adapter, calls } = observe(false);
  for (const input of ["1e0", " 1 ", "0x10"]) {
    await adapter.findOne({ model: "user", where: [{ field: "id", value: input }] });
    expect(calls.at(-1)?.where?.[0]?.value).toBe(input);
    await adapter.create({ model: "account", data: { userId: input, accountId: "subject", providerId: "fixture" } });
    expect(calls.at(-1)?.data?.userId).toBe(input);
  }
});

test("serial reference conversion follows application input transforms", async () => {
  const observed: unknown[] = [];
  const { adapter, calls } = observe("serial", true, { additionalFields: { userId: {
    type: "string", references: { model: "user", field: "id" },
    transform: { input(value: unknown) { observed.push(value); return "0x10"; } },
  } } });
  await adapter.create({ model: "account", data: { userId: "alias", accountId: "subject", providerId: "fixture" } });
  expect(observed).toEqual(["alias"]);
  expect(calls.at(-1)?.data?.userId).toBe(16);
  for (const generateId of ["serial", false] as const) {
    const { adapter, calls } = observe(generateId, true, { additionalFields: { userId: {
      type: "json", references: { model: "user", field: "id" },
      transform: { input(value: unknown) { observed.push(value); return ["0x10", null, [], ["1e0"]]; } },
    } } }, false);
    await adapter.create({ model: "account", data: { userId: "array-alias", accountId: "subject", providerId: "fixture" } });
    expect(calls.at(-1)?.data?.userId).toEqual(generateId === "serial" ? [16, null, 0, 1] : '["0x10",null,[],["1e0"]]');
  }
  expect(observed).toEqual(["alias", "array-alias", "array-alias"]);
});
