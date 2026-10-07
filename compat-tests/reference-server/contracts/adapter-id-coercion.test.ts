import { expect, test } from "bun:test";
import { createAdapterFactory } from "@better-auth/core/db/adapter";
import type { BetterAuthOptions } from "better-auth";

type ObservationOptions = Pick<BetterAuthOptions, "account" | "session" | "user"> & {
  supportsUUIDs?: boolean;
  supportsJSON?: boolean;
  found?: Record<string, unknown>;
};

function observe(generateId: "serial" | "uuid" | false, options: ObservationOptions = {}) {
  const { supportsUUIDs = true, supportsJSON = true, found, ...schema } = options;
  const calls: { method: string; data?: Record<string, unknown>; where?: { value: unknown }[] }[] = [];
  const adapter = createAdapterFactory({
    config: { adapterId: "id-contract", supportsUUIDs, supportsJSON },
    adapter: () => ({
      async create(input) { calls.push({ method: "create", ...input }); return { id: "database-default", ...input.data }; },
      async findOne(input) { calls.push({ method: "findOne", ...input }); return found ?? null; },
      async findMany(input) { calls.push({ method: "findMany", ...input }); return []; },
      async update(input) { calls.push({ method: "update", ...input, data: input.update }); return { id: 1, ...input.update }; },
      async updateMany() { return 0; },
      async delete() {},
      async deleteMany() { return 0; },
      async count() { return 0; },
    }),
  })({ advanced: { database: { generateId } }, ...schema, logger: { disabled: true } });
  return { adapter, calls };
}

test("forced UUIDs require canonical hyphenated v1-v5 syntax before database insertion", async () => {
  const canonical = "63747488-4175-41a0-a68e-153881808aec";
  for (const supportsUUIDs of [false, true]) {
    const { adapter, calls } = observe("uuid", { supportsUUIDs });
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
  const { adapter, calls } = observe("serial", { account: { additionalFields: { userId: {
    type: "string", references: { model: "user", field: "id" },
    transform: { input(value: unknown) { observed.push(value); return "0x10"; } },
  } } } });
  await adapter.create({ model: "account", data: { userId: "alias", accountId: "subject", providerId: "fixture" } });
  expect(observed).toEqual(["alias"]);
  expect(calls.at(-1)?.data?.userId).toBe(16);
  for (const generateId of ["serial", false] as const) {
    const { adapter, calls } = observe(generateId, { supportsJSON: false, account: { additionalFields: { userId: {
      type: "json", references: { model: "user", field: "id" },
      transform: { input(value: unknown) { observed.push(value); return ["0x10", null, [], ["1e0"]]; } },
    } } } });
    await adapter.create({ model: "account", data: { userId: "array-alias", accountId: "subject", providerId: "fixture" } });
    expect(calls.at(-1)?.data?.userId).toEqual(generateId === "serial" ? [16, null, 0, 1] : '["0x10",null,[],["1e0"]]');
  }
  expect(observed).toEqual(["alias", "array-alias", "array-alias"]);
});

test("UUID update resolves the ID policy after preceding same-runtime queries", async () => {
  const supplied = "f79b497c-7d3b-4ff7-a20d-407fd259f788";
  const timestamp = new Date("2030-01-02T03:04:05Z");
  for (const supportsUUIDs of [false, true]) {
    for (const idFirst of [false, true]) {
      for (const read of ["none", "missing", "found"] as const) {
        const events: string[] = [];
        const id = { type: "string" as const, fieldName: "ignored_id_column", transform: {
          input() { throw new Error("Application ID input must be replaced"); },
          output() { throw new Error("Application ID output must be replaced"); },
        } };
        const label = { type: "string" as const, transform: {
          async input(value: unknown) {
            events.push("input");
            if (read !== "none") {
              const row = await adapter.findOne({ model: "session", where: [{ field: "token", value: "nested-token" }] });
              events.push(row === null ? "read:missing" : `read:${row.id}`);
            }
            return value;
          },
        } };
        const { adapter, calls } = observe("uuid", {
          supportsUUIDs,
          found: read === "found" ? { id: "7", token: "nested-token" } : undefined,
          session: { additionalFields: idFirst ? { id, label } : { label, id } },
        });
        const row = await adapter.update({
          model: "session",
          where: [{ field: "token", value: "session-token" }],
          update: { id: supplied, token: "updated-token", updatedAt: timestamp, label: "after" },
        });
        const omitted = supportsUUIDs && (idFirst || read === "none");
        const expected = { token: "updated-token", updatedAt: timestamp, label: "after", ...omitted ? {} : { id: supplied } };
        expect(calls.at(-1)?.data).toEqual(expected);
        expect(calls.map(({ method }) => method)).toEqual(read === "none" ? ["update"] : ["findOne", "update"]);
        expect(row?.id).toBe(omitted ? "1" : supplied);
        expect(row?.label).toBe("after");
        expect(events).toEqual(read === "none" ? ["input"] : ["input", read === "found" ? "read:7" : "read:missing"]);
      }
    }
  }
});

test("UUID create retains forceAllowId through empty unfiltered reads but loses it after field lookup", async () => {
  for (const supportsUUIDs of [false, true]) {
    for (const idFirst of [false, true]) {
      for (const read of ["missing", "empty"] as const) {
        const events: string[] = [];
        const id = { type: "string" as const };
        const label = { type: "string" as const, transform: {
          async input(value: unknown) {
            events.push("input");
            if (read === "missing") {
              expect(await adapter.findOne({ model: "user", where: [{ field: "id", value: "missing-user" }] })).toBeNull();
            } else {
              expect(await adapter.findMany({ model: "user" })).toEqual([]);
            }
            events.push(`read:${read}`);
            return value;
          },
        } };
        const { adapter, calls } = observe("uuid", {
          supportsUUIDs,
          user: { additionalFields: idFirst ? { id, label } : { label, id } },
        });
        const timestamp = new Date("2030-01-02T03:04:05Z");
        const data = { id: "not-a-uuid", name: "Owner", email: "owner@example.test", emailVerified: false, createdAt: timestamp, updatedAt: timestamp, label: "after" };
        const row = await adapter.create({ model: "user", data, forceAllowId: true });
        const { id: supplied, ...withoutId } = data;
        const preserved = !idFirst && read === "missing";
        expect(calls.at(-1)?.data).toEqual(preserved ? data : withoutId);
        expect(calls.map(({ method }) => method)).toEqual([read === "missing" ? "findOne" : "findMany", "create"]);
        expect(row.id).toBe(preserved ? supplied : "database-default");
        expect(events).toEqual(["input", `read:${read}`]);
      }
    }
  }
});
