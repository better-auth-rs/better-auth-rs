import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { username } from "better-auth/plugins";
import { parseInputData } from "better-auth/db";
import { cases, observe, options, owner, revive, user } from "./user-runtime-contract";
import inputCases from "../../../tests/fixtures/user-runtime-input-cases.json";

test("Memory User list binds native Boolean strings from the complete schema", async () => {
  const rows = [true, false].map(emailVerified => ({
    id: emailVerified ? "verified" : "unverified", name: "Owner",
    email: `${emailVerified}@native-query.test`, emailVerified, image: null,
    createdAt: new Date("2030-01-01T00:00:00.000Z"), updatedAt: new Date("2030-01-01T00:00:00.000Z"),
  }));
  const memory = { user: rows, session: [], account: [], verification: [] };
  const before = structuredClone(memory);
  const { adapter } = await betterAuth({ ...options(memory), user: {} }).$context;
  for (const [value, index] of [["true", 0], ["false", 1], ["TRUE", 1], ["", 1]] as const) {
    const where = [{ field: "emailVerified", value }];
    expect(await adapter.findMany({ model: "user", where })).toStrictEqual([rows[index]]);
    expect(await adapter.count({ model: "user", where })).toBe(1);
    expect(memory).toStrictEqual(before);
  }
});

test("Public input keeps own undefined and skips validators and transforms only for undefined input", () => {
  for (const action of ["create", "update"] as const) {
    const events: string[] = [];
    const fields = {
      ownValidator: { type: "string", validator: { input: { "~standard": { validate() { throw new Error("undefined validator ran"); } } } } },
      ownTransform: { type: "string", transform: { input() { throw new Error("undefined transform ran"); } } },
      validated: { type: "string", validator: { input: { "~standard": { validate() { events.push("validator"); return { value: undefined }; } } } } },
      transformed: { type: "string", transform: { input() { events.push("transform"); return undefined; } } },
      factory: { type: "string", defaultValue() { events.push("factory"); return undefined; } },
      literal: { type: "string", required: false, defaultValue: undefined },
    };
    const parsed = parseInputData({ ownValidator: undefined, ownTransform: undefined, validated: "input", transformed: "input" }, { action, fields });
    const expected = Object.assign(Object.create(null), { ownValidator: undefined, ownTransform: undefined, validated: undefined, transformed: undefined });
    if (action === "create") expected.factory = undefined;
    expect(parsed).toStrictEqual(expected);
    expect(Object.keys(parsed)).toStrictEqual(Object.keys(expected));
    expect(events).toStrictEqual(action === "create" ? ["validator", "transform", "factory"] : ["validator", "transform"]);
  }
  expect(() => parseInputData({}, { action: "create", fields: { required: { type: "string", required: true, defaultValue: undefined } } })).toThrow("required is required");
});

for (const create of [true, false]) {
  for (const sample of inputCases.usernames) {
    test(`Username ${create ? "create" : "update"} ${sample.name} keeps native values or fails before storage`, async () => {
      const memory = { user: create ? [] : [user()], session: [], account: [], verification: [] };
      const before = structuredClone(memory);
      const events: unknown[] = [];
      const normalization = sample.mode === "disabled" ? false : sample.mode === "custom" ? (value: unknown) => {
        events.push(["normalize", observe(value)]);
        return { length: 5, label: "normalized" };
      } : undefined;
      const auth = betterAuth({ ...options(memory), plugins: [username({
        usernameNormalization: normalization,
        usernameValidator(value: unknown) { events.push(["validate", observe(value)]); return true; },
      })] });
      const { internalAdapter } = await auth.$context;
      const input: Record<string, any> = { ...user(), username: revive(sample.value) };
      delete input.displayUsername;
      const result = create ? internalAdapter.createUser(input) : internalAdapter.updateUser(owner, input);
      if ("error" in sample) {
        await expect(result).rejects.toThrow(sample.error);
        expect(memory).toStrictEqual(before);
      } else {
        const returned = await result;
        expect(observe(returned!.username)).toStrictEqual(sample.expected);
        expect(observe(memory.user[0].username)).toStrictEqual(sample.expected);
      }
      expect(events).toStrictEqual(sample.events.map(phase => [phase, sample.value]));
    });
  }
}

for (const create of [true, false]) {
  for (const field of cases.fields) {
    test(`User ${create ? "create" : "update"} ${field.name} input replacement reaches storage and after hooks once`, async () => {
      const memory = { user: create ? [] : [user()], session: [], account: [], verification: [] };
      const calls: unknown[] = [];
      const events: [string, any][] = [];
      const replacement = revive(field.replacement);
      const auth = betterAuth({
        ...options(memory, { [field.name]: { transform: { input(value: unknown) { calls.push(value); return replacement; } } } }),
        databaseHooks: { user: {
          create: { before: async (data: unknown) => { events.push(["before", structuredClone(data)]); }, after: async (data: unknown) => { events.push(["after", structuredClone(data)]); } },
          update: { before: async (data: unknown) => { events.push(["before", structuredClone(data)]); }, after: async (data: unknown) => { events.push(["after", structuredClone(data)]); } },
        } },
      });
      const { internalAdapter, adapter } = await auth.$context;
      const input = user();
      const result = create ? await internalAdapter.createUser(input) : await internalAdapter.updateUser(owner, input);
      const count = "calls" in field ? field.calls : 1;
      expect(calls.length).toBe(count);
      if (count) expect(observe(calls[0])).toStrictEqual(observe(input[field.name]));
      const expected = count && (create || replacement !== undefined) ? replacement : input[field.name];
      expect(observe(result![field.name])).toStrictEqual(observe(expected));
      expect(observe(memory.user[0][field.name])).toStrictEqual(observe(expected));
      expect(events.map(event => event[0])).toStrictEqual(["before", "after"]);
      expect(observe(events[0][1][field.name])).toStrictEqual(observe(input[field.name]));
      expect(observe(events[1][1][field.name])).toStrictEqual(observe(expected));
      const expectedRecord = observe({ ...input, [field.name]: expected });
      expect(observe(result)).toStrictEqual(expectedRecord);
      expect(observe(await adapter.findOne({ model: "user", where: [{ field: "id", value: owner }] }))).toStrictEqual(expectedRecord);
      // Memory stores JSON text and omits undefined writes before adapter output.
      const expectedStorage = { ...input, metadata: '{"seed":true}', [field.name]: expected };
      if (create && expected === undefined) delete expectedStorage[field.name];
      expect(observe(memory.user[0])).toStrictEqual(observe(expectedStorage));
      expect(observe(events[1][1])).toStrictEqual(expectedRecord);
    });
  }

  test(`User ${create ? "create" : "update"} hooks merge native patches with the upstream visibility boundary`, async () => {
    const memory = { user: create ? [] : [user()], session: [], account: [], verification: [] };
    const events: [string, any][] = [];
    const first = { email: { source: "hook" }, emailVerified: [] };
    const second = { role: ["admin"] };
    const hooks = (name: string, patch: object) => ({
      create: { before: async (data: unknown) => { events.push([name, structuredClone(data)]); return { data: patch }; }, after: async (data: unknown) => { events.push(["after", structuredClone(data)]); } },
      update: { before: async (data: unknown) => { events.push([name, structuredClone(data)]); return { data: patch }; }, after: async (data: unknown) => { events.push(["after", structuredClone(data)]); } },
    });
    const auth = betterAuth({
      ...options(memory),
      plugins: [{ id: "runtime-input-first", init() { return { options: { databaseHooks: { user: hooks("first", first) } } }; } }],
      databaseHooks: { user: hooks("second", second) },
    });
    const { internalAdapter, adapter } = await auth.$context;
    const input = user();
    const result = create ? await internalAdapter.createUser(input) : await internalAdapter.updateUser(owner, input);
    expect(events.map(event => event[0])).toStrictEqual(["first", "second", "after", "after"]);
    for (const [name, value] of Object.entries({ ...first, ...second })) {
      expect(observe(result![name])).toStrictEqual(observe(value));
      expect(observe(memory.user[0][name])).toStrictEqual(observe(value));
      expect(observe(events[2][1][name])).toStrictEqual(observe(value));
      expect(observe(events[3][1][name])).toStrictEqual(observe(value));
    }
    const expectedRecord = observe({ ...input, ...first, ...second });
    expect(observe(await adapter.findOne({ model: "user", where: [{ field: "id", value: owner }] }))).toStrictEqual(expectedRecord);
    for (const record of [result, events[2][1], events[3][1]]) {
      expect(observe(record)).toStrictEqual(expectedRecord);
    }
    expect(observe(memory.user[0])).toStrictEqual(observe({ ...input, metadata: '{"seed":true}', ...first, ...second }));
    expect(events[0][1].email).toBe(input.email);
    expect(observe(events[1][1].email)).toStrictEqual(observe(create ? first.email : input.email));
  });

  test(`User ${create ? "create" : "update"} later input errors stop writes and after hooks`, async () => {
    const memory = { user: create ? [] : [user()], session: [], account: [], verification: [] };
    const before = structuredClone(memory);
    const calls: string[] = [];
    const events: string[] = [];
    const fields = Object.fromEntries(["emailVerified", "createdAt"].map(name => [name, { transform: { input(value: unknown) {
      calls.push(name);
      if (name === "createdAt") throw new Error("user-input-stop");
      return value;
    } } }]));
    const hooks = { before: async () => { events.push("before"); }, after: async () => { events.push("after"); } };
    const auth = betterAuth({ ...options(memory, fields), databaseHooks: { user: { create: hooks, update: hooks } } });
    const { internalAdapter } = await auth.$context;
    await expect(create ? internalAdapter.createUser(user()) : internalAdapter.updateUser(owner, user())).rejects.toThrow("user-input-stop");
    expect(calls).toStrictEqual(["emailVerified", "createdAt"]);
    expect(events).toStrictEqual(["before"]);
    expect(memory).toStrictEqual(before);
  });
}

for (const create of [true, false]) {
  for (const sample of inputCases.emails) {
    test(`User ${create ? "create" : "update"} ${sample.name} email normalization runs before hooks`, async () => {
      const memory = { user: create ? [] : [user()], session: [], account: [], verification: [] };
      const before = structuredClone(memory);
      const events: [string, any][] = [];
      const hooks = { before: async (data: unknown) => { events.push(["before", structuredClone(data)]); }, after: async (data: unknown) => { events.push(["after", structuredClone(data)]); } };
      const auth = betterAuth({ ...options(memory), databaseHooks: { user: { create: hooks, update: hooks } } });
      const { internalAdapter } = await auth.$context;
      const input = { ...user(), email: revive(sample.value) };
      const operation = create ? "create" : "update";
      const result = create ? internalAdapter.createUser(input) : internalAdapter.updateUser(owner, input);
      if (`${operation}Error` in sample) {
        await expect(result).rejects.toThrow("toLowerCase");
        expect(events).toStrictEqual([]);
        expect(memory).toStrictEqual(before);
      } else {
        const returned = await result;
        expect(events.map(event => event[0])).toStrictEqual(["before", "after"]);
        expect(observe(events[0][1].email)).toStrictEqual(sample[operation]);
        const selected = revive(sample[operation]);
        const expected = !create && selected === undefined ? before.user[0].email : selected;
        expect(observe(returned!.email)).toStrictEqual(observe(expected));
        expect(observe(memory.user[0].email)).toStrictEqual(observe(expected));
      }
    });
  }
}
