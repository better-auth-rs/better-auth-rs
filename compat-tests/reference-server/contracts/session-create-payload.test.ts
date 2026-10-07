import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";
import { runWithTransaction } from "@better-auth/core/context";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

assert.equal(JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version, "1.7.6");

type Mode = "database" | "secondary" | "mirrored";
type RecordValue = Record<string, unknown>;
type Events = unknown[][];
type Before = (data: RecordValue) => void | false | { data: RecordValue };
const modes: Mode[] = ["database", "secondary", "mirrored"];
const generatedId = "generated-session-1";
const lifetimeSeconds = 3600;
const userDate = new Date("2030-01-02T03:04:05.000Z");
const owner = {
  id: "owner", name: "Owner", email: "owner@session-payload.test", emailVerified: true,
  image: null, createdAt: userDate, updatedAt: userDate,
};
const otherUser = { ...owner, id: "other", name: "Other", email: "other@session-payload.test" };

function nativeSession() {
  return {
    token: "caller-token", userId: owner.id,
    expiresAt: new Date("2100-01-02T03:04:05.000Z"),
    createdAt: new Date("2030-01-02T03:04:05.000Z"),
    updatedAt: new Date("2030-01-02T03:04:06.000Z"),
    ipAddress: "192.0.2.10", userAgent: "session-payload-contract",
  };
}

function replacement() {
  return {
    token: "hook-token", userId: otherUser.id,
    expiresAt: new Date("2101-01-02T03:04:05.000Z"),
    createdAt: new Date("2031-01-02T03:04:05.000Z"),
    updatedAt: new Date("2031-01-02T03:04:06.000Z"),
  };
}

function generation(mode: Mode) {
  return ["generate", mode === "secondary" ? { model: "session", size: undefined } : { model: "session" }, generatedId];
}

function initialRecord(mode: Mode, fields: RecordValue) {
  return { ...fields, ...(mode === "secondary" ? { id: generatedId } : {}) };
}

async function observe(options: {
  mode: Mode;
  caller?: RecordValue;
  overrideAll?: boolean;
  fields?: (events: Events) => Record<string, DBFieldAttribute>;
  beforePlugin?: Before;
  beforeUser?: Before;
  expectedError?: Error;
  deferred?: boolean;
}) {
  const events: Events = [];
  const before: RecordValue[] = [];
  const hookInputs: RecordValue[] = [];
  const memory: Record<string, RecordValue[]> = { user: [], account: [], session: [], verification: [] };
  const cache = new Map<string, { value: string; ttl: number | undefined }>();
  let generated = 0;
  function hooks(source: string, callback?: Before) {
    return { session: { create: {
      before(data: RecordValue) {
        const snapshot = structuredClone(data);
        before.push(snapshot);
        hookInputs.push(data);
        events.push(["before", source, snapshot]);
        return callback?.(data);
      },
      after(data: RecordValue) { events.push(["after", source, structuredClone(data)]); },
    } } };
  }
  const context = await betterAuth({
    database: memoryAdapter(memory),
    baseURL: "http://session-payload.test",
    secret: "session-payload-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId(input) {
      const id = `generated-${input.model}-${++generated}`;
      events.push(["generate", { ...input }, id]);
      return id;
    } } },
    session: {
      expiresIn: lifetimeSeconds,
      storeSessionInDatabase: options.mode !== "secondary",
      additionalFields: options.fields?.(events),
    },
    plugins: [{
      id: "session-payload-contract",
      init() { return { options: { databaseHooks: hooks("plugin", options.beforePlugin) } }; },
    }],
    databaseHooks: hooks("user", options.beforeUser),
    ...(options.mode !== "database" ? { secondaryStorage: {
      async get(key: string) {
        const value = cache.get(key)?.value ?? null;
        events.push(["get", key, value]);
        return value;
      },
      async set(key: string, value: string, ttl?: number) {
        cache.set(key, { value, ttl });
        events.push(["set", key, JSON.parse(value), ttl]);
      },
      async delete(key: string) { events.push(["delete", key]); cache.delete(key); },
    } } : {}),
  }).$context;
  for (const user of [owner, otherUser]) {
    expect(await context.adapter.create({ model: "user", forceAllowId: true, data: user })).toStrictEqual(user);
  }
  expect(events).toStrictEqual([]);
  const started = Date.now();
  const create = () => context.internalAdapter.createSession(owner.id, false, options.caller, options.overrideAll, {
    deferSecondaryStorageWrites: options.deferred,
  });
  const operation = options.deferred ? runWithTransaction(context.adapter, async () => {
    const result = await create();
    expect([...cache]).toStrictEqual([]);
    events.push(["transaction-return", structuredClone(result)]);
    return result;
  }) : create();
  let result: RecordValue | null = null;
  if (options.expectedError) await expect(operation).rejects.toBe(options.expectedError);
  else result = await operation;
  return {
    ...options, events, before, hookInputs, memory, cache, result, started, finished: Date.now(),
    readStoredSession(token: string) {
      return context.adapter.findOne({ model: "session", where: [{ field: "token", value: token }] });
    },
  };
}

function check(observation: Awaited<ReturnType<typeof observe>>, expected: {
  defaults?: Events;
  adapter?: Events;
  before: RecordValue[];
  result: RecordValue | null;
  row?: RecordValue;
  mirror?: { token: string; expiresAt: Date };
}) {
  expect(observation.result).toStrictEqual(expected.result);
  expect(observation.before).toStrictEqual(expected.before);
  expect(observation.memory).toStrictEqual({
    user: [owner, otherUser], account: [],
    session: observation.mode !== "secondary" && expected.result ? [expected.row ?? expected.result] : [], verification: [],
  });
  const events: Events = [
    ...(observation.mode === "secondary" ? [generation(observation.mode)] : []),
    ...(expected.defaults ?? []),
    ...expected.before.map((data, index) => ["before", index === 0 ? "plugin" : "user", data]),
    ...(expected.adapter ?? []),
  ];
  const after: Events = expected.result === null ? [] : [
    ["after", "plugin", expected.result], ["after", "user", expected.result],
  ];
  if (expected.result !== null && observation.mode !== "secondary") events.push(generation(observation.mode));
  if (observation.deferred) events.push(["transaction-return", expected.result], ...after);
  let cache: [string, { value: unknown; ttl: number }][] = [];
  if (observation.mode !== "database" && expected.result !== null) {
    assert.ok(expected.mirror);
    const { token, expiresAt } = expected.mirror;
    const ttl = observation.cache.get(token)?.ttl;
    assert.ok(typeof ttl === "number" && Number.isInteger(ttl));
    expect(ttl).toBeGreaterThanOrEqual(Math.floor((expiresAt.getTime() - observation.finished) / 1000));
    expect(ttl).toBeLessThanOrEqual(Math.floor((expiresAt.getTime() - observation.started) / 1000));
    const references = [{ token, expiresAt: expiresAt.getTime() }];
    // The mirror captures the caller's owner even when a hook replaces the session's userId.
    const value = JSON.parse(JSON.stringify({ session: expected.result, user: owner }));
    cache = [
      [`active-sessions-${owner.id}`, { value: references, ttl }],
      [token, { value, ttl }],
    ];
    events.push(["get", `active-sessions-${owner.id}`, null]);
    for (const [key, entry] of cache) events.push(["set", key, entry.value, entry.ttl]);
  }
  if (!observation.deferred) events.push(...after);
  expect([...observation.cache].map(([key, entry]) => [key, { value: JSON.parse(entry.value), ttl: entry.ttl }])).toStrictEqual(cache);
  expect(observation.events).toStrictEqual(events);
}

test("native session values are generated before hooks and ordinary caller overrides cannot replace them", async () => {
  for (const mode of modes) {
    const caller = { ...nativeSession(), id: "ignored-id", userId: otherUser.id };
    const observation = await observe({ mode, caller, fields: events => ({
      label: { type: "string", defaultValue() { events.push(["default", "label", "D"]); return "D"; } },
    }) });
    const before = observation.before[0];
    assert.ok(before);
    assert.ok(typeof before.token === "string");
    expect(before.token).toMatch(/^[A-Za-z0-9]{32}$/);
    for (const name of ["createdAt", "updatedAt", "expiresAt"]) {
      const date = before[name];
      assert.ok(date instanceof Date);
      const offset = name === "expiresAt" ? lifetimeSeconds * 1000 : 0;
      expect(date.getTime()).toBeGreaterThanOrEqual(observation.started + offset);
      expect(date.getTime()).toBeLessThanOrEqual(observation.finished + offset);
    }
    expect(observation.hookInputs[0]?.createdAt).not.toBe(observation.hookInputs[0]?.updatedAt);
    expect(observation.hookInputs[0]).toBe(observation.hookInputs[1]);
    const record = initialRecord(mode, {
      token: before.token, userId: owner.id, expiresAt: before.expiresAt,
      createdAt: before.createdAt, updatedAt: before.updatedAt,
      ipAddress: caller.ipAddress, userAgent: caller.userAgent, label: "D",
    });
    assert.ok(before.expiresAt instanceof Date);
    check(observation, {
      defaults: [["default", "label", "D"]], before: [record, record],
      result: { ...record, id: generatedId }, mirror: { token: before.token, expiresAt: before.expiresAt },
    });
  }
});

test("configured native defaults precede hooks while overrideAll reapplies caller values after evaluating defaults", async () => {
  for (const mode of modes) {
    for (const overrideAll of [false, true]) {
      const native = nativeSession();
      const caller = { ...native, id: "ignored-id" };
      const defaults = {
        token: "default-token",
        createdAt: new Date("2032-01-02T03:04:05.000Z"),
        updatedAt: new Date("2032-01-02T03:04:06.000Z"),
      };
      const defaultEvents: Events = Object.entries(defaults).map(([name, value]) => ["default", name, value]);
      const observation = await observe({ mode, caller, overrideAll, fields: events => Object.fromEntries(
        Object.entries(defaults).map(([name, value]): [string, DBFieldAttribute] => [name, {
          type: value instanceof Date ? "date" : "string",
          defaultValue() { events.push(["default", name, structuredClone(value)]); return structuredClone(value); },
        }]),
      ) });
      const observed = observation.before[0];
      assert.ok(observed?.expiresAt instanceof Date);
      if (!overrideAll) {
        expect(observed.expiresAt.getTime()).toBeGreaterThanOrEqual(observation.started + lifetimeSeconds * 1000);
        expect(observed.expiresAt.getTime()).toBeLessThanOrEqual(observation.finished + lifetimeSeconds * 1000);
      }
      const record = initialRecord(mode, overrideAll ? native : { ...native, ...defaults, expiresAt: observed.expiresAt });
      const mirror = { token: overrideAll ? native.token : defaults.token, expiresAt: observed.expiresAt };
      check(observation, { defaults: defaultEvents, before: [record, record], result: { ...record, id: generatedId }, mirror });
    }
  }
});

test("in-place session changes update cache identity while returned patches preserve the original cache identity", async () => {
  for (const mode of modes) {
    for (const patch of [false, true]) {
      const caller = nativeSession();
      const changed = replacement();
      const before = initialRecord(mode, caller);
      const final = { ...before, ...changed };
      const observation = await observe({ mode, caller, overrideAll: true, beforePlugin(data) {
        if (patch) return { data: changed };
        Object.assign(data, changed);
      } });
      if (patch) expect(observation.hookInputs[0]).not.toBe(observation.hookInputs[1]);
      else expect(observation.hookInputs[0]).toBe(observation.hookInputs[1]);
      check(observation, {
        before: [before, final], result: { ...final, id: generatedId }, mirror: patch ? caller : changed,
      });
    }
  }
});

test("a partial returned patch retains in-place changes and does not change the captured owner", async () => {
  const mode = "secondary";
  const caller = nativeSession();
  const changed = replacement();
  const before = initialRecord(mode, caller);
  const final = { ...before, ...changed };
  const observation = await observe({ mode, caller, overrideAll: true, beforePlugin(data) {
    Object.assign(data, { userId: changed.userId, expiresAt: changed.expiresAt, createdAt: changed.createdAt });
    return { data: { token: changed.token, updatedAt: changed.updatedAt } };
  } });
  check(observation, {
    before: [before, final], result: final, mirror: { token: caller.token, expiresAt: changed.expiresAt },
  });
});

test("an empty returned patch detaches later replacements but preserves shared Date objects", async () => {
  for (const mutateDate of [false, true]) {
    const mode = "secondary";
    const caller = nativeSession();
    const changed = replacement();
    const before = structuredClone(initialRecord(mode, caller));
    assert.ok(before.expiresAt instanceof Date);
    const final = { ...before, ...changed };
    const observation = await observe({ mode, caller, overrideAll: true,
      beforePlugin() { return { data: {} }; },
      beforeUser(data) {
        if (mutateDate) {
          assert.ok(data.expiresAt instanceof Date);
          assert.ok(data.createdAt instanceof Date);
          assert.ok(data.updatedAt instanceof Date);
          data.expiresAt.setTime(changed.expiresAt.getTime());
          data.createdAt.setTime(changed.createdAt.getTime());
          data.updatedAt.setTime(changed.updatedAt.getTime());
          Object.assign(data, { token: changed.token, userId: changed.userId });
        } else Object.assign(data, changed);
      },
    });
    expect(observation.hookInputs[0]).not.toBe(observation.hookInputs[1]);
    if (mutateDate) expect(observation.hookInputs[0]?.expiresAt).toBe(observation.hookInputs[1]?.expiresAt);
    else expect(observation.hookInputs[0]?.expiresAt).not.toBe(observation.hookInputs[1]?.expiresAt);
    check(observation, {
      before: [before, before], result: final,
      mirror: { token: "caller-token", expiresAt: mutateDate ? changed.expiresAt : before.expiresAt },
    });
  }
});

test("deferred secondary writes retain the original identity after the session transaction commits", async () => {
  const mode = "mirrored";
  const caller = nativeSession();
  const changed = replacement();
  const before = initialRecord(mode, caller);
  const final = { ...before, ...changed };
  const observation = await observe({ mode, caller, overrideAll: true, deferred: true,
    beforePlugin() { return { data: changed }; },
  });
  check(observation, { before: [before, final], result: { ...final, id: generatedId }, mirror: caller });
});

test("a cancelling or failing creation hook prevents later hooks and storage writes", async () => {
  for (const failure of [false, true]) {
    const mode = "secondary";
    const caller = nativeSession();
    const error = new Error("session payload hook failure");
    const observation = await observe({ mode, caller, overrideAll: true, expectedError: failure ? error : undefined,
      beforePlugin(data) {
        data.token = "never-stored";
        if (failure) throw error;
        return false;
      },
    });
    check(observation, { before: [initialRecord(mode, caller)], result: null });
  }
});

test("a native token alias remains available to another field reading the same stored value", async () => {
  const mode = "database";
  const caller = nativeSession();
  const before = initialRecord(mode, caller);
  const result = { ...before, id: generatedId, echo: caller.token };
  const { token, ...native } = caller;
  const observation = await observe({ mode, caller, overrideAll: true, fields: () => ({
    token: { type: "string", fieldName: "storedToken" },
    echo: { type: "string", required: false, fieldName: "storedToken" },
  }) });
  check(observation, { before: [before, before], result, row: { ...native, storedToken: token, id: generatedId } });
  expect(await observation.readStoredSession(token)).toStrictEqual(result);
});

test("an aliased native default is evaluated again when a hook deletes the token", async () => {
  const mode = "database";
  const caller: RecordValue = { ...nativeSession() };
  delete caller.token;
  const before = { ...caller, token: "D1" };
  const result = { ...caller, token: "D2", id: generatedId };
  let defaults = 0;
  const observation = await observe({ mode, caller, overrideAll: true, fields: events => ({
    token: { type: "string", fieldName: "storedToken", defaultValue() {
      const value = `D${++defaults}`;
      events.push(["default", "token", value]);
      return value;
    } },
  }), beforePlugin(data) { delete data.token; } });
  check(observation, {
    defaults: [["default", "token", "D1"]], adapter: [["default", "token", "D2"]],
    before: [before, caller], result, row: { ...caller, storedToken: "D2", id: generatedId },
  });
  expect(await observation.readStoredSession("D2")).toStrictEqual(result);
  expect(await observation.readStoredSession("D1")).toBeNull();
});

test("a native output transform changes the returned and mirrored token while storage queries use the original token", async () => {
  const mode = "mirrored";
  const caller = nativeSession();
  const before = initialRecord(mode, caller);
  const result = { ...before, token: `out:${caller.token}`, id: generatedId };
  const observation = await observe({ mode, caller, overrideAll: true, fields: () => ({
    token: { type: "string", transform: { output(value) { return `out:${value}`; } } },
  }) });
  check(observation, { before: [before, before], result, row: { ...caller, id: generatedId }, mirror: caller });
  expect(await observation.readStoredSession(caller.token)).toStrictEqual(result);
  expect(await observation.readStoredSession(result.token)).toBeNull();
});

test("a later native input overwrites a preceding token alias targeting the same storage field", async () => {
  const mode = "database";
  const caller = nativeSession();
  const before = initialRecord(mode, caller);
  const result = { ...before, token: caller.userAgent, id: generatedId };
  const row: RecordValue = { ...caller, id: generatedId };
  delete row.token;
  const observation = await observe({ mode, caller, overrideAll: true, fields: () => ({
    token: { type: "string", fieldName: "userAgent" },
  }) });
  check(observation, { before: [before, before], result, row });
  expect(await observation.readStoredSession(caller.userAgent)).toStrictEqual(result);
  expect(await observation.readStoredSession(caller.token)).toBeNull();
});

test("chained native aliases retain each physical value while exposing the logical session fields", async () => {
  const mode = "database";
  const caller = nativeSession();
  const before = initialRecord(mode, caller);
  const result = { ...before, id: generatedId };
  const { token, userAgent, ...native } = caller;
  const observation = await observe({ mode, caller, overrideAll: true, fields: () => ({
    token: { type: "string", fieldName: "userAgent" },
    userAgent: { type: "string", required: false, fieldName: "storedAgent" },
  }) });
  check(observation, {
    before: [before, before], result,
    row: { ...native, userAgent: token, storedAgent: userAgent, id: generatedId },
  });
  expect(await observation.readStoredSession(token)).toStrictEqual(result);
  expect(await observation.readStoredSession(userAgent)).toBeNull();
});

test("native output transforms preserve number and null values in callbacks and the mirrored payload", async () => {
  const mode = "mirrored";
  const caller = nativeSession();
  const before = initialRecord(mode, caller);
  const result = { ...before, token: 7, createdAt: null, id: generatedId };
  const observation = await observe({ mode, caller, overrideAll: true, fields: () => ({
    token: { type: "string", transform: { output() { return 7; } } },
    createdAt: { type: "date", transform: { output() { return null; } } },
  }) });
  check(observation, { before: [before, before], result, row: { ...caller, id: generatedId }, mirror: caller });
  expect(await observation.readStoredSession(caller.token)).toStrictEqual(result);
  expect(await observation.readStoredSession("7")).toBeNull();
  expect(observation.cache.has("7")).toBe(false);
});
