import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

assert.equal(JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version, "1.7.6");

type Mode = "database" | "secondary";
type RecordValue = Record<string, unknown>;
type Events = unknown[][];
const modes: Mode[] = ["database", "secondary"];
const date = new Date("2030-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const token = "session-defaults-token";
const owner = {
  id: "owner", name: "Owner", email: "owner@session-defaults.test", emailVerified: true,
  image: null, createdAt: date, updatedAt: date,
};
const nativeSession = {
  token, userId: owner.id, ipAddress: "", userAgent: "",
  expiresAt, createdAt: date, updatedAt: date,
};
const generatedId = "generated-session-1";

function generation(mode: Mode) {
  return ["generate", mode === "secondary" ? { model: "session", size: undefined } : { model: "session" }, generatedId];
}

async function observe(options: {
  mode: Mode;
  fields: (events: Events) => Record<string, DBFieldAttribute>;
  patch?: RecordValue;
  caller?: RecordValue;
  cancel?: boolean;
}) {
  const events: Events = [];
  const memory: Record<string, RecordValue[]> = { user: [], account: [], session: [], verification: [] };
  const cache = new Map<string, { value: string; ttl: number | undefined }>();
  let generated = 0;
  const context = await betterAuth({
    database: memoryAdapter(memory),
    baseURL: "http://session-defaults.test",
    secret: "session-defaults-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId(input) {
      const id = `generated-${input.model}-${++generated}`;
      events.push(["generate", { ...input }, id]);
      return id;
    } } },
    session: { storeSessionInDatabase: options.mode === "database", additionalFields: options.fields(events) },
    ...(options.mode === "secondary" ? { secondaryStorage: {
      async get(key: string) {
        const value = cache.get(key)?.value ?? null;
        events.push(["get", key, value]);
        return value;
      },
      async set(key: string, value: string, ttl?: number) {
        cache.set(key, { value, ttl });
        events.push(["set", key, JSON.parse(value), ttl]);
      },
      async delete(key: string) {
        events.push(["delete", key]);
        cache.delete(key);
      },
    } } : {}),
    databaseHooks: { session: { create: {
      before(data) {
        // Rust CreateSession lacks native token and creation timestamps; paired Rust hook assertions cover only fields exposed by that API.
        events.push(["before", structuredClone(data)]);
        return options.cancel ? false : { data: options.patch ?? {} };
      },
      after(data) { events.push(["after", structuredClone(data)]); },
    } } },
  }).$context;
  expect(await context.adapter.create({ model: "user", forceAllowId: true, data: owner })).toStrictEqual(owner);
  expect(events).toStrictEqual([]);
  const started = Date.now();
  const result = await context.internalAdapter.createSession(owner.id, false, {
    ...nativeSession, ...options.caller,
  }, true);
  const finished = Date.now();
  return { mode: options.mode, events, memory, cache, result, started, finished };
}

function check(observation: Awaited<ReturnType<typeof observe>>, expected: {
  events: Events;
  result: RecordValue | null;
  row?: RecordValue;
}) {
  expect(observation.result).toStrictEqual(expected.result);
  expect(observation.memory).toStrictEqual({
    user: [owner], account: [], session: expected.row ? [expected.row] : [], verification: [],
  });
  const events = [...expected.events];
  let cache: [string, { value: unknown; ttl: number }][] = [];
  if (observation.mode === "secondary" && expected.result !== null) {
    const ttl = observation.cache.get(token)?.ttl;
    assert.ok(typeof ttl === "number");
    assert.ok(Number.isInteger(ttl));
    expect(ttl).toBeGreaterThanOrEqual(Math.floor((expiresAt.getTime() - observation.finished) / 1000));
    expect(ttl).toBeLessThanOrEqual(Math.floor((expiresAt.getTime() - observation.started) / 1000));
    const references = [{ token, expiresAt: expiresAt.getTime() }];
    const value = JSON.parse(JSON.stringify({ session: expected.result, user: owner }));
    cache = [
      [`active-sessions-${owner.id}`, { value: references, ttl }],
      [token, { value, ttl }],
    ];
    events.push(["get", `active-sessions-${owner.id}`, null]);
    for (const [key, entry] of cache) events.push(["set", key, entry.value, entry.ttl]);
  }
  expect([...observation.cache].map(([key, entry]) => [key, { value: JSON.parse(entry.value), ttl: entry.ttl }])).toStrictEqual(cache);
  if (expected.result !== null) events.push(["after", expected.result]);
  expect(observation.events).toStrictEqual(events);
}

test("configured session ID defaults survive caller stripping and precede creation hooks", async () => {
  for (const mode of modes) {
    for (const cancel of [false, true]) {
      const observation = await observe({ mode, cancel, caller: { id: "caller-id" }, fields: events => ({
        id: { type: "string", defaultValue() {
          events.push(["default", "id", "configured-id"]);
          return "configured-id";
        } },
      }) });
      const result = { ...nativeSession, id: "configured-id" };
      check(observation, {
        events: [...(mode === "secondary" ? [generation(mode)] : []), ["default", "id", "configured-id"], ["before", result]],
        result: cancel ? null : result,
        row: !cancel && mode === "database" ? result : undefined,
      });
    }
  }
});

test("session hook patches distinguish internal defaults from adapter defaults", async () => {
  for (const mode of modes) {
    for (const required of [false, true]) {
      for (const patch of [undefined, null, "P"]) {
        let defaults = 0;
        const observation = await observe({ mode, patch: { label: patch }, fields: events => ({
          label: { type: "string", required, defaultValue() {
            const value = `D${++defaults}`;
            events.push(["default", "label", defaults, value]);
            return value;
          } },
        }) });
        const before = { ...nativeSession, ...(mode === "secondary" ? { id: generatedId } : {}), label: "D1" };
        const repeated = mode === "database" && (patch === undefined || required && patch === null);
        const result = { ...nativeSession, id: generatedId, label: repeated ? "D2" : patch };
        check(observation, {
          events: [
            ...(mode === "secondary" ? [generation(mode)] : []),
            ["default", "label", 1, "D1"], ["before", before],
            ...(repeated ? [["default", "label", 2, "D2"]] : []),
            ...(mode === "database" ? [generation(mode)] : []),
          ],
          result, row: mode === "database" ? result : undefined,
        });
      }
    }
  }
});

test("caller session values override initial defaults without skipping default factories", async () => {
  for (const mode of modes) {
    const observation = await observe({ mode, caller: { label: "caller" }, fields: events => ({
      label: { type: "string", defaultValue() {
        events.push(["default", "label", 1, "D1"]);
        return "D1";
      } },
    }) });
    const before = { ...nativeSession, ...(mode === "secondary" ? { id: generatedId } : {}), label: "caller" };
    const result = { ...nativeSession, id: generatedId, label: "caller" };
    check(observation, {
      events: [
        ...(mode === "secondary" ? [generation(mode)] : []),
        ["default", "label", 1, "D1"], ["before", before],
        ...(mode === "database" ? [generation(mode)] : []),
      ],
      result, row: mode === "database" ? result : undefined,
    });
  }
});

test("literal and factory undefined session defaults retain distinct own-key and cache behavior", async () => {
  for (const mode of modes) {
    for (const field of ["label", "id"]) {
      for (const factory of [false, true]) {
        let defaults = 0;
        const observation = await observe({ mode, fields: events => ({
          [field]: { type: "string", required: false, defaultValue: factory ? () => {
            events.push(["default", field, ++defaults, undefined]);
            return undefined;
          } : undefined },
        }) });
        const before = {
          ...nativeSession, ...(mode === "secondary" ? { id: generatedId } : {}),
          ...(factory ? { [field]: undefined } : {}),
        };
        const row = { ...nativeSession, id: generatedId };
        const result = {
          ...row,
          ...(field === "label" && (factory || mode === "database") ? { label: undefined } : {}),
          ...(field === "id" && factory && mode === "secondary" ? { id: undefined } : {}),
        };
        check(observation, {
          events: [
            ...(mode === "secondary" ? [generation(mode)] : []),
            ...(factory ? [["default", field, 1, undefined]] : []), ["before", before],
            ...(field === "label" && factory && mode === "database" ? [["default", field, 2, undefined]] : []),
            ...(mode === "database" ? [generation(mode)] : []),
          ],
          result, row: mode === "database" ? row : undefined,
        });
      }
    }
  }
});
