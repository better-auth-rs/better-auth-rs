import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
type Snapshot = { entries: { key: string; value: string; ttl: number | null }[]; rows: any[] };

async function owner(ctx: Context) {
  const result = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("storage"), password: "password123", name: "Storage Owner" });
  expect(result.error).toBeNull();
  return result.data!.user.id;
}
async function control(ctx: Context, body: object): Promise<Snapshot> {
  const response = await fetch(`${ctx.baseURL}/__test/api-key-storage`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200);
  return response.json();
}
async function create(ctx: Context, userId: string, configId: string, extra: object = {}) {
  const response = await ctx.rawRequest({ path: "/__test/api-key/create", method: "POST", json: { userId, configId, ...extra } });
  expect(response.status).toBe(200);
  return response.body as any;
}
async function verify(ctx: Context, key: any, configId = key.configId) {
  const response = await ctx.rawRequest({ path: "/__test/api-key/verify", method: "POST", json: { key: key.key, configId } });
  expect(response.status).toBe(200);
  return response.body as any;
}
function stored(snapshot: Snapshot, id: string) {
  const entry = snapshot.entries.find((entry) => entry.key === `api-key:by-id:${id}`);
  return entry ? JSON.parse(entry.value) : null;
}
async function list(ctx: Context, configId?: string) {
  const response = await ctx.rawRequest({ path: `/api/auth/api-key/list?sortBy=name${configId ? `&configId=${configId}` : ""}` });
  expect(response.status).toBe(200);
  return response.body as any;
}

compatScenario("secondary storage persists both key indexes and the reference list without database rows", async (ctx) => {
  const userId = await owner(ctx);
  const key = await create(ctx, userId, "cache", { name: "Alpha", metadata: { source: "cache" } });
  const second = await create(ctx, userId, "cache", { name: "Beta" });
  const snapshot = await control(ctx, { referenceId: userId });
  expect(snapshot.rows).toHaveLength(0);
  expect(snapshot.entries).toHaveLength(5);
  expect(snapshot.entries.every((entry) => entry.ttl === null)).toBe(true);
  const row = stored(snapshot, key.id);
  expect(row.metadata).toEqual({ source: "cache" });
  expect(snapshot.entries.some((entry) => entry.key === `api-key:${row.key}`)).toBe(true);
  expect(JSON.parse(snapshot.entries.find((entry) => entry.key === `api-key:by-ref:${userId}`)!.value)).toEqual([key.id, second.id]);
  expect((await list(ctx, "cache")).apiKeys.map((key: any) => key.name)).toEqual(["Alpha", "Beta"]);
  const mismatch = await verify(ctx, key, "default");
  expect(mismatch.valid).toBe(false);
  const updated = await ctx.rawRequest({ path: "/__test/api-key/update", method: "POST", json: { userId, keyId: key.id, configId: "cache", name: "Changed", metadata: { changed: true } } });
  expect(updated.status).toBe(200);
  expect((await verify(ctx, key)).key.name).toBe("Changed");
  const deleted = await ctx.rawRequest({ path: "/api/auth/api-key/delete", method: "POST", json: { keyId: key.id, configId: "cache" } });
  expect(deleted.status).toBe(200);
  const after = await control(ctx, { referenceId: userId });
  expect(stored(after, key.id)).toBeNull();
  expect(after.entries.some((entry) => entry.key === `api-key:${row.key}`)).toBe(false);
  expect(JSON.parse(after.entries.find((entry) => entry.key === `api-key:by-ref:${userId}`)!.value)).toEqual([second.id]);
  return { mismatch, deleted, remaining: (await list(ctx, "cache")).apiKeys.map((key: any) => key.name) };
});

compatScenario("fallback rehydrates cache misses and database quota overrides stale cached counters", async (ctx) => {
  const userId = await owner(ctx);
  const key = await create(ctx, userId, "fallback", { name: "Durable", remaining: 2, metadata: { source: "database" } });
  let snapshot = await control(ctx, { referenceId: userId });
  expect(snapshot.rows).toHaveLength(1);
  expect(snapshot.entries).toHaveLength(2);
  await control(ctx, { action: "evict" });
  const read = await ctx.rawRequest({ path: `/api/auth/api-key/get?id=${key.id}&configId=fallback` });
  expect(read.status).toBe(200);
  snapshot = await control(ctx, { referenceId: userId });
  expect(snapshot.entries).toHaveLength(2);
  const cached = stored(snapshot, key.id);
  cached.remaining = 100;
  await control(ctx, { action: "put", key: `api-key:${cached.key}`, value: JSON.stringify(cached) });
  const first = await verify(ctx, key);
  expect(first.valid).toBe(true);
  expect(first.key.remaining).toBe(1);
  snapshot = await control(ctx, { referenceId: userId });
  expect(snapshot.rows[0].remaining).toBe(1);
  expect(stored(snapshot, key.id).remaining).toBe(1);
  await control(ctx, { action: "put", key: `api-key:${cached.key}`, value: "not-json" });
  expect((await verify(ctx, key)).key.remaining).toBe(0);
  const exhausted = await verify(ctx, key);
  expect(exhausted.error.code).toBe("USAGE_EXCEEDED");
  snapshot = await control(ctx, { referenceId: userId });
  expect(snapshot.rows).toHaveLength(0);
  expect(snapshot.entries).toHaveLength(0);
  expect((read.body as any).start).toBe(key.key.slice(0, 6));
  expect(first.key.start).toBe(key.key.slice(0, 6));
  return { read: { status: read.status, metadata: (read.body as any).metadata }, remaining: first.key.remaining, exhausted };
});

compatScenario("custom storage overrides global storage and listing joins configured backends", async (ctx) => {
  const userId = await owner(ctx);
  const cached = await create(ctx, userId, "cache", { name: "Cache" });
  const custom = await create(ctx, userId, "custom", { name: "Custom" });
  const database = await create(ctx, userId, "database-custom", { name: "Database" });
  const fallback = await create(ctx, userId, "custom-fallback", { name: "Fallback" });
  const global = await control(ctx, { referenceId: userId });
  const isolated = await control(ctx, { backend: "custom", referenceId: userId });
  expect(stored(global, cached.id)).not.toBeNull();
  expect(stored(global, custom.id)).toBeNull();
  expect(stored(isolated, custom.id)).not.toBeNull();
  expect(stored(isolated, database.id)).toBeNull();
  expect(stored(isolated, fallback.id)).not.toBeNull();
  expect(global.rows.map((row) => row.name).sort()).toEqual(["Database", "Fallback"]);
  // fallback invalidates the shared custom reference index; its next list rebuilds from the database.
  const customList = await list(ctx, "custom");
  expect(customList.total).toBe(0);
  const all = await list(ctx);
  expect(new Set(all.apiKeys.map((key: any) => key.name))).toEqual(new Set(["Cache", "Database", "Fallback"]));
  const unknown = await create(ctx, userId, "unknown", { name: "Default" });
  expect(unknown.configId).toBe("default");
  expect((await verify(ctx, unknown, "unknown")).valid).toBe(false);
  const unknownList = await list(ctx, "unknown");
  expect(unknownList.total).toBe(0);
  return { customList, names: all.apiKeys.map((key: any) => key.name), unknownList };
});

compatScenario("secondary quota rejects rate limits before writing while fallback consumes database quota", async (ctx) => {
  const userId = await owner(ctx);
  const outcomes = [];
  for (const configId of ["cache", "fallback"]) {
    const key = await create(ctx, userId, configId, { name: configId, remaining: 3, rateLimitMax: 1, rateLimitTimeWindow: 60000 });
    expect((await verify(ctx, key)).key.remaining).toBe(2);
    const rejected = await verify(ctx, key);
    expect(rejected.error.code).toBe("RATE_LIMITED");
    const snapshot = await control(ctx, { referenceId: userId });
    const remaining = configId === "cache" ? stored(snapshot, key.id).remaining : snapshot.rows.find((row) => row.id === key.id).remaining;
    expect(remaining).toBe(configId === "cache" ? 2 : 1);
    outcomes.push({ configId, remaining, code: rejected.error.code });
  }
  return outcomes;
});

compatScenario("deferred secondary usage returns before cache writes and TTL expiration leaves no live key", async (ctx) => {
  const userId = await owner(ctx);
  const key = await create(ctx, userId, "deferred", { name: "Deferred", remaining: 2 });
  await control(ctx, { action: "block", blocked: true });
  const verified = await verify(ctx, key);
  expect(verified.key.remaining).toBe(1);
  expect(stored(await control(ctx, {}), key.id).remaining).toBe(2);
  await control(ctx, { action: "block", blocked: false });
  for (let attempt = 0; attempt < 100; attempt++) {
    if (stored(await control(ctx, {}), key.id).remaining === 1) break;
    await Bun.sleep(10);
  }
  expect(stored(await control(ctx, {}), key.id).remaining).toBe(1);
  const temporary = await create(ctx, userId, "cache", { name: "Temporary", expiresIn: 2 });
  const expiring = (await control(ctx, {})).entries.find((entry) => entry.key === `api-key:by-id:${temporary.id}`)!;
  expect(expiring.ttl).toBeGreaterThan(0);
  expect(expiring.ttl).toBeLessThanOrEqual(2);
  await Bun.sleep(2100);
  const expired = await verify(ctx, temporary);
  expect(expired.error.code).toBe("INVALID_API_KEY");
  const live = await list(ctx, "cache");
  expect(live.total).toBe(0);
  expect(verified.key.start).toBe(key.key.slice(0, 6));
  return { verified: { valid: verified.valid, remaining: verified.key.remaining }, expired, live };
});

compatScenario("fallback storage failures propagate without becoming misses or undoing database consumption", async (ctx) => {
  const userId = await owner(ctx);
  const key = await create(ctx, userId, "fallback", { remaining: 2 });
  await control(ctx, { action: "failure", operation: "get" });
  const readFailure = await verify(ctx, key);
  expect(readFailure.valid).toBe(false);
  expect(readFailure.error.code).toBe("INVALID_API_KEY");
  expect((await control(ctx, { referenceId: userId })).rows[0].remaining).toBe(2);
  await control(ctx, { action: "failure", operation: "set" });
  const writeFailure = await verify(ctx, key);
  expect(writeFailure.valid).toBe(false);
  expect(writeFailure.error.code).toBe("INVALID_API_KEY");
  const snapshot = await control(ctx, { referenceId: userId });
  expect(snapshot.rows[0].remaining).toBe(1);
  expect(stored(snapshot, key.id).remaining).toBe(2);
  await control(ctx, { action: "failure", operation: null });
  expect((await verify(ctx, key)).key.remaining).toBe(0);
  return { readFailure, writeFailure };
});

compatScenario("secondary reference mutations retain concurrent creations and expired refill windows replenish quota", async (ctx) => {
  const userId = await owner(ctx);
  const keys = await Promise.all(Array.from({ length: 12 }, async (_, index) => {
    const response = await fetch(`${ctx.baseURL}/__test/api-key/create`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ userId, configId: "cache", name: `Key ${index}` }) });
    expect(response.status).toBe(200);
    return response.json();
  }));
  const snapshot = await control(ctx, { referenceId: userId });
  const ids = JSON.parse(snapshot.entries.find((entry) => entry.key === `api-key:by-ref:${userId}`)!.value);
  expect(new Set(ids)).toEqual(new Set(keys.map((key) => key.id)));
  const listed = await list(ctx, "cache");
  expect(listed.total).toBe(12);
  const refill = await create(ctx, userId, "cache", { remaining: 0, refillAmount: 3, refillInterval: 1000 });
  const cached = stored(await control(ctx, {}), refill.id);
  cached.lastRefillAt = "2020-01-02T03:04:05.000Z";
  await control(ctx, { action: "put", key: `api-key:${cached.key}`, value: JSON.stringify(cached) });
  const valid = await verify(ctx, refill);
  expect(valid.valid).toBe(true);
  expect(valid.key.remaining).toBe(2);
  expect(valid.key.lastRefillAt).not.toBe(cached.lastRefillAt);
  return { names: listed.apiKeys.map((key: any) => key.name), remaining: valid.key.remaining };
});

compatScenario("fallback update preserves its cached snapshot when the database row has disappeared", async ctx => {
  const userId = await owner(ctx);
  const key = await create(ctx, userId, "fallback", { name: "Cached Before Delete" });
  await control(ctx, { action: "delete-database", id: key.id, referenceId: userId });
  const updated = await ctx.rawRequest({ path: "/__test/api-key/update", method: "POST", json: { userId, keyId: key.id, configId: "fallback", name: "Unpersisted Change" } });
  expect(updated.status).toBe(200);
  expect((updated.body as any).name).toBe("Cached Before Delete");
  const snapshot = await control(ctx, { referenceId: userId });
  expect(snapshot.rows).toHaveLength(0);
  expect(stored(snapshot, key.id).name).toBe("Cached Before Delete");
  expect((updated.body as any).start).toBe(key.key.slice(0, 6));
  return { ...updated, body: { ...(updated.body as any), start: "<key-start>" } };
});
