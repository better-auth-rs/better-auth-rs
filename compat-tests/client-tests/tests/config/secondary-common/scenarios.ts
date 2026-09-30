import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
export async function control(ctx: Context, body: object = {}) {
  const response = await fetch(`${ctx.baseURL}/__test/secondary`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200);
  return response.json() as Promise<any>;
}
async function signup(ctx: Context) {
  const email = ctx.uniqueEmail("secondary");
  const result = await ctx.actor().client.signUp.email({ email, password: "Password123!", name: "Cached User" });
  expect(result.error).toBeNull();
  return { email, id: result.data!.user.id, token: result.data!.token! };
}
export function sessionScenarios(mode: "only" | "database" | "preserved") {
  const database = mode !== "only";
  compatScenario("secondary session keeps an authenticated user snapshot and custom fields", async ctx => {
    const user = await signup(ctx);
    const initial = await control(ctx);
    expect(initial.sessions).toBe(database ? 1 : 0);
    const entry = initial.entries.find((entry: any) => entry.key === user.token);
    expect(entry.ttl).toBeGreaterThan(0);
    expect(entry.ttl).toBeLessThanOrEqual(604800);
    expect(JSON.parse(entry.value).user.name).toBe("Cached User");
    expect(JSON.parse(initial.entries.find((entry: any) => entry.key === `active-sessions-${user.id}`).value)[0].token).toBe(user.token);
    await control(ctx, { action: "database-user-name", userId: user.id, name: "Direct Database" });
    const cached = await ctx.actor().client.getSession();
    expect(cached.data!.user.name).toBe("Cached User");
    expect((cached.data!.session as any).deviceLabel).toBe(database ? null : undefined);
    const updated = await ctx.actor().client.updateUser({ name: "Runtime Update" });
    expect(updated.error).toBeNull();
    const refreshed = await ctx.actor().client.getSession();
    expect(refreshed.data!.user.name).toBe("Runtime Update");
    const updateSession = await ctx.rawRequest({ path: "/api/auth/update-session", method: "POST", json: { deviceLabel: "laptop" } });
    expect(updateSession.status).toBe(200);
    const listed = await ctx.rawRequest({ path: "/api/auth/list-sessions" });
    expect((listed.body as any[])[0].deviceLabel).toBe("laptop");
    expect((listed.body as any[])[0]).not.toHaveProperty("internalNote");
    return { cached: ctx.snapshot(cached), refreshed: ctx.snapshot(refreshed), updateSession, listed };
  });
  compatScenario("secondary session cache misses and malformed cache records follow database policy", async ctx => {
    const user = await signup(ctx);
    await control(ctx, { action: "evict", key: user.token });
    const missing = await ctx.actor().client.getSession();
    if (mode === "database") expect(missing.data?.user.id).toBe(user.id);
    else expect(missing.data).toBeNull();
    const next = await ctx.actor().client.signIn.email({ email: user.email, password: "Password123!" });
    expect(next.error).toBeNull();
    await control(ctx, { action: "put", key: next.data!.token, value: "broken json" });
    const invalid = await ctx.actor().client.getSession();
    expect(invalid.data).toBeNull();
    return { missing: ctx.snapshot(missing), invalid: ctx.snapshot(invalid) };
  });
  compatScenario("secondary session revocation removes active references and preserves only expired audit rows", async ctx => {
    const user = await signup(ctx);
    const second = await ctx.actor("second").client.signIn.email({ email: user.email, password: "Password123!" });
    expect(second.error).toBeNull();
    const revoke = await ctx.actor().client.revokeOtherSessions();
    expect(revoke.error).toBeNull();
    const invalid = await ctx.actor("second").client.getSession();
    expect(invalid.data).toBeNull();
    const state = await control(ctx);
    expect(state.sessions).toBe(mode === "preserved" ? 2 : mode === "database" ? 1 : 0);
    expect(state.rows.filter((row: any) => row.live)).toHaveLength(database ? 1 : 0);
    await control(ctx, { action: "clear-events" });
    await control(ctx, { action: "end-session", token: user.token });
    await control(ctx, { action: "end-session", token: user.token });
    const final = await control(ctx);
    expect(final.rows.filter((row: any) => row.live)).toHaveLength(0);
    expect(final.entries.some((entry: any) => entry.key === `active-sessions-${user.id}`)).toBe(false);
    expect(final.events.filter((event: string) => event === "session.delete.before")).toHaveLength(database ? 1 : 0);
    return { revoke: ctx.snapshot(revoke), invalid: ctx.snapshot(invalid), rowCount: final.sessions, events: final.events };
  });
  compatScenario("secondary session writes remain absent after a database transaction rolls back", async ctx => {
    const user = await signup(ctx);
    const initial = await control(ctx);
    const rollback = await control(ctx, { action: "transaction-session", userId: user.id, rollback: true });
    expect(rollback.error).toBe("secondary transaction rollback");
    const after = await control(ctx);
    expect(after.sessions).toBe(initial.sessions);
    expect(after.entries.map((entry: any) => entry.key)).toEqual(initial.entries.map((entry: any) => entry.key));
    const committed = await control(ctx, { action: "transaction-session", userId: user.id });
    expect(committed).toEqual({ committed: true });
    const final = await control(ctx);
    expect(final.sessions).toBe(database ? 2 : 0);
    const references = JSON.parse(final.entries.find((entry: any) => entry.key === `active-sessions-${user.id}`).value);
    expect(references).toHaveLength(2);
    return { rollback, committed, sessions: final.sessions, referenceCount: references.length };
  });
}
export function verificationScenarios(database: boolean) {
  compatScenario("secondary verification update and concurrent consumption use one atomic claim", async ctx => {
    const identifier = ctx.uniqueToken("verification");
    const created = await control(ctx, { action: "create-verification", identifier, value: "first" });
    expect(created.value).toBe("first");
    const initial = await control(ctx);
    expect(initial.verifications).toBe(database ? 1 : 0);
    expect(initial.entries.find((entry: any) => entry.key === `verification:${identifier}`).ttl).toBeGreaterThan(0);
    await control(ctx, { action: "update-verification", identifier, value: "changed" });
    const found = await control(ctx, { action: "find-verification", identifier });
    expect(found.value).toBe("changed");
    const consumed = await Promise.all(Array.from({ length: 12 }, () => control(ctx, { action: "consume-verification", identifier })));
    expect(consumed.filter(Boolean)).toHaveLength(1);
    expect(consumed.find(Boolean).value).toBe("changed");
    expect(await control(ctx, { action: "consume-verification", identifier })).toBeNull();
    const final = await control(ctx);
    expect(final.verifications).toBe(0);
    expect(final.entries.some((entry: any) => entry.key === `verification:${identifier}`)).toBe(false);
    return { consumed: consumed.filter(Boolean).map(row => row.value), count: final.verifications };
  });
  compatScenario("secondary verification malformed-cache fallback and expired-record cleanup follow database policy", async ctx => {
    const identifier = ctx.uniqueToken("cache-miss");
    await control(ctx, { action: "create-verification", identifier, value: "database" });
    await control(ctx, { action: "put", key: `verification:${identifier}`, value: "broken json" });
    const found = await control(ctx, { action: "find-verification", identifier });
    expect(found?.value ?? null).toBe(database ? "database" : null);
    await control(ctx, { action: "delete-verification", identifier });
    expect((await control(ctx)).verifications).toBe(0);
    const expired = ctx.uniqueToken("expired");
    await control(ctx, { action: "create-verification", identifier: expired, value: "old", seconds: -1 });
    await control(ctx, { action: "clear-events" });
    const expiredValue = await control(ctx, { action: "find-verification", identifier: expired });
    expect(expiredValue?.value ?? null).toBe(database ? "old" : null);
    const final = await control(ctx);
    expect(final.verifications).toBe(0);
    expect(final.events).toEqual(database ? ["verification.delete.before", "verification.delete.after"] : []);
    return { value: found?.value ?? null, expiredValue: expiredValue?.value ?? null, events: final.events };
  });
  compatScenario("secondary verification reservation requires database uniqueness", async ctx => {
    const identifier = ctx.uniqueToken("reserve");
    const first = await control(ctx, { action: "reserve-verification", identifier, value: "reserved" });
    if (database) {
      expect(first).toEqual({ reserved: true });
      expect(await control(ctx, { action: "reserve-verification", identifier, value: "reserved" })).toEqual({ reserved: false });
    } else expect(first.error).toContain("requires database-backed verification storage");
    return first;
  });
  compatScenario("secondary verification backend failures preserve the storage operation boundary", async ctx => {
    const identifier = `hash:${ctx.uniqueToken("backend-failure")}`;
    await control(ctx, { action: "create-verification", identifier, value: "single-use" });
    await control(ctx, { action: "failure", operation: database ? "delete" : "getAndDelete" });
    const failed = await fetch(`${ctx.baseURL}/__test/secondary`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "consume-verification", identifier }) });
    expect(failed.status).toBe(500);
    await control(ctx, { action: "failure", operation: null });
    const retry = await control(ctx, { action: "consume-verification", identifier });
    expect(retry?.value ?? null).toBe(database ? null : "single-use");
    return { failure: failed.status, retry: retry?.value ?? null };
  });
  compatScenario("secondary password reset consumes its verification once before changing credentials", async ctx => {
    const user = await signup(ctx);
    const requested = await ctx.actor().client.requestPasswordReset({ email: user.email, redirectTo: `${ctx.baseURL}/reset` });
    expect(requested.error).toBeNull();
    const sent = await fetch(`${ctx.baseURL}/__test/reset-password-token?email=${encodeURIComponent(user.email)}`).then(response => response.json());
    const statuses = await Promise.all(Array.from({ length: 8 }, async () => {
      const response = await fetch(`${ctx.baseURL}/api/auth/reset-password`, { method: "POST", headers: { "content-type": "application/json", origin: ctx.baseURL }, body: JSON.stringify({ token: sent.token, newPassword: "NewPassword123!" }) });
      const body = await response.json();
      expect(response.status === 200 ? body.status : body.code).toBe(response.status === 200 ? true : "INVALID_TOKEN");
      return response.status;
    }));
    expect(statuses.filter(status => status === 200)).toHaveLength(1);
    expect(statuses.filter(status => status === 400)).toHaveLength(7);
    const signedIn = await ctx.actor("new-password").client.signIn.email({ email: user.email, password: "NewPassword123!" });
    expect(signedIn.error).toBeNull();
    return { statuses: statuses.sort(), signedIn: ctx.snapshot(signedIn) };
  });
}
