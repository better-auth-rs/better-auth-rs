import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

export function cookieVersionScenarios() {
  compatScenario("dynamic versions see internal writes, filtered caches, and invalidate without restoring revoked sessions", async ctx => {
    const control = async (body?: unknown) => {
      const response = await fetch(`${ctx.baseURL}/__test/cookie-version`, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : undefined);
      expect(response.status).toBe(200);
      return await response.json();
    };
    const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("cache-version"), password: "Password123!", name: "Cache Version" });
    expect(signup.error).toBeNull();
    const created = await control();
    expect(created.events).toHaveLength(1);
    expect(created.events[0]).toMatchObject({ hiddenSession: "session-secret", hiddenUser: "user-secret" });
    const cached = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(cached.status).toBe(200);
    expect((cached.body as any).user.id).toBe(signup.data!.user.id);
    expect((cached.body as any).session).not.toHaveProperty("internalNote");
    expect((cached.body as any).user).not.toHaveProperty("secretNote");
    const read = await control();
    expect(read.events).toHaveLength(2);
    expect(read.events[1]).toMatchObject({ hiddenSession: null, hiddenUser: null });
    await control({ version: "2", clear: true });
    const replaced = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(replaced.status).toBe(200);
    const mismatch = await control();
    expect(mismatch.events).toHaveLength(2);
    expect(mismatch.events[1]).toMatchObject({ hiddenSession: null, hiddenUser: null });
    await control({ version: "", clear: true });
    const emptyVersion = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(emptyVersion.status).toBe(200);
    await control({ clear: true });
    const emptyRead = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(emptyRead.status).toBe(200);
    const emptyEvents = await control();
    expect(emptyEvents.events).toHaveLength(2);
    await control({ version: "2" });
    const restoredVersion = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(restoredVersion.status).toBe(200);
    const revoke = await ctx.rawRequest({ path: "/__test/jwt/action", method: "POST", json: { action: "revoke", token: signup.data!.token } });
    expect(revoke.status).toBe(200);
    const stillCached = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect((stillCached.body as any).user.id).toBe(signup.data!.user.id);
    await control({ version: "3" });
    const revoked = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(revoked.body).toBeNull();
    return { created, cached, read, replaced, mismatch, emptyVersion, emptyRead, emptyEvents, restoredVersion, revoke, stillCached, revoked };
  });

  compatScenario("a version callback failure fails the read without falling back to storage", async ctx => {
    const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("cache-error"), password: "Password123!", name: "Cache Error" });
    expect(signup.error).toBeNull();
    const mode = await fetch(`${ctx.baseURL}/__test/cookie-version`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ fail: true, clear: true }) });
    expect(mode.status).toBe(200);
    const failed = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(failed.status).toBe(500);
    expect(failed.body).toEqual({ code: "FAILED_TO_GET_SESSION", message: "Failed to get session" });
    const state = await (await fetch(`${ctx.baseURL}/__test/cookie-version`)).json();
    expect(state.events).toHaveLength(1);
    return { failed, state };
  });
}
