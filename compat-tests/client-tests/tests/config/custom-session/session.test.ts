import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

const profile = process.env.COMPAT_PROFILE;

compatScenario("custom sessions transform public data, retain cache cookies, and leave internal authentication unchanged", async ctx => {
  const control = async (body?: unknown) => {
    const response = await fetch(`${ctx.baseURL}/__test/custom-session`, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : undefined);
    expect(response.status).toBe(200);
    return response.json();
  };
  const empty = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(empty.body).toBeNull();
  expect((await control()).events).toEqual([]);
  const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("custom"), password: "Password123!", name: "Custom User" });
  expect(signup.error).toBeNull();
  const response = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=true`, { headers: { "x-app-tag": "application" } });
  expect(response.status).toBe(200);
  const session = await response.json();
  expect(session.user.id).toBe(signup.data!.user.id);
  expect(session.marker).toBe("custom-session");
  expect(session.session.token).toBe(signup.data!.token);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("pragma")).toBe("no-cache");
  expect(response.headers.get("x-customized")).toBe("true");
  const setsCache = response.headers.getSetCookie().some(cookie => cookie.startsWith("better-auth.session_data="));
  expect(setsCache).toBe(true);
  const events = await control();
  expect(events.events).toEqual([{ path: "/get-session", name: "Custom User", exists: true, tag: "application", needsRefresh: profile === "custom-session-deferred" ? false : null }]);
  const hidden = await ctx.rawRequest({ path: "/api/auth/get-session", headers: { "x-custom-mode": "null" } });
  expect(hidden.body).toBeNull();
  const accounts = await ctx.rawRequest({ path: "/api/auth/list-accounts" });
  expect(accounts.status).toBe(200);
  expect((accounts.body as any[]).map(account => account.providerId)).toEqual(["credential"]);
  const post = await ctx.rawRequest({ path: "/api/auth/get-session", method: "POST", json: {} });
  expect(post.status).toBe(404);
  return { empty, session, events, hidden, accounts, post, setsCache };
});

compatScenario("custom sessions suppress nested read errors and propagate callback rejection", async ctx => {
  const control = async (body: unknown) => {
    const response = await fetch(`${ctx.baseURL}/__test/custom-session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    expect(response.status).toBe(200);
    return response.json();
  };
  const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("custom-errors"), password: "Password123!", name: "Errors" });
  expect(signup.error).toBeNull();
  await control({ failRead: true, clear: true });
  const failedRead = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(failedRead.status).toBe(200);
  expect(failedRead.body).toBeNull();
  expect((await control({ failRead: false })).events).toEqual([]);
  const rejected = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true", headers: { "x-custom-mode": "reject" } });
  expect(rejected.status).toBe(403);
  expect(rejected.body).toEqual({ code: "CUSTOM_SESSION_REJECTED", message: "Custom session rejected" });
  const recovered = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(recovered.status).toBe(200);
  expect((recovered.body as any).user.id).toBe(signup.data!.user.id);
  return { failedRead, rejected, recovered };
});

compatScenario("custom device-session callbacks run concurrently only when enabled", async ctx => {
  for (const name of ["First", "Second"]) {
    const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail(name), password: "Password123!", name });
    expect(signup.error).toBeNull();
  }
  const list = await ctx.rawRequest({ path: "/api/auth/multi-session/list-device-sessions", headers: { "x-custom-mode": "barrier", "x-app-tag": "multi" } });
  expect(list.status).toBe(200);
  const body = list.body as any[];
  expect(body).toHaveLength(2);
  const enabled = profile === "custom-session-list";
  expect(body.every(value => value.marker === "custom-session")).toBe(enabled);
  const headerResponse = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/multi-session/list-device-sessions`);
  expect(headerResponse.headers.get("x-customized")).toBe(enabled ? "true" : null);
  await headerResponse.arrayBuffer();
  const events = await (await fetch(`${ctx.baseURL}/__test/custom-session`)).json();
  expect(events.events).toHaveLength(enabled ? 4 : 0);
  const ordered = body.toSorted((left, right) => left.user.name.localeCompare(right.user.name));
  events.events.sort((left: any, right: any) => left.name.localeCompare(right.name));
  const rejected = await ctx.rawRequest({ path: "/api/auth/multi-session/list-device-sessions", headers: { "x-custom-mode": "reject" } });
  expect(rejected.status).toBe(enabled ? 403 : 200);
  if (enabled) expect(rejected.body).toEqual({ code: "CUSTOM_SESSION_REJECTED", message: "Custom session rejected" });
  if (enabled) {
    const partial = await ctx.rawRequest({ path: "/api/auth/multi-session/list-device-sessions", headers: { "x-custom-mode": "partial-reject" } });
    expect(partial.status).toBe(403);
    let completed = false;
    for (let attempt = 0; attempt < 20 && !completed; attempt++) {
      const state = await (await fetch(`${ctx.baseURL}/__test/custom-session`)).json();
      completed = state.events.some((event: any) => event.completed === "Second");
      if (!completed) await new Promise(resolve => setTimeout(resolve, 25));
    }
    expect(completed).toBe(true);
  }
  return { list: ordered, events, rejectionStatus: rejected.status };
});
