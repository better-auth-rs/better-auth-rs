import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

const profile = process.env.COMPAT_PROFILE!;
const persists = profile !== "last-login-cookie";
const cookieName = persists ? "better-auth.last_used_login_method" : "__Host-login_hint";
const cookieAttributes = (cookie: string | undefined) => cookie?.split("; ").sort();
const stored = (method: string) => profile === "last-login-fields" ? `${method}:in:out` : method;

compatScenario("last login persists through ordered hooks and uses one public field projection", async ctx => {
  const control = async (body?: any) => (await fetch(`${ctx.baseURL}/__test/last-login`, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : undefined)).json();
  const email = ctx.uniqueEmail("last-login");
  if (persists) {
    const forbidden = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", json: { email, password: "Password123!", name: "Last", lastLoginMethod: "forged" } });
    expect(forbidden.status).toBe(400);
    expect(forbidden.body).toEqual({ code: "FIELD_NOT_ALLOWED", message: "lastLoginMethod is not allowed to be set" });
    expect((await control()).users).toEqual([]);
  }
  await control({});
  const signup = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/sign-up/email`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: "Password123!", name: "Last" }) });
  expect(signup.status).toBe(200);
  const body = await signup.json();
  expect(body.user.lastLoginMethod).toBe(persists ? stored("email") : undefined);
  const cookie = signup.headers.getSetCookie().find(cookie => cookie.startsWith(`${cookieName}=`));
  expect(cookie).toContain("=email;");
  expect(cookie).toContain(`Max-Age=${persists ? 2592000 : 90}`);
  expect(cookie).not.toContain("HttpOnly");
  if (!persists) expect(cookie).toContain("Secure");
  const created = await control();
  expect(created.users).toEqual([{ email, method: persists ? stored("email") : null }]);
  expect(created.events.map((event: any) => event.kind)).toEqual(persists
    ? ["resolve", "user.before", "session.before", "user.after", "resolve", "user.update", "user.updated", "session.after", "resolve", "cookie"]
    : ["user.before", "session.before", "user.after", "session.after", "resolve", "cookie"]);
  await control({ resolve: "custom" });
  const signin = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/sign-in/email`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: "Password123!" }) });
  expect(signin.status).toBe(200);
  await signin.arrayBuffer();
  const customCookie = signin.headers.getSetCookie().find(cookie => cookie.startsWith(`${cookieName}=`));
  expect(customCookie).toContain("=custom%20method;");
  const updated = await control();
  expect(updated.users[0].method).toBe(persists ? stored("custom method") : null);
  const uncached = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
  const cached = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect((uncached.body as any).user.lastLoginMethod).toBe(persists ? stored("custom method") : undefined);
  expect((cached.body as any).user.lastLoginMethod).toBe((uncached.body as any).user.lastLoginMethod);
  if (profile === "last-login-secondary") expect(updated.cache.every((entry: any) => entry.method === "custom method")).toBe(true);
  return { body, cookie: cookieAttributes(cookie), created, customCookie: cookieAttributes(customCookie), updated, uncached, cached };
});

compatScenario("last login cookie veto, resolver suppression and update errors retain authentication", async ctx => {
  const control = async (body: any) => (await fetch(`${ctx.baseURL}/__test/last-login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
  const outcomes = [];
  for (const [index, options] of [{ veto: "deny" }, { veto: "error" }, { resolve: "empty" }, { fail: "update", resolve: "custom" }].entries()) {
    await control(options);
    const response = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/sign-up/email`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: ctx.uniqueEmail(`veto-${index}`), name: "Veto", password: "Password123!" }) });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(typeof body.token).toBe("string");
    const hasMethodCookie = response.headers.getSetCookie().some(cookie => cookie.startsWith(`${cookieName}=`));
    expect(hasMethodCookie).toBe(Boolean(options.fail));
    const state = await (await fetch(`${ctx.baseURL}/__test/last-login`)).json();
    if (options.fail && persists) {
      expect(state.events.some((event: any) => event.kind === "user.update")).toBe(true);
      expect(state.events.some((event: any) => event.kind === "user.updated")).toBe(false);
      expect(state.events.some((event: any) => event.kind === "session.after")).toBe(true);
    }
    outcomes.push({ options, body, hasMethodCookie, events: state.events });
  }
  return outcomes;
});

compatScenario("last login resolver and session failures expose the real commit boundary", async ctx => {
  const outcomes = [];
  for (const options of [{ resolve: "error" }, { fail: "session" }, ...(persists ? [{ resolve: "session-error" }] : [])]) {
    await fetch(`${ctx.baseURL}/__test/reset-state`, { method: "POST" });
    await fetch(`${ctx.baseURL}/__test/last-login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(options) });
    const response = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", json: { email: ctx.uniqueEmail("failure"), password: "Password123!", name: "Failure" } });
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ code: "LOGIN_FIXTURE_REJECTED", message: "Login fixture rejected" });
    const state = await (await fetch(`${ctx.baseURL}/__test/last-login`)).json();
    expect(state.events.some((event: any) => event.kind === "cookie")).toBe(options.resolve === "session-error");
    outcomes.push({ options, response, state });
  }
  return outcomes;
});

compatScenario("native last login keeps hook context without inventing an HTTP Request", async ctx => {
  const response = await fetch(`${ctx.baseURL}/__test/last-login/native`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: ctx.uniqueEmail("native"), name: "Native", password: "Password123!" }) });
  expect(response.status).toBe(200);
  const result = await response.json();
  expect(result.body.user.lastLoginMethod).toBe(persists ? stored("email") : undefined);
  expect(result.cookies.some((cookie: string) => cookie.startsWith(`${cookieName}=email;`))).toBe(true);
  const state = await (await fetch(`${ctx.baseURL}/__test/last-login`)).json();
  expect(state.events.length).toBeGreaterThan(0);
  expect(state.events.every((event: any) => event.http === false)).toBe(true);
  expect(state.events.every((event: any) => event.path === "/sign-up/email")).toBe(true);
  expect(state.events.filter((event: any) => event.kind === "resolve").every((event: any) => event.header === "native-header")).toBe(true);
  expect(result.cookies.some((cookie: string) => cookie.startsWith("better-auth.session_token="))).toBe(true);
  return { body: result.body, cookie: cookieAttributes(result.cookies.find((cookie: string) => cookie.startsWith(`${cookieName}=`))), state };
});

for (const native of [true, false]) {
  compatScenario(native ? "native last login resolves the supplied endpoint body" : "HTTP last login resolves the body replaced by a before hook", async ctx => {
    const name = native ? "Original name" : "Replaced name";
    const email = ctx.uniqueEmail(native ? "native-body" : "replaced-body");
    await fetch(`${ctx.baseURL}/__test/last-login`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ resolve: "body", ...(native ? {} : { replaceName: name }) }),
    });
    const response = await fetch(`${ctx.baseURL}${native ? "/__test/last-login/native" : "/api/auth/sign-up/email"}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, name: "Original name", password: "Password123!" }),
    });
    expect(response.status).toBe(200);
    const result = await response.json();
    const body = native ? result.body : result;
    const cookies: string[] = native ? result.cookies : response.headers.getSetCookie();
    expect(body.user.name).toBe(name);
    expect(body.user.lastLoginMethod).toBe(persists ? stored(name) : undefined);
    const cookie = cookies.find(cookie => cookie.startsWith(`${cookieName}=`));
    expect(cookie).toContain(`=${encodeURIComponent(name)};`);
    const state = await (await fetch(`${ctx.baseURL}/__test/last-login`)).json();
    const callbacks = state.events.filter((event: any) => ["resolve", "cookie"].includes(event.kind));
    expect(callbacks.length).toBe(persists ? 4 : 2);
    expect(callbacks.every((event: any) => event.bodyName === name && event.http === !native)).toBe(true);
    expect(state.users).toEqual([{ email, method: persists ? stored(name) : null }]);
    return { body, cookie: cookieAttributes(cookie), state };
  });
}
