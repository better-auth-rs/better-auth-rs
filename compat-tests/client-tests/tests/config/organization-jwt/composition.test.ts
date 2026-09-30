import { expect } from "bun:test";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import { compatScenario } from "../../../support/scenario";
import { control } from "../../../support/oidc";

compatScenario("teams, transformed user fields and custom session fields survive asymmetric caches and JWT callbacks", async ctx => {
  const post = (path: string, json: unknown) => ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json });
  const signup = await ctx.actor().fetch("/api/auth/sign-up/email", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: ctx.uniqueEmail("composition"), password: "Password123!", name: "Owner", department: "engineering", alias: "owner", secretNote: "private" }),
  });
  expect(signup.status).toBe(200);
  const owner = await signup.json();
  const cacheCookie = signup.headers.getSetCookie().find(cookie => cookie.startsWith("better-auth.session_data="))!;
  expect(typeof cacheCookie).toBe("string");
  const cacheToken = cacheCookie.split(";")[0]!.slice("better-auth.session_data=".length);
  const jwks = await ctx.rawRequest({ path: "/api/auth/jwks" });
  expect(jwks.status).toBe(200);
  const keys = createLocalJWKSet(jwks.body as JSONWebKeySet);
  const cache = await jwtVerify(cacheToken, keys, { issuer: ctx.baseURL, audience: "better-auth:session-cache", typ: "better-auth.session-cache+jwt", algorithms: ["EdDSA"] });
  expect(cache.payload.sub).toBe(owner.user.id);
  expect(cache.payload.sid).toBe(owner.token);
  expect(cache.payload.user).toEqual(owner.user);
  expect(cache.payload.session).toMatchObject({ userId: owner.user.id, token: owner.token, activeTeamId: null });
  expect(cache.payload.exp! - cache.payload.iat!).toBe(300);
  const observations: unknown[] = [];
  async function snapshot(fresh = false) {
    const response = await ctx.rawRequest({ path: `/api/auth/get-session${fresh ? "?disableCookieCache=true" : ""}` });
    expect(response.status).toBe(200);
    const data = response.body as any;
    expect(data.user).toEqual(owner.user);
    expect(data.user.alias).toBe("owner:in:in:out");
    expect(data.user).not.toHaveProperty("secretNote");
    expect(data.session).not.toHaveProperty("internalNote");
    const issued = await ctx.actor().fetch("/api/auth/token");
    expect(issued.status).toBe(200);
    const { payload } = await jwtVerify((await issued.json()).token, keys, { issuer: ctx.baseURL, audience: ctx.baseURL, algorithms: ["EdDSA"] });
    expect(payload.sub).toBe(data.session.id);
    expect(payload.user).toEqual(data.user);
    expect(payload.session).toEqual(data.session);
    observations.push(response, { user: payload.user, session: payload.session, subjectMatches: payload.sub === data.session.id });
    return data.session;
  }
  expect((await snapshot()).activeTeamId).toBeNull();
  const updated = await post("/update-session", { deviceLabel: "Work laptop" });
  expect(updated.status).toBe(200);
  expect((await snapshot()).deviceLabel).toBe("Work laptop");
  const denied = await post("/update-session", { internalNote: "private", deviceLabel: "blocked" });
  expect(denied.status).toBe(400);
  const created = await post("/organization/create", { name: "Composed", slug: ctx.uniqueToken("composition") });
  expect(created.status).toBe(200);
  const organizationId = (created.body as any).id;
  expect((await snapshot()).activeTeamId).toBeNull();
  const selected = await snapshot(true);
  expect(selected.activeOrganizationId).toBe(organizationId);
  expect(typeof selected.activeTeamId).toBe("string");
  expect(selected.deviceLabel).toBe("Work laptop");
  const teamId = selected.activeTeamId;
  expect((await snapshot()).activeTeamId).toBe(teamId);
  const cleared = await post("/organization/set-active-team", { teamId: null });
  expect(cleared.status).toBe(200);
  expect((await snapshot()).activeTeamId).toBeNull();
  const restored = await post("/organization/set-active-team", { teamId });
  expect(restored.status).toBe(200);
  const final = await snapshot();
  expect(final.activeTeamId).toBe(teamId);
  expect(final.deviceLabel).toBe("Work laptop");
  return { owner, cache: { user: cache.payload.user, session: cache.payload.session }, updated, denied, created, cleared, restored, observations };
});

compatScenario("OIDC mapped fields use the shared user schema on creation and profile updates", async ctx => {
  const email = ctx.uniqueEmail("mapped-fields");
  const sub = ctx.uniqueToken("mapped-fields");
  const observations: unknown[] = [];
  let userId: string | undefined;
  for (const [mode, alias] of [["mapped-image", "picture"], ["valid", "plain"]]) {
    await control("configure", { email, sub, mode });
    const signIn = await ctx.actor().client.signIn.social({ provider: "oidc-mapped", callbackURL: "/done", errorCallbackURL: "/error" });
    expect(signIn.error).toBeNull();
    const authorization = await fetch(signIn.data!.url, { redirect: "manual" });
    expect(authorization.status).toBe(302);
    const callback = await ctx.rawRequest({ path: authorization.headers.get("location")!, redirect: "manual" });
    expect(callback.status).toBe(302);
    expect(callback.location).toBe("/done");
    const cached = await ctx.rawRequest({ path: "/api/auth/get-session" });
    const fresh = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
    expect(cached.status).toBe(200);
    expect(fresh.status).toBe(200);
    const user = (fresh.body as any).user;
    expect(user).toMatchObject({ email, department: "identity", alias: `${alias}:in:in:out`, internalCode: "server" });
    expect(user).not.toHaveProperty("secretNote");
    expect((cached.body as any).user).toEqual(user);
    if (userId) expect(user.id).toBe(userId);
    userId = user.id;
    const accounts = await ctx.actor().client.listAccounts();
    expect(accounts.error).toBeNull();
    expect(accounts.data).toHaveLength(1);
    expect(accounts.data![0]!.accountId).toBe(`external-${sub}`);
    observations.push({ callback, cached, fresh, accounts: ctx.snapshot(accounts) });
    expect((await ctx.actor().client.signOut()).error).toBeNull();
  }
  return observations;
});
