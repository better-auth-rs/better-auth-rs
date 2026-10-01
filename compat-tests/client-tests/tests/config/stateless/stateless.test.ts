import { expect, test } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { TS_BASE_URL, RUST_BASE_URL } from "../../../support/config";

const profile = process.env.COMPAT_PROFILE;
const explicit = profile === "stateless-explicit";
const secondary = profile === "stateless-secondary";
const defaults = profile === "stateless-default";
const refreshing = profile === "stateless-refresh" || profile === "stateless-no-refresh";

function cookies(response: Response) {
  return response.headers.getSetCookie().map(line => line.split(";")[0]!).join("; ");
}
function cacheCookie(cookie: string) {
  return cookie.split("; ").find(value => value.startsWith("better-auth.session_data="))?.split("=")[1];
}

compatScenario("stateless defaults preserve explicit cookie and session authority settings", async ctx => {
  const actor = ctx.actor();
  const signup = await actor.fetch("/api/auth/sign-up/email", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Cookie Owner", email: ctx.uniqueEmail("stateless"), password: "password123" }) });
  expect(signup.status).toBe(200);
  const signupBody = await signup.json() as any;
  const originalCookies = cookies(signup);
  expect(Boolean(cacheCookie(originalCookies))).toBe(!explicit);
  if (!explicit) expect(decodeURIComponent(cacheCookie(originalCookies)!).split(".")).toHaveLength(5);
  const restart = await ctx.rawRequest({ path: "/__test/stateless", method: "POST", json: { restart: true } });
  expect((restart.body as any).users).toBe(0);
  const session = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(session.status).toBe(200);
  if (explicit) expect(session.body).toBeNull();
  else expect((session.body as any).user.email).toBe(signupBody.user.email);
  if (!explicit) {
    const application = await ctx.rawRequest({ path: "/__test/cached-session" });
    expect(application.status).toBe(200);
    expect((application.body as any).user.email).toBe(signupBody.user.email);
  }
  const authoritative = await ctx.rawRequest({ actor: "forced", path: "/api/auth/get-session?disableCookieCache=true", headers: { cookie: originalCookies } });
  expect(authoritative.status).toBe(200);
  expect(Boolean(authoritative.body)).toBe(secondary);
  const invalid = await ctx.rawRequest({ actor: "tampered", path: "/api/auth/get-session", headers: { cookie: originalCookies.replace(/(better-auth.session_token=)[^;]+/, "$1invalid") } });
  expect(invalid.body).toBeNull();
  if (secondary) {
    await ctx.rawRequest({ path: "/__test/stateless", method: "POST", json: { revoke: signupBody.token } });
    const cached = await ctx.rawRequest({ actor: "cached", path: "/api/auth/get-session", headers: { cookie: originalCookies } });
    expect((cached.body as any).user.email).toBe(signupBody.user.email);
    const revoked = await ctx.rawRequest({ actor: "revoked", path: "/api/auth/get-session?disableCookieCache=true", headers: { cookie: originalCookies } });
    expect(revoked.body).toBeNull();
  }
  const signout = await ctx.rawRequest({ path: "/api/auth/sign-out", method: "POST", json: {} });
  expect(signout.status).toBe(200);
  const signedOut = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(signedOut.body).toBeNull();
  return { session: session.body, authoritative: authoritative.body, events: (restart.body as any).events, signout };
});

if (!refreshing) compatScenario("OAuth PKCE state and account cookies survive a fresh ephemeral adapter", async ctx => {
  const start = await ctx.rawRequest({ path: "/api/auth/sign-in/social", method: "POST", json: { provider: "mock", callbackURL: "/done", errorCallbackURL: "/failed" } });
  expect(start.status).toBe(200);
  const authorization = new URL((start.body as any).url);
  expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
  expect(authorization.searchParams.get("code_challenge")).toBeTruthy();
  await ctx.rawRequest({ path: "/__test/stateless", method: "POST", json: { restart: true } });
  const callback = await ctx.rawRequest({ path: `/api/auth/callback/mock?code=fixture-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}`, redirect: "manual" });
  expect(callback.status).toBe(302);
  if (explicit) {
    expect(callback.location).toContain("error=");
    const state = await ctx.rawRequest({ path: "/__test/stateless" });
    expect((state.body as any).tokenRequests).toHaveLength(0);
    return { callback, state };
  }
  expect(callback.location).toBe("/done");
  const accounts = await ctx.rawRequest({ path: "/api/auth/list-accounts" });
  expect(accounts.status).toBe(200);
  expect(accounts.body as any[]).toHaveLength(1);
  await ctx.rawRequest({ path: "/__test/stateless", method: "POST", json: { restart: true } });
  const session = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect((session.body as any).user.email).toBe("stateless@example.com");
  const access = await ctx.rawRequest({ path: "/api/auth/get-access-token", method: "POST", json: { useAccountCookie: true } });
  expect(access.status).toBe(200);
  expect((access.body as any).accessToken).toBe("initial-access");
  const refresh = await ctx.rawRequest({ path: "/api/auth/refresh-token", method: "POST", json: { useAccountCookie: true } });
  expect(refresh.status).toBe(200);
  expect((refresh.body as any).accessToken).toBe("refreshed-access");
  expect((refresh.body as any).accountId).toBe((accounts.body as any[])[0].id);
  const persisted = await ctx.rawRequest({ path: "/api/auth/get-access-token", method: "POST", json: { useAccountCookie: true } });
  expect((persisted.body as any).accessToken).toBe("refreshed-access");
  const state = await ctx.rawRequest({ path: "/__test/stateless" });
  expect((state.body as any).users).toBe(0);
  expect((state.body as any).tokenRequests).toEqual([{ grant: "authorization_code", verifier: true, refresh: null }, { grant: "refresh_token", verifier: false, refresh: "refresh-token" }]);
  const { accountId, ...refreshBody } = refresh.body as any;
  return { callback, accounts, session, access, refresh: { ...refresh, body: { ...refreshBody, id: accountId } }, persisted, state };
});

if (refreshing) compatScenario("stateless cookie refresh preserves the original session expiry", async ctx => {
  const response = await ctx.actor().fetch("/api/auth/sign-up/email", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Refresh", email: ctx.uniqueEmail("refresh"), password: "password123" }) });
  expect(response.status).toBe(200);
  const original = cookies(response);
  const before = await ctx.rawRequest({ path: "/api/auth/get-session" });
  await ctx.rawRequest({ path: "/__test/stateless", method: "POST", json: { restart: true } });
  await new Promise(resolve => setTimeout(resolve, 2200));
  const refreshed = await ctx.actor().fetch("/__test/cached-session");
  expect(refreshed.headers.get("cache-control")).toBe("no-store");
  expect(refreshed.headers.get("pragma")).toBe("no-cache");
  const body = await refreshed.json() as any;
  expect(body.session.expiresAt).toBe((before.body as any).session.expiresAt);
  const changed = Boolean(cacheCookie(cookies(refreshed)));
  expect(changed).toBe(profile === "stateless-refresh");
  if (changed) expect(cacheCookie(cookies(refreshed))).not.toBe(cacheCookie(original));
  await new Promise(resolve => setTimeout(resolve, 3000));
  const after = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(Boolean(after.body)).toBe(profile === "stateless-refresh");
  return { changed, body, after };
});

if (defaults) test.serial("stateless JWE session and account cookies work in both runtime directions", async () => {
  for (const [source, target] of [[TS_BASE_URL, RUST_BASE_URL], [RUST_BASE_URL, TS_BASE_URL]]) {
    for (const baseURL of [source!, target!]) expect((await fetch(`${baseURL}/__test/reset-state`, { method: "POST" })).ok).toBe(true);
    const start = await fetch(`${source}/api/auth/sign-in/social`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ provider: "mock", callbackURL: "/done" }) });
    expect(start.status).toBe(200);
    const authorization = new URL((await start.json() as any).url);
    const callback = await fetch(`${source}/api/auth/callback/mock?code=fixture-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}`, { headers: { cookie: cookies(start) }, redirect: "manual" });
    expect(callback.status).toBe(302);
    const cookie = cookies(callback);
    const session = await fetch(`${target}/api/auth/get-session`, { headers: { cookie } });
    expect(session.status).toBe(200);
    expect((await session.json() as any).user.email).toBe("stateless@example.com");
    const access = await fetch(`${target}/api/auth/get-access-token`, { method: "POST", headers: { cookie, origin: target!, "content-type": "application/json" }, body: JSON.stringify({ useAccountCookie: true }) });
    expect(access.status).toBe(200);
    expect((await access.json() as any).accessToken).toBe("initial-access");
  }
});
