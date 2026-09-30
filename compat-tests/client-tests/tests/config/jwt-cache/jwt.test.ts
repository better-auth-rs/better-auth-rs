import { expect } from "bun:test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { compatScenario } from "../../../support/scenario";

compatScenario("asymmetric cookie cache binds purpose, identity and expiry across rotation", async ctx => {
  const control = async (body: unknown) => {
    const response = await fetch(`${ctx.baseURL}/__test/jwt/action`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    expect(response.status).toBe(200);
    return response.json();
  };
  const signup = await ctx.actor().fetch("/api/auth/sign-up/email", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: ctx.uniqueEmail("jwt-cache"), name: "Cache", password: "password123" }) });
  expect(signup.status).toBe(200);
  const owner = await signup.json();
  const cookies = signup.headers.getSetCookie().map(cookie => cookie.split(";")[0]!);
  const credential = cookies.find(cookie => cookie.startsWith("better-auth.session_token="))!;
  const cache = cookies.find(cookie => cookie.startsWith("better-auth.session_data="))!;
  expect(typeof cache).toBe("string");
  const token = cache.slice(cache.indexOf("=") + 1);
  const keys = (await ctx.rawRequest({ path: "/api/auth/jwks" })).body as any;
  const options = { issuer: ctx.baseURL, audience: "better-auth:session-cache", algorithms: ["EdDSA"], typ: "better-auth.session-cache+jwt" };
  const verified = await jwtVerify(token, createLocalJWKSet(keys), options);
  const claims = verified.payload;
  expect(claims.sub).toBe(owner.user.id);
  expect(claims.sid).toBe(owner.token);
  expect((claims.session as any).token).toBe(owner.token);
  expect((claims.user as any).id).toBe(owner.user.id);
  expect(claims.exp! - claims.iat!).toBe(300);
  expect((await control({ action: "verify", token })).payload).toBeNull();
  await control({ action: "rotate" });
  const fresh = (await ctx.rawRequest({ path: "/api/auth/jwks" })).body as any;
  expect(fresh.keys.length).toBeGreaterThan(1);
  expect((await jwtVerify(token, createLocalJWKSet(fresh), options)).payload).toEqual(claims);
  await control({ action: "revoke", token: owner.token });
  const request = async (cacheToken: string, query = "") => {
    const response = await fetch(`${ctx.baseURL}/api/auth/get-session${query}`, { headers: { cookie: `${credential}; better-auth.session_data=${cacheToken}` } });
    expect(response.status).toBe(200);
    return response.json();
  };
  const cached = await request(token);
  expect(cached.user.id).toBe(owner.user.id);
  expect(cached.session.token).toBe(owner.token);
  expect(await request(token, "?disableCookieCache=true")).toBeNull();
  const ordinary = await control({ action: "sign", payload: claims });
  expect(await request(ordinary.token)).toBeNull();
  for (const change of [{ sub: "other-user" }, { sid: "other-session" }, { iss: "wrong" }, { aud: "wrong" }, { exp: 1 }, { session: { ...(claims.session as object), expiresAt: "2000-01-01T00:00:00.000Z" } }]) {
    const forged = await control({ action: "sign", payload: { ...claims, ...change }, header: { typ: "better-auth.session-cache+jwt" } });
    expect(await request(forged.token)).toBeNull();
  }
  return { owner, cached, cachedClaims: { user: claims.user, session: claims.session }, type: verified.protectedHeader.typ, algorithm: verified.protectedHeader.alg, ttl: claims.exp! - claims.iat!, audience: claims.aud, version: claims.version };
});
