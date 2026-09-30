import { expect } from "bun:test";
import { createLocalJWKSet, jwtVerify, decodeProtectedHeader, generateKeyPair, SignJWT } from "jose";
import { compatScenario } from "../../../support/scenario";

compatScenario("JWT callbacks, pinned algorithms and server verification", async ctx => {
  const control = async (body: unknown) => fetch(`${ctx.baseURL}/__test/jwt/action`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const owner = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("jwt-callback"), name: "Callback", password: "password123" });
  expect(owner.error).toBeNull();
  const session = await ctx.actor().client.getSession();
  expect(session.error).toBeNull();
  const issued = await ctx.rawRequest({ path: "/api/auth/token" });
  expect(issued.status).toBe(200);
  const token = (issued.body as { token: string }).token;
  const keys = (await ctx.rawRequest({ path: "/api/auth/jwks" })).body as any;
  const { payload } = await jwtVerify(token, createLocalJWKSet(keys), { issuer: ctx.baseURL, audience: ctx.baseURL, algorithms: ["EdDSA"] });
  expect(payload.sub).toBe(session.data!.session.id);
  expect(payload.userId).toBe(owner.data!.user.id);
  expect(payload.sessionUserId).toBe(owner.data!.user.id);
  expect(payload.sessionId).toBe(session.data!.session.id);
  expect(payload.userAgent).toBe(session.data!.session.userAgent);
  expect(payload).not.toHaveProperty("email");
  const sessionResponse = await ctx.actor().fetch("/api/auth/get-session");
  const header = (await jwtVerify(sessionResponse.headers.get("set-auth-jwt")!, createLocalJWKSet(keys))).payload;
  expect(header.sessionId).toBe(payload.sessionId);
  expect(header.sub).toBe(payload.sub);
  expect((await (await control({ action: "verify", token })).json()).payload).toEqual(payload);
  const wrongKey = await generateKeyPair("EdDSA");
  const forged = await new SignJWT(payload).setProtectedHeader(decodeProtectedHeader(token)).sign(wrongKey.privateKey);
  expect((await (await control({ action: "verify", token: forged })).json()).payload).toBeNull();
  for (const claims of [{ sub: "owner", aud: "wrong" }, { sub: "owner", iss: "wrong" }, { sub: "owner", exp: 1 }, { sub: "owner", nbf: Math.floor(Date.now() / 1000) + 3600 }, {}]) {
    const signed = await (await control({ action: "sign", payload: claims })).json();
    expect((await (await control({ action: "verify", token: signed.token })).json()).payload).toBeNull();
  }
  expect((await (await control({ action: "verify", token, issuer: "wrong" })).json()).payload).toBeNull();
  const algorithms = [];
  for (const alg of ["PS256", "ES512"]) {
    const response = await control({ action: "sign", alg, payload: { sub: "resource-owner" }, header: { typ: "logout+jwt" } });
    expect(response.status).toBe(200);
    const issued = await response.json();
    const currentKeys = (await ctx.rawRequest({ path: "/api/auth/jwks" })).body as any;
    const verified = await jwtVerify(issued.token, createLocalJWKSet(currentKeys), { algorithms: [alg], issuer: ctx.baseURL, audience: ctx.baseURL });
    expect(verified.protectedHeader.typ).toBe("logout+jwt");
    expect(verified.payload.sub).toBe("resource-owner");
    expect((await (await control({ action: "verify", token: issued.token })).json()).payload).toEqual(verified.payload);
    const pinned = await (await control({ action: "sign", kid: verified.protectedHeader.kid, alg, payload: { sub: "pinned" } })).json();
    expect(decodeProtectedHeader(pinned.token).kid).toBe(verified.protectedHeader.kid);
    expect((await control({ action: "sign", kid: verified.protectedHeader.kid, alg: "EdDSA", payload: {} })).status).toBe(500);
    algorithms.push({ alg, subject: verified.payload.sub, typ: verified.protectedHeader.typ });
  }
  expect((await control({ action: "sign", kid: "missing", payload: {} })).status).toBe(500);
  expect((await control({ action: "sign", alg: "RS256", payload: {} })).status).toBe(500);
  const expired = await (await control({ action: "expired" })).json();
  expect((await control({ action: "sign", kid: expired.kid, payload: {} })).status).toBe(500);
  const concurrent = await Promise.all(Array.from({ length: 3 }, async () => {
    const response = await control({ action: "sign", payload: { sub: "concurrent-owner" } });
    expect(response.status).toBe(200);
    return (await response.json()).token;
  }));
  for (const token of concurrent) expect((await (await control({ action: "verify", token })).json()).payload.sub).toBe("concurrent-owner");
  const unpinned = await (await control({ action: "sign", payload: { sub: "owner" } })).json();
  expect(decodeProtectedHeader(unpinned.token).alg).toBe("EdDSA");
  const { iat, exp, iss, aud, sub, sessionUserId, ...claims } = payload;
  return { owner: owner.data, session: session.data, claims, subjectMatches: sub === session.data!.session.id, sessionUserMatches: sessionUserId === owner.data!.user.id, ttl: exp! - iat!, algorithms };
});
