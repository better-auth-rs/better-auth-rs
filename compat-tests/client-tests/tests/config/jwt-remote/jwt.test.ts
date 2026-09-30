import { expect } from "bun:test";
import { createRemoteJWKSet, jwtVerify, decodeProtectedHeader } from "jose";
import { compatScenario } from "../../../support/scenario";

compatScenario("custom signing publishes remote JWKS and refreshes after rotation", async ctx => {
  const control = async (body: unknown) => {
    const response = await fetch(`${ctx.baseURL}/__test/jwt/action`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    expect(response.status).toBe(200);
    return response.json();
  };
  const owner = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("jwt-remote"), name: "Remote", password: "password123" });
  expect(owner.error).toBeNull();
  const issued = await ctx.rawRequest({ path: "/api/auth/token" });
  expect(issued.status).toBe(200);
  const token = (issued.body as { token: string }).token;
  const keys = createRemoteJWKSet(new URL(`${ctx.baseURL}/__test/jwt/remote-jwks`), { cooldownDuration: 0 });
  const options = { issuer: ctx.baseURL, audience: ctx.baseURL, algorithms: ["EdDSA"] };
  const verified = await jwtVerify(token, keys, options);
  expect(verified.payload.sub).toBe(owner.data!.user.id);
  expect(verified.payload.email).toBe(owner.data!.user.email);
  await expect(jwtVerify(token, keys, { ...options, algorithms: ["RS256"] })).rejects.toThrow();
  await expect(jwtVerify(token, keys, { ...options, issuer: "wrong" })).rejects.toThrow();
  await expect(jwtVerify(token, keys, { ...options, audience: "wrong" })).rejects.toThrow();
  // Upstream verifyJWT reads adapter keys, not remoteUrl.
  expect((await control({ action: "verify", token })).payload).toBeNull();
  await control({ action: "rotate" });
  const next = await control({ action: "sign", payload: { sub: "remote-resource" }, header: { typ: "logout+jwt" } });
  const rotated = await jwtVerify(next.token, keys, options);
  expect(rotated.protectedHeader.kid).not.toBe(verified.protectedHeader.kid);
  expect(rotated.protectedHeader.typ).toBe("logout+jwt");
  expect(rotated.payload.sub).toBe("remote-resource");
  expect((await jwtVerify(token, keys, options)).payload).toEqual(verified.payload);
  const pinned = await control({ action: "sign", kid: verified.protectedHeader.kid, alg: "EdDSA", payload: { sub: "pinned" } });
  expect(decodeProtectedHeader(pinned.token).kid).toBe(verified.protectedHeader.kid);
  const session = await ctx.actor().fetch("/api/auth/get-session");
  expect((await jwtVerify(session.headers.get("set-auth-jwt")!, keys, options)).payload.sub).toBe(owner.data!.user.id);
  const discovery = await ctx.rawRequest({ path: "/api/auth/jwks" });
  expect(discovery.status).toBe(404);
  const { iat, exp, iss, aud, sub, ...claims } = verified.payload;
  return { owner: owner.data, session: await session.json(), claims, subjectMatches: sub === owner.data!.user.id, algorithm: verified.protectedHeader.alg, ttl: exp! - iat!, rotatedSubject: rotated.payload.sub, localDiscoveryStatus: discovery.status };
});
