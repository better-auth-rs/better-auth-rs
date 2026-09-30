import { expect } from "bun:test";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import { compatScenario } from "../support/scenario";

export function jwtScenario(algorithm: "EdDSA" | "RS256" | "ES256" | "PS256" | "ES512", identityDefaults = false) {
  compatScenario(`JWT ${algorithm} signs real session claims with public-only discovery`, async (ctx) => {
    const denied = await ctx.rawRequest({ path: "/api/auth/token" });
    expect(denied.status).toBe(401);
    expect(denied.body).toEqual({ code: "UNAUTHORIZED", message: "Unauthorized" });
    const discovery = await ctx.rawRequest({ path: "/api/auth/jwks" });
    expect(discovery.status).toBe(200);
    const keys = discovery.body as JSONWebKeySet;
    expect(keys.keys).toHaveLength(1);
    const key = keys.keys[0]!;
    expect(key.alg).toBe(algorithm);
    if (algorithm === "PS256") expect(Buffer.from(key.n!, "base64url").length * 8).toBe(3072);
    if (algorithm === "ES512") expect(key.crv).toBe("P-521");
    expect(typeof key.kid).toBe("string");
    for (const privateField of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) expect(key).not.toHaveProperty(privateField);
    const owner = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("jwt-owner"), password: "password123", name: "JWT Owner" });
    expect(owner.error).toBeNull();
    const issued = await ctx.rawRequest({ path: "/api/auth/token" });
    expect(issued.status).toBe(200);
    const token = (issued.body as { token: string }).token;
    const jwks = createLocalJWKSet(keys);
    const options = { issuer: ctx.baseURL, audience: ctx.baseURL, algorithms: [algorithm] };
    const verified = await jwtVerify(token, jwks, options);
    expect(verified.protectedHeader.kid).toBe(key.kid);
    expect(verified.protectedHeader.alg).toBe(algorithm);
    expect(verified.payload.sub).toBe(owner.data!.user.id);
    expect(verified.payload.id).toBe(owner.data!.user.id);
    expect(verified.payload.email).toBe(owner.data!.user.email);
    if (identityDefaults) {
      expect(verified.payload.isAnonymous).toBe(false);
      expect(verified.payload.phoneNumber).toBeNull();
      expect(verified.payload.phoneNumberVerified).toBeNull();
    }
    expect(verified.payload.exp! - verified.payload.iat!).toBe(900);
    expect(Math.abs(verified.payload.iat! - Math.floor(Date.now() / 1000))).toBeLessThan(10);
    const parts = token.split(".");
    parts[2] = `${parts[2]![0] === "A" ? "B" : "A"}${parts[2]!.slice(1)}`;
    await expect(jwtVerify(parts.join("."), jwks, options)).rejects.toThrow();
    await expect(jwtVerify(token, jwks, { ...options, audience: "wrong-audience" })).rejects.toThrow();
    const sessionResponse = await ctx.actor().fetch("/api/auth/get-session");
    expect(sessionResponse.status).toBe(200);
    const header = sessionResponse.headers.get("set-auth-jwt");
    expect(typeof header).toBe("string");
    expect(sessionResponse.headers.get("access-control-expose-headers")!.split(",").map((value) => value.trim())).toContain("set-auth-jwt");
    const sessionClaims = (await jwtVerify(header!, jwks, options)).payload;
    expect(sessionClaims.sub).toBe(owner.data!.user.id);
    if (identityDefaults) {
      expect(sessionClaims.isAnonymous).toBe(false);
      expect(sessionClaims.phoneNumber).toBeNull();
      expect(sessionClaims.phoneNumberVerified).toBeNull();
    }
    const { iat, exp, iss, aud, sub, ...claims } = verified.payload;
    const publicKey = Object.fromEntries(Object.entries(key).map(([field, value]) => [field, ["kid", "x", "y", "n"].includes(field) ? "<verified-key-component>" : value]));
    return { denied, publicKey, claims, ttl: exp! - iat!, issuerMatches: iss === ctx.baseURL, audienceMatches: aud === ctx.baseURL, subjectMatches: sub === owner.data!.user.id, session: await sessionResponse.json() };
  });
}
