import { expect } from "bun:test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { compatScenario } from "../../../support/scenario";

export function jwtClaimsScenario(expiration: number) {
  compatScenario("JWT audience arrays and expiration policies preserve claims and reject unmatched recipients", async ctx => {
    const control = async (body: unknown) => {
      const response = await fetch(`${ctx.baseURL}/__test/jwt/action`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      expect(response.status).toBe(200);
      return response.json();
    };
    const signed = await control({ action: "sign", payload: { sub: "resource-owner", iat: 1900000000.25 } });
    const jwks = await ctx.rawRequest({ path: "/api/auth/jwks" });
    expect(jwks.status).toBe(200);
    const keys = jwks.body as any;
    const { payload } = await jwtVerify(signed.token, createLocalJWKSet(keys), { issuer: ctx.baseURL, audience: "service-b" });
    expect(payload.aud).toEqual(["service-a", "service-b"]);
    expect(payload.iat).toBe(1900000000.25);
    expect(payload.exp).toBe(expiration);
    expect((await control({ action: "verify", token: signed.token })).payload).toEqual(payload);
    const verified = [];
    for (const audience of ["service-b", ["other", "service-a"], "other", ["other"], []]) {
      const issued = await control({ action: "sign", payload: { sub: "recipient", aud: audience, exp: 2000000042 } });
      const response = await control({ action: "verify", token: issued.token });
      const accepted = audience === "service-b" || Array.isArray(audience) && audience.includes("service-a");
      expect(response.payload !== null).toBe(accepted);
      if (accepted) {
        expect(response.payload.aud).toEqual(audience);
        expect(response.payload.exp).toBe(2000000042);
      }
      verified.push(response);
    }
    const overridden = await control({ action: "sign", payload: { sub: "override", aud: null, exp: 2000000011.5 } });
    const override = await control({ action: "verify", token: overridden.token });
    expect(override.payload.aud).toEqual(["service-a", "service-b"]);
    expect(override.payload.exp).toBe(2000000011.5);
    const observe = (claims: typeof payload | null) => {
      if (claims === null) return null;
      expect(claims.iss).toBe(ctx.baseURL);
      return { ...claims, iss: "<base-url>" };
    };
    return { payload: observe(payload), verified: verified.map(value => observe(value.payload)), override: observe(override.payload) };
  });
}
