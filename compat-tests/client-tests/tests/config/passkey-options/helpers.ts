import { expect } from "bun:test";
import { asArray, asRecord, type CompatContext } from "../../phase6/helpers";
import { authenticator, type RegistrationOptions, type AuthenticationOptions } from "../../phase8/authenticator";
export { asArray, asRecord, authenticator, type CompatContext, type RegistrationOptions, type AuthenticationOptions };

export function fixture(ctx: CompatContext) {
  const observations: unknown[] = [];
  return {
    observations,
    async control(body: Record<string, unknown> = {}) {
      const result = await ctx.rawRequest({ path: "/__test/passkey-options", method: "POST", json: body });
      expect(result.status).toBe(200);
    },
    async trace(userId?: string) {
      const result = await ctx.rawRequest({ path: `/__test/passkey-options${userId ? `?userId=${encodeURIComponent(userId)}` : ""}` });
      expect(result.status).toBe(200); observations.push(result);
      return asRecord(result.body);
    },
    async options(actor = "primary", query = "") {
      const result = await ctx.rawRequest({ actor, path: `/api/auth/passkey/generate-register-options${query}` });
      expect(result.status).toBe(200);
      const options = result.body as RegistrationOptions;
      observations.push({ ...result, body: { ...options, challenge: "<challenge>", user: { ...options.user, id: "<handle>" } } });
      return options;
    },
    async register(key: ReturnType<typeof authenticator>, options: RegistrationOptions, body: Record<string, unknown> = {}, actor = "primary", origin = "https://passkeys.example") {
      const result = await ctx.rawRequest({ actor, path: "/api/auth/passkey/verify-registration", method: "POST", json: { response: key.register(options, origin, false), ...body } });
      observations.push(result); return result;
    },
    async authenticationOptions(actor = "login") {
      const result = await ctx.rawRequest({ actor, path: "/api/auth/passkey/generate-authenticate-options" });
      expect(result.status).toBe(200);
      expect(asRecord(result.body).extensions).toEqual({ uvm: true });
      observations.push({ ...result, body: { ...asRecord(result.body), challenge: "<challenge>" } });
      return result.body as AuthenticationOptions;
    },
  };
}
