import { expect } from "bun:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { compatScenario } from "../../../support/scenario";

export type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
export async function publishKeys(ctx: Context, keys: unknown[]) {
  const configured = await fetch(`${ctx.baseURL}/__test/one-tap-jwks`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ keys }) });
  expect(configured.status).toBe(200);
}
export async function issuer(ctx: Context, email: string, audience = "google-client-id") {
  const keys = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(keys.publicKey), kid: "one-tap-fixture", use: "sig", alg: "RS256" };
  await publishKeys(ctx, [jwk]);
  const subject = ctx.uniqueToken("google-sub");
  return async (patch: Record<string, unknown> = {}, header: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const claims = { sub: subject, email, email_verified: true, name: "One Tap User", picture: "https://example.com/avatar.png", iss: "https://accounts.google.com", aud: audience, iat: now, exp: now + 3600, ...patch };
    for (const key of Object.keys(claims)) if (claims[key] === undefined) delete claims[key];
    return new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "one-tap-fixture", ...header }).sign(keys.privateKey, { crit: { fixture: true } });
  };
}
export function callback(ctx: Context, idToken: string, extra: Record<string, unknown> = {}) {
  return ctx.rawRequest({ path: "/api/auth/one-tap/callback", method: "POST", json: { idToken, ...extra } });
}
export function invalid(response: Awaited<ReturnType<typeof callback>>) {
  expect(response.status).toBe(400);
  expect(response.body).toEqual({ message: "invalid id token" });
}

export async function verifyLocalEmail(ctx: Context, email: string) {
  const sent = await ctx.actor().client.sendVerificationEmail({ email });
  expect(sent.error).toBeNull();
  const record = await ctx.readVerificationEmail({ email }) as { token: string };
  const verified = await ctx.actor().client.verifyEmail({ query: { token: record.token } });
  expect(verified.error).toBeNull();
  return verified;
}
