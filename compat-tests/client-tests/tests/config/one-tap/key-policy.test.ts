import { expect } from "bun:test";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { compatScenario } from "../../../support/scenario";
import { callback, invalid, publishKeys } from "./helpers";

compatScenario("One Tap applies Google's imported JWK policy and rejects weak RSA keys", async (ctx) => {
  const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...keys.publicKey.export({ format: "jwk" }), kid: "key-policy", alg: "RS256", use: "sig" };
  const now = Math.floor(Date.now() / 1000);
  const claims = { sub: ctx.uniqueToken("key-policy"), email: ctx.uniqueEmail("key-policy"), email_verified: true, iss: "https://accounts.google.com", aud: "google-client-id", iat: now, exp: now + 3600 };
  const signed = `${Buffer.from(JSON.stringify({ alg: "RS256", kid: jwk.kid })).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}`;
  const signature = sign("RSA-SHA256", Buffer.from(signed), keys.privateKey);
  expect(verify("RSA-SHA256", Buffer.from(signed), keys.publicKey, signature)).toBe(true);
  const token = `${signed}.${signature.toString("base64url")}`;
  const rejected = [];
  for (const patch of [{ key_ops: ["sign"] }, { key_ops: [] }, { key_ops: ["verify", "verify"] }, { key_ops: ["verify", "sign"] }, { key_ops: null }, { ext: "true" }, { ext: null }]) {
    await publishKeys(ctx, [{ ...jwk, ...patch }]);
    const response = await callback(ctx, token);
    invalid(response);
    rejected.push(response);
  }
  const weakKeys = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const weakSignature = sign("RSA-SHA256", Buffer.from(signed), weakKeys.privateKey);
  expect(verify("RSA-SHA256", Buffer.from(signed), weakKeys.publicKey, weakSignature)).toBe(true);
  await publishKeys(ctx, [{ ...weakKeys.publicKey.export({ format: "jwk" }), kid: jwk.kid }]);
  const weak = await callback(ctx, `${signed}.${weakSignature.toString("base64url")}`);
  invalid(weak);
  const session = await ctx.actor().client.getSession();
  expect(session.data).toBeNull();
  // Google imports RSA keys with an explicit RS256 algorithm; jose ignores JWK alg/use here.
  await publishKeys(ctx, [{ ...jwk, alg: "RS512", use: "enc", key_ops: ["verify"], ext: false }]);
  const importedPolicy = await callback(ctx, token);
  expect(importedPolicy.status).toBe(200);
  return { rejected, weak, session, importedPolicy };
});
