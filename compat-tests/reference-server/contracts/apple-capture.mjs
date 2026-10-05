import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { apple } from "@better-auth/core/social-providers";
import { verifyProviderIdToken } from "../node_modules/@better-auth/core/dist/oauth2/verify-id-token.mjs";
import { captureAppleFlows } from "./apple-flow-capture.mjs";

export const metadata = {
  clientId: "ordinary-client", clientSecret: "ordinary-client-secret",
  callbackURL: "https://app.example.test/callback/apple",
  codeVerifier: "ordinary-code-verifier-at-least-forty-three-characters",
  issuer: "https://appleid.apple.com",
  tokenEndpoint: "https://appleid.apple.com/auth/token",
  jwksEndpoint: "https://appleid.apple.com/auth/keys",
};
const credentials = { clientId: metadata.clientId, clientSecret: metadata.clientSecret };
export const normalized = value => JSON.parse(JSON.stringify(value, (key, value) =>
  key === "iat" ? "<issued-at>" : key === "exp" ? "<expiry>" : value));

export async function captureApple() {
  const core = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8"));
  assert.equal(core.version, "1.7.6");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "ordinary-apple-key", alg: "RS256" };
  const sign = async claims => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ ...claims, iat: now - 60, exp: now + 3600 })
      .setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
  };
  const authorization = [];
  for (const input of [
    { name: "defaults", options: {} },
    { name: "merged scopes", options: { scope: ["name", "configured"] }, scopes: ["request", "configured"] },
    { name: "empty scopes", options: { disableDefaultScope: true, scope: [] }, scopes: [] },
    { name: "configured endpoints", options: { authorizationEndpoint: "https://authorize.example.test/apple?retained=ordinary", redirectURI: "https://app.example.test/configured-callback", prompt: "consent" } },
    { name: "multiple clients", options: { clientId: [metadata.clientId, "ordinary-secondary-client"] } },
    { name: "additional parameters", options: {}, additionalParams: { response_mode: "query", login_hint: "additional@example.test", prompt: "consent" } },
  ]) {
    const provider = apple({ ...credentials, ...input.options });
    const url = await provider.createAuthorizationURL({
      state: "ordinary-state", redirectURI: metadata.callbackURL, codeVerifier: metadata.codeVerifier,
      scopes: input.scopes, additionalParams: input.additionalParams,
      loginHint: "ignored@example.test", idTokenNonce: "ordinary-nonce",
    });
    authorization.push({ ...input, url: url.href });
  }
  const tokenResponse = { access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer", scope: "email name" };
  const grants = [], profiles = [], verification = [];
  const originalFetch = globalThis.fetch;
  try {
    for (const input of [
      { name: "defaults", options: {} },
      { name: "configured callback and client key", options: { redirectURI: "https://app.example.test/configured-callback", clientKey: "ordinary-client-key" } },
    ]) {
      const requests = [];
      globalThis.fetch = Object.assign(async (input, init) => {
        const request = new Request(input, init);
        assert.equal(request.url, metadata.tokenEndpoint);
        requests.push({ method: request.method, contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), authorization: request.headers.get("authorization"), body: Object.fromEntries(new URLSearchParams(await request.text())) });
        return Response.json(tokenResponse);
      }, originalFetch);
      const provider = apple({ ...credentials, ...input.options });
      const code = await provider.validateAuthorizationCode({ code: "ordinary-code", codeVerifier: metadata.codeVerifier, redirectURI: metadata.callbackURL, deviceId: "ordinary-device" });
      const refresh = await provider.refreshAccessToken("ordinary-refresh");
      grants.push({ ...input, requests, tokens: [code, refresh] });
    }
    const complete = { sub: "ordinary-apple-user", name: "Token Name", email: "apple@example.test", email_verified: true, picture: "https://images.example.test/ignored.png", iss: metadata.issuer, aud: metadata.clientId };
    const custom = { user: { id: "custom-apple-user", name: "Custom Name", email: "custom@example.test", image: null, emailVerified: true }, data: { sub: "custom-apple-user" } };
    for (const input of [
      { name: "token name", claims: complete },
      { name: "callback names", claims: { ...complete, email_verified: "true" }, user: { name: { firstName: "Callback", lastName: "Name" }, email: "ignored@example.test" } },
      { name: "first name", claims: { ...complete, email_verified: false }, user: { name: { firstName: "First" } } },
      { name: "last name", claims: { ...complete, email_verified: "false" }, user: { name: { lastName: "Last" } } },
      { name: "empty callback name", claims: complete, user: { name: {} } },
      { name: "omitted fields", claims: { sub: "ordinary-apple-user", iss: metadata.issuer, aud: metadata.clientId } },
      { name: "null email and trim", claims: { ...complete, email: null }, user: { name: { firstName: "\uFEFF Trimmed", lastName: "Name\u00A0" } } },
      { name: "mapped fields", claims: complete, user: { name: { firstName: "Before", lastName: "Mapper" } }, patch: { name: "Mapped Name", email: "mapped@example.test", image: null, emailVerified: false } },
      { name: "custom handler", claims: complete, patch: { name: "Unused Mapper" }, custom },
    ]) {
      const mapperInputs = [], calls = [], requests = [];
      globalThis.fetch = Object.assign(async input => {
        requests.push(String(input));
        throw new Error("Apple profile unexpectedly fetched HTTP");
      }, originalFetch);
      const provider = apple({ ...credentials,
        ...(input.patch ? { mapProfileToUser: async raw => { calls.push("map"); mapperInputs.push(normalized(raw)); return input.patch; } } : {}),
        ...(input.custom ? { getUserInfo: async () => { calls.push("get"); return input.custom; } } : {}),
      });
      const result = await provider.getUserInfo({ idToken: await sign(input.claims), user: input.user });
      assert.ok(result);
      profiles.push({ ...input, result: normalized(result), subject: await provider.accountSubject({ profile: result.data }), mapperInputs, calls, requests });
    }
    for (const input of [
      { name: "primary client", options: {}, audience: metadata.clientId },
      { name: "additional client", options: { clientId: [metadata.clientId, "ordinary-secondary-client"] }, audience: "ordinary-secondary-client" },
      { name: "bundle", options: { appBundleIdentifier: "ordinary.bundle" }, audience: "ordinary.bundle" },
      { name: "explicit audience", options: { audience: ["explicit-primary", "explicit-secondary"], appBundleIdentifier: "unused.bundle" }, audience: "explicit-secondary" },
      { name: "empty audience uses bundle", options: { audience: [], appBundleIdentifier: "ordinary.bundle" }, audience: "ordinary.bundle" },
      { name: "empty bundle uses client", options: { appBundleIdentifier: "" }, audience: metadata.clientId },
      { name: "exact nonce", options: {}, audience: metadata.clientId, nonce: "ordinary-nonce", claimNonce: "ordinary-nonce" },
      { name: "hashed nonce", options: {}, audience: metadata.clientId, nonce: "ordinary-nonce", claimNonce: createHash("sha256").update("ordinary-nonce").digest("hex") },
    ]) {
      const requests = [];
      globalThis.fetch = Object.assign(async (input, init) => {
        const request = new Request(input, init);
        requests.push(new URL(request.url).pathname);
        assert.equal(request.url, metadata.jwksEndpoint);
        return Response.json({ keys: [jwk] });
      }, originalFetch);
      const claims = { ...complete, aud: input.audience, ...(input.claimNonce ? { nonce: input.claimNonce } : {}) };
      const provider = apple({ ...credentials, ...input.options });
      const accepted = await verifyProviderIdToken(provider, await sign(claims), input.nonce);
      assert.equal(accepted, true);
      verification.push({ ...input, claims, accepted, audiences: [provider.idToken.audience].flat(), requests });
    }
    const flows = await captureAppleFlows({ sign, jwk, metadata, normalized });
    return { version: core.version, metadata, tokenResponse, authorization, grants, profiles, verification, flows };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  if (!output) throw new Error("Provide the Apple capture output path");
  writeFileSync(output, JSON.stringify(await captureApple(), null, 2) + "\n");
}
