import { readFileSync, writeFileSync } from "node:fs";
import { microsoft } from "../node_modules/@better-auth/core/dist/social-providers/microsoft-entra-id.mjs";
import { verifyProviderIdToken } from "../node_modules/@better-auth/core/dist/oauth2/verify-id-token.mjs";
import { SignJWT, generateKeyPair, exportJWK } from "jose";

const metadata = {
  clientId: "ordinary-microsoft-client", clientSecret: "ordinary-microsoft-secret-0123456789",
  clientKey: "ordinary-client-key", secondaryClientId: "ordinary-secondary-client",
  callbackURL: "https://social-microsoft.example.test/api/auth/callback/microsoft",
  codeVerifier: "ordinary-microsoft-code-verifier-012345678901234567890123456789",
};
const base = { oid: "ordinary-microsoft-owner", sub: "ordinary-app-subject", name: "Microsoft Owner", email: "microsoft@example.test", picture: "https://images.example.test/microsoft.png", locale: "en-US" };
const provider = (options = {}) => microsoft({ clientId: metadata.clientId, clientSecret: metadata.clientSecret, clientKey: metadata.clientKey, ...options });
const profileToken = profile => new SignJWT(profile).setProtectedHeader({ alg: "HS256" }).sign(new TextEncoder().encode(metadata.clientSecret));
const json = value => JSON.parse(JSON.stringify(value));
const bytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46]);

export async function captureSocialMicrosoft() {
  const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
  if (version !== "1.7.6") throw new Error("Social Microsoft capture requires @better-auth/core 1.7.6");
  const authorization = [];
  for (const input of [
    { name: "defaults", options: {} },
    { name: "empty defaults", options: { tenantId: "", authority: "", clientSecret: "" } },
    { name: "configured", options: { tenantId: "OrdinaryTenant", authority: "https://ordinary-authority.example.test///", scope: ["extra", "openid"], prompt: "consent", redirectURI: "https://app.example.test/configured-callback" }, requestScopes: ["request", "extra"], additionalParams: { domain_hint: "organizations" } },
    { name: "empty scope", options: { disableDefaultScope: true, scope: [] }, requestScopes: [] },
  ]) {
    const configured = provider(input.options);
    const url = await configured.createAuthorizationURL({
      state: "ordinary-state", codeVerifier: metadata.codeVerifier, redirectURI: metadata.callbackURL,
      scopes: input.requestScopes, loginHint: "microsoft@example.test", idTokenNonce: "ordinary-nonce",
      additionalParams: input.additionalParams,
    });
    authorization.push({ ...input, url: url.href });
  }
  const originalFetch = globalThis.fetch;
  let requests = [], responseBody, jwks;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.pathname.endsWith("/oauth2/v2.0/token")) {
      requests.push({ method: request.method, contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), authorization: request.headers.get("authorization"), body: Object.fromEntries(new URLSearchParams(await request.text())) });
      return Response.json(responseBody);
    }
    if (url.origin === "https://graph.microsoft.com") {
      requests.push({ url: request.url, method: request.method, authorization: request.headers.get("authorization") });
      return new Response(bytes, { headers: { "content-type": "image/jpeg" } });
    }
    if (url.pathname.endsWith("/discovery/v2.0/keys")) {
      requests.push({ url: request.url, method: request.method });
      return Response.json(jwks);
    }
    throw new Error(`Unexpected Social Microsoft capture URL: ${request.url}`);
  }, originalFetch);
  try {
    const grants = [];
    for (const input of [
      { name: "defaults", options: {} },
      { name: "configured scopes", options: { scope: ["extra", "openid"], redirectURI: "https://app.example.test/configured-callback" } },
      { name: "empty scope", options: { disableDefaultScope: true, scope: [] } },
      { name: "public client", options: { clientSecret: "" } },
      { name: "assertion", options: { clientSecret: "" }, assertion: true },
    ]) {
      requests = [];
      const assertionCalls = [];
      const options = input.assertion ? { ...input.options, clientAssertion: async context => {
        assertionCalls.push(context);
        return "ordinary-assertion";
      } } : input.options;
      const configured = provider(options);
      responseBody = { access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer", scope: "openid ordinary-returned-scope" };
      const code = await configured.validateAuthorizationCode({ code: "ordinary-code", codeVerifier: metadata.codeVerifier, redirectURI: metadata.callbackURL, deviceId: "ordinary-device" });
      const refresh = await configured.refreshAccessToken("ordinary-refresh");
      grants.push({ ...input, rawResponse: responseBody, requests, tokens: [code, refresh], assertionCalls });
    }
    const profiles = [];
    const absent = { oid: base.oid, sub: base.sub, locale: base.locale };
    for (const input of [
      { name: "default fields", profile: base, options: {} },
      { name: "absent fields", profile: absent, options: {} },
      { name: "null fields", profile: { ...base, name: null, email: null, picture: null, email_verified: null }, options: {} },
      { name: "primary email", profile: { ...base, verified_primary_email: [base.email] }, options: {} },
      { name: "secondary email", profile: { ...base, verified_secondary_email: [base.email] }, options: {} },
      { name: "explicit false", profile: { ...base, email_verified: false, verified_primary_email: [base.email] }, options: {} },
      { name: "explicit true", profile: { ...base, email_verified: true }, options: {} },
      { name: "photo default", profile: base, options: {}, accessToken: "ordinary-access" },
      { name: "photo mapped", profile: base, options: { profilePhotoSize: 96 }, accessToken: "ordinary-access", mapped: { name: "Mapped Microsoft Owner", image: null, emailVerified: true, locale: "zh-TW" } },
      { name: "photo disabled", profile: base, options: { disableProfilePhoto: true }, accessToken: "ordinary-access" },
    ]) {
      requests = [];
      const mapperInputs = [];
      const configured = provider({ ...input.options, ...(input.mapped ? { mapProfileToUser: async profile => { mapperInputs.push(profile); return input.mapped; } } : {}) });
      const result = await configured.getUserInfo({ idToken: await profileToken(input.profile), accessToken: input.accessToken });
      profiles.push({ ...input, result, subject: configured.accountSubject({ profile: result.data }), requests, mapperInputs });
    }
    requests = [];
    let customCalls = 0, mapperCalls = 0;
    const customResult = { user: { id: "application-owner", name: "Application Owner", email: "application@example.test", emailVerified: true }, data: { source: "application" } };
    const configuredCustom = provider({ getUserInfo: async () => { customCalls++; return customResult; }, mapProfileToUser: async () => { mapperCalls++; return { name: "Unused" }; } });
    const custom = { result: await configuredCustom.getUserInfo({ accessToken: "ordinary-access" }), calls: customCalls, mapperCalls, requests };
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    jwks = { keys: [{ ...await exportJWK(publicKey), kid: "ordinary-microsoft-key", alg: "RS256" }] };
    const signed = [];
    for (const input of [
      { tenant: "common", tid: "ordinary-tenant", audience: metadata.clientId },
      { tenant: "organizations", tid: "ordinary-tenant", audience: metadata.secondaryClientId },
      { tenant: "consumers", tid: "9188040d-6c67-4c5b-b112-36a304b66dad", audience: metadata.clientId },
      { tenant: "OrdinaryTenant", tid: "OrdinaryTenant", audience: metadata.clientId },
    ]) {
      requests = [];
      const authority = "https://ordinary-authority.example.test";
      const configured = provider({ tenantId: input.tenant, authority: `${authority}///`, clientId: [metadata.clientId, metadata.secondaryClientId], disableProfilePhoto: true });
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({ ...base, tid: input.tid, nonce: "ordinary-nonce" }).setProtectedHeader({ alg: "RS256", kid: "ordinary-microsoft-key" }).setIssuer(`${authority}/${input.tid}/v2.0`).setAudience(input.audience).setIssuedAt(now).setExpirationTime(now + 3600).sign(privateKey);
      const verified = await verifyProviderIdToken(configured, token, "ordinary-nonce");
      signed.push({ ...input, authority, verified, requests });
    }
    return json({ version, metadata, authorization, grants, profiles, custom, signed });
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  if (!output) throw new Error("Provide the Social Microsoft capture output path");
  writeFileSync(output, JSON.stringify(await captureSocialMicrosoft(), null, 2) + "\n");
}
