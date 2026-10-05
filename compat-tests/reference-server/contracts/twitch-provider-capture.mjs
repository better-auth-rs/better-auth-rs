import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { SignJWT } from "jose";

const clientId = "ordinary-twitch-client";
const clientSecret = "ordinary-twitch-secret-at-least-32-characters";
const clientKey = "ordinary-twitch-key";
const callbackURL = "https://app.example.test/api/auth/callback/twitch";
const codeVerifier = "ordinary-twitch-code-verifier-at-least-forty-three-characters";
const endpoints = {
  authorization: "https://id.twitch.tv/oauth2/authorize",
  token: "https://id.twitch.tv/oauth2/token",
};

async function provider(options = {}) {
  const context = await betterAuth({
    secret: "ordinary-twitch-contract-secret-at-least-32-characters",
    baseURL: "https://app.example.test",
    telemetry: { enabled: false }, logger: { disabled: true },
    socialProviders: { twitch: { clientId, clientSecret, clientKey, ...options } },
  }).$context;
  const configured = context.socialProviders.find(value => value.id === "twitch");
  if (!configured) throw new Error("Missing Twitch provider");
  return configured;
}

async function idToken(profile) {
  return new SignJWT(profile).setProtectedHeader({ alg: "HS256" })
    .sign(new TextEncoder().encode(clientSecret));
}

export async function captureTwitch() {
  const metadata = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8"));
  if (metadata.version !== "1.7.6") throw new Error("Twitch capture requires @better-auth/core 1.7.6");
  const authorization = [];
  for (const input of [
    { name: "defaults", options: {} },
    { name: "appended", options: { scope: ["extra", "openid"] }, requestScopes: ["request", "extra"], additionalParams: { request_marker: "ordinary" } },
    { name: "disabled", options: { disableDefaultScope: true, scope: ["extra"] }, requestScopes: ["request"] },
    { name: "empty scopes", options: { disableDefaultScope: true, scope: [] }, requestScopes: [] },
    { name: "configured claims", options: { claims: ["picture", "locale", "email", "locale"] } },
    { name: "empty claims", options: { claims: [] } },
    { name: "configured prompt", options: { prompt: "consent" } },
    { name: "configured endpoints", options: { authorizationEndpoint: "https://twitch.example.test/authorize?marker=configured", redirectURI: "https://app.example.test/configured-callback" } },
    { name: "request claims", options: {}, additionalParams: { claims: "{\"id_token\":{\"preferred_username\":null}}" } },
  ]) {
    const configured = await provider(input.options);
    const url = await configured.createAuthorizationURL({
      state: "ordinary-state", codeVerifier, redirectURI: callbackURL,
      scopes: input.requestScopes, loginHint: "twitch@example.test",
      idTokenNonce: "ordinary-nonce", additionalParams: input.additionalParams,
    });
    authorization.push({ ...input, url: url.href });
  }
  const profile = {
    sub: "ordinary-twitch-user", preferred_username: "Twitch Reader",
    email: "twitch@example.test", email_verified: true,
    picture: "https://images.example.test/twitch.png", locale: "en-US",
  };
  const profileInputs = [
    { name: "populated profile", profile },
    { name: "nullable display fields", profile: { ...profile, preferred_username: null, picture: null } },
    { name: "absent display fields", profile: { sub: profile.sub, email: profile.email, email_verified: true } },
  ];
  const profiles = [];
  const requests = [];
  const mapperInputs = [];
  const mapperPatch = { name: "Mapped Twitch Reader", image: null, emailVerified: false, locale: "en-GB" };
  const customResult = {
    user: { id: "ordinary-twitch-user", name: "Custom Twitch Reader", email: "custom-twitch@example.test", image: null, emailVerified: true, source: "custom" },
    data: { sub: profile.sub, source: "custom" },
  };
  const signed = await idToken(profile);
  const response = { access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer", scope: "user:read:email openid", id_token: signed };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    requests.push({ url: request.url, method: request.method, headers: Object.fromEntries(request.headers), body: await request.text() });
    if (request.url === endpoints.token) return Response.json(response);
    throw new Error(`Unexpected Twitch capture URL: ${request.url}`);
  }, originalFetch);
  try {
    const configured = await provider();
    for (const input of profileInputs) {
      const result = await configured.getUserInfo({ idToken: await idToken(input.profile), accessToken: "ordinary-access" });
      profiles.push({ ...input, result });
    }
    const mapped = await provider({ mapProfileToUser: async raw => { mapperInputs.push(raw); return mapperPatch; } });
    const mappedResult = await mapped.getUserInfo({ idToken: signed, accessToken: "ordinary-access" });
    let customCalls = 0;
    let customMapperCalls = 0;
    const custom = await provider({
      getUserInfo: async () => { customCalls += 1; return customResult; },
      mapProfileToUser: async () => { customMapperCalls += 1; return mapperPatch; },
    });
    const observedCustom = await custom.getUserInfo({ idToken: signed, accessToken: "ordinary-access" });
    const codeTokens = await configured.validateAuthorizationCode({ code: "ordinary-code", codeVerifier, deviceId: "ordinary-device", redirectURI: callbackURL });
    const refreshTokens = await configured.refreshAccessToken("ordinary-refresh");
    return {
      version: metadata.version, clientId, clientSecret, clientKey, callbackURL, codeVerifier,
      endpoints, authorization, profiles, mapperPatch, mapperInputs, mappedResult,
      customResult: observedCustom, customCalls, customMapperCalls,
      requests, grantTokens: [codeTokens, refreshTokens],
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  if (!output) throw new Error("Provide the Twitch capture output path");
  writeFileSync(output, JSON.stringify(await captureTwitch(), null, 2) + "\n");
}
