import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";

const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/social-http-providers-1.7.6.json", import.meta.url), "utf8"));

async function provider(options = {}) {
  const context = await betterAuth({
    secret: "social-http-provider-contract-secret-at-least-32-characters",
    baseURL: "http://social-http.example.test",
    logger: { disabled: true },
    telemetry: { enabled: false },
    socialProviders: {
      roblox: { clientId: fixture.clientId, clientSecret: fixture.clientSecret, ...options },
    },
  }).$context;
  const configured = context.socialProviders.find(value => value.id === "roblox");
  if (!configured) throw new Error("Missing configured Roblox provider");
  return configured;
}

export async function captureRoblox() {
  const core = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8"));
  if (core.version !== "1.7.6" || fixture.version !== core.version) {
    throw new Error("Roblox capture requires Better Auth core 1.7.6");
  }
  const endpoints = {
    authorizationEndpoint: "https://apis.roblox.com/oauth/v1/authorize",
    tokenEndpoint: "https://apis.roblox.com/oauth/v1/token",
    userinfoEndpoint: "https://apis.roblox.com/oauth/v1/userinfo",
  };
  const profile = {
    sub: "1234567890", nickname: "Roblox Owner", preferred_username: "roblox-owner",
    picture: "https://images.example.test/roblox.png",
  };
  const mapperPatch = { name: "Mapped Roblox Owner", image: null, emailVerified: true, locale: "zh-TW" };
  const customUser = { name: "Custom Roblox Owner", email: "custom-roblox@example.test", image: "https://images.example.test/custom-roblox.png", emailVerified: true };
  const scopeCases = [];
  const authorizationURLs = [];
  for (const input of [
    { name: "defaults", options: {} },
    { name: "appended", options: { scope: ["extra", "openid"] }, requestScopes: ["request", "extra"], loginHint: "owner@example.test", additionalParams: { request_marker: "ordinary" } },
    { name: "disabled", options: { disableDefaultScope: true, scope: ["extra"] }, requestScopes: ["request"] },
    { name: "noScopes", options: { disableDefaultScope: true, scope: [] }, requestScopes: [] },
    { name: "configuredPrompt", options: { prompt: "consent" } },
    { name: "emptyPrompt", options: { prompt: "" } },
  ]) {
    const configured = await provider(input.options);
    const url = await configured.createAuthorizationURL({
      state: fixture.state, codeVerifier: fixture.codeVerifier,
      redirectURI: "http://social-http.example.test/api/auth/callback/roblox",
      scopes: input.requestScopes, loginHint: input.loginHint, additionalParams: input.additionalParams,
    });
    scopeCases.push({ ...input, scope: url.searchParams.get("scope"), prompt: url.searchParams.get("prompt") });
    authorizationURLs.push(url.href);
  }
  const tokens = { accessToken: "ordinary-local-profile-token" };
  const code = { code: "ordinary-code", codeVerifier: fixture.codeVerifier, redirectURI: "http://app.example.test/api/auth/callback/roblox" };
  const refresh = { refreshToken: "ordinary-refresh" };
  const response = { access_token: "roblox-access-token", refresh_token: "roblox-refresh-token", token_type: "Bearer", scope: "openid profile" };
  let activeProfile = profile;
  const requests = [];
  const mapperInputs = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    requests.push({ url: request.url, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), body: await request.text() });
    if (request.url === endpoints.userinfoEndpoint) return Response.json(activeProfile);
    if (request.url === endpoints.tokenEndpoint) return Response.json(response);
    throw new Error(`Unexpected Roblox capture endpoint: ${request.url}`);
  }, originalFetch);
  try {
    const configured = await provider();
    const defaultResult = await configured.getUserInfo(tokens);
    const normalProfileCases = [];
    for (const input of [
      { name: "empty nickname uses preferred username and omits absent picture", profile: { sub: profile.sub, nickname: "", preferred_username: "roblox-reader" } },
      { name: "empty display names remain empty and preserve null picture", profile: { ...profile, nickname: "", preferred_username: "", picture: null } },
    ]) {
      activeProfile = input.profile;
      const result = await configured.getUserInfo(tokens);
      normalProfileCases.push({ ...input, user: JSON.parse(JSON.stringify(result?.user)) });
    }
    activeProfile = profile;
    const mapped = await provider({ mapProfileToUser: async raw => { mapperInputs.push(raw); return mapperPatch; } });
    const mappedResult = await mapped.getUserInfo(tokens);
    const custom = await provider({ getUserInfo: async () => ({ user: customUser, data: profile }) });
    const customResult = await custom.getUserInfo(tokens);
    const codeTokens = await configured.validateAuthorizationCode(code);
    const refreshTokens = await configured.refreshAccessToken(refresh.refreshToken);
    const grantRequests = requests.slice(-2);
    return {
      ...endpoints, subjectField: "sub", scopeCases, profile,
      defaultUser: defaultResult?.user, mapperPatch, mappedUser: mappedResult?.user, customUser: customResult?.user,
      normalProfileCases,
      tokenContract: { authorization: grantRequests[0].authorization, code, refresh, response },
      observations: { authorizationURLs, requests, mapperInputs, grantTokens: [codeTokens, refreshTokens] },
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  if (!output) throw new Error("Provide the Roblox capture output path");
  const observed = JSON.parse(JSON.stringify(await captureRoblox()));
  writeFileSync(output, JSON.stringify(observed, null, 2) + "\n");
}
