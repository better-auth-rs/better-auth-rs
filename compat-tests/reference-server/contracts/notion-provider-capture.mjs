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
      notion: { clientId: fixture.clientId, clientSecret: fixture.clientSecret, ...options },
    },
  }).$context;
  const configured = context.socialProviders.find(value => value.id === "notion");
  if (!configured) throw new Error("Missing configured Notion provider");
  return configured;
}

export async function captureNotion() {
  const core = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8"));
  if (core.version !== "1.7.6" || fixture.version !== core.version) {
    throw new Error("Notion capture requires Better Auth core 1.7.6");
  }
  const endpoints = {
    authorizationEndpoint: "https://api.notion.com/v1/oauth/authorize",
    tokenEndpoint: "https://api.notion.com/v1/oauth/token",
    userinfoEndpoint: "https://api.notion.com/v1/users/me",
  };
  const profile = {
    object: "user", id: "9c23e19c-1eb9-4304-804e-19fdf3d14b83", type: "person",
    name: "Notion Owner", avatar_url: "https://images.example.test/notion.png",
    person: { email: "notion-owner@example.test" },
  };
  const mapperPatch = { name: "Mapped Notion Owner", image: null, emailVerified: true, locale: "zh-TW" };
  const customUser = { name: "Custom Notion Owner", email: "custom-notion@example.test", image: "https://images.example.test/custom-notion.png", emailVerified: true };
  const scopeCases = [];
  const authorizationURLs = [];
  for (const input of [
    { name: "defaults", options: {} },
    { name: "appended", options: { scope: ["extra", "openid"] }, requestScopes: ["request", "extra"], loginHint: "owner@example.test", idTokenNonce: "ordinary-notion-nonce", additionalParams: { request_marker: "ordinary" } },
    { name: "disabled", options: { disableDefaultScope: true, scope: ["extra"] }, requestScopes: ["request"] },
    { name: "noScopes", options: { disableDefaultScope: true, scope: [] }, requestScopes: [] },
    { name: "configuredPrompt", options: { prompt: "consent" } },
    { name: "emptyPrompt", options: { prompt: "" } },
  ]) {
    const configured = await provider(input.options);
    const url = await configured.createAuthorizationURL({
      state: fixture.state, codeVerifier: fixture.codeVerifier,
      redirectURI: "http://social-http.example.test/api/auth/callback/notion",
      scopes: input.requestScopes, loginHint: input.loginHint, idTokenNonce: input.idTokenNonce, additionalParams: input.additionalParams,
    });
    scopeCases.push({ ...input, scope: url.searchParams.get("scope"), prompt: url.searchParams.get("prompt") });
    authorizationURLs.push(url.href);
  }
  const tokens = { accessToken: "ordinary-local-profile-token" };
  const code = { code: "ordinary-code", codeVerifier: fixture.codeVerifier, redirectURI: "http://app.example.test/api/auth/callback/notion" };
  const refresh = { refreshToken: "ordinary-refresh" };
  const response = { access_token: "notion-access-token", refresh_token: "notion-refresh-token", token_type: "Bearer", scope: "openid profile" };
  let activeProfile = profile;
  const requests = [];
  const mapperInputs = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    requests.push({ url: request.url, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), notionVersion: request.headers.get("notion-version"), body: await request.text() });
    if (request.url === endpoints.userinfoEndpoint) return Response.json({ bot: { owner: { user: activeProfile } } });
    if (request.url === endpoints.tokenEndpoint) return Response.json(response);
    throw new Error(`Unexpected Notion capture endpoint: ${request.url}`);
  }, originalFetch);
  try {
    const configured = await provider();
    const defaultResult = await configured.getUserInfo(tokens);
    const normalProfileCases = [];
    for (const input of [
      { name: "empty name retains its value and omits absent avatar", profile: { object: "user", id: profile.id, type: "person", name: "", person: profile.person } },
      { name: "missing person email becomes null and preserves null avatar", profile: { ...profile, person: {}, avatar_url: null } },
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
      ...endpoints, subjectField: "id", scopeCases, profile,
      defaultUser: defaultResult?.user, mapperPatch, mappedUser: mappedResult?.user, customUser: customResult?.user,
      normalProfileCases,
      tokenContract: { authorization: grantRequests[0].authorization, refreshAuthorization: grantRequests[1].authorization, code, refresh, response },
      observations: { authorizationURLs, requests, mapperInputs, grantTokens: [codeTokens, refreshTokens] },
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  if (!output) throw new Error("Provide the Notion capture output path");
  const observed = JSON.parse(JSON.stringify(await captureNotion()));
  writeFileSync(output, JSON.stringify(observed, null, 2) + "\n");
}
