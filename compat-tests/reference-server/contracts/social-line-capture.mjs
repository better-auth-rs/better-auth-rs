import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { SignJWT } from "jose";

const clientId = "1234567891";
const clientSecret = "ordinary-line-fixture-secret-012345";
const callbackURL = "https://social-line.example.test/api/auth/callback/line";
const codeVerifier = "ordinary-line-code-verifier-012345678901234567890123456789";
const endpoints = {
  authorization: "https://access.line.me/oauth2/v2.1/authorize",
  token: "https://api.line.me/oauth2/v2.1/token",
  userinfo: "https://api.line.me/oauth2/v2.1/userinfo",
  verify: "https://api.line.me/oauth2/v2.1/verify",
};

async function provider(options = {}) {
  const context = await betterAuth({
    secret: "social-line-capture-secret-at-least-32-characters",
    baseURL: "https://social-line.example.test",
    telemetry: { enabled: false }, logger: { disabled: true },
    socialProviders: { line: { clientId, clientSecret, ...options } },
  }).$context;
  const configured = context.socialProviders.find(value => value.id === "line");
  if (!configured) throw new Error("Missing Social LINE provider");
  return configured;
}

export async function captureSocialLine() {
  const metadata = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8"));
  if (metadata.version !== "1.7.6") throw new Error("Social LINE capture requires @better-auth/core 1.7.6");
  const authorization = [];
  for (const input of [
    { name: "defaults", options: {} },
    { name: "appended", options: { scope: ["extra", "openid"] }, requestScopes: ["request", "extra"], loginHint: "line@example.test" },
    { name: "disabled", options: { disableDefaultScope: true, scope: ["extra"] }, requestScopes: ["request"] },
    { name: "empty", options: { disableDefaultScope: true, scope: [] }, requestScopes: [] },
    { name: "configured prompt", options: { prompt: "consent" } },
  ]) {
    const configured = await provider(input.options);
    const url = await configured.createAuthorizationURL({
      state: "ordinary-state", codeVerifier, redirectURI: callbackURL,
      scopes: input.requestScopes, loginHint: input.loginHint, idTokenNonce: "ordinary-nonce",
    });
    authorization.push({ ...input, url: url.href });
  }
  const profile = { sub: "ordinary-line-user", name: "LINE Reader", email: "line@example.test", picture: "https://images.example.test/line.png", email_verified: true, locale: "ja-JP" };
  const profileInputs = [
    { source: "token", profile },
    { source: "token", profile: { ...profile, name: null, picture: null } },
    { source: "token", profile: { sub: profile.sub, email: profile.email } },
    { source: "userinfo", profile },
  ];
  const profiles = [];
  const requests = [];
  const mapperInputs = [];
  let activeProfile = profile;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    requests.push({ url: request.url, method: request.method, headers: Object.fromEntries(request.headers), body: await request.text() });
    if (request.url === endpoints.userinfo) return Response.json(activeProfile);
    if (request.url === endpoints.token) return Response.json({ access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer", scope: "openid profile email" });
    if (request.url === endpoints.verify) return Response.json({ ...profile, aud: clientId, nonce: "ordinary-nonce" });
    throw new Error(`Unexpected Social LINE capture URL: ${request.url}`);
  }, originalFetch);
  try {
    const configured = await provider();
    for (const input of profileInputs) {
      activeProfile = input.profile;
      const idToken = input.source === "token" ? await new SignJWT(input.profile)
        .setProtectedHeader({ alg: "HS256" }).sign(new TextEncoder().encode(clientSecret)) : undefined;
      const result = await configured.getUserInfo({ idToken, accessToken: "ordinary-access" });
      profiles.push({ ...input, result });
    }
    activeProfile = profile;
    const mapped = await provider({ mapProfileToUser: async raw => {
      mapperInputs.push(raw);
      return { name: "Mapped LINE Reader", image: null, emailVerified: true };
    } });
    const mappedResult = await mapped.getUserInfo({ accessToken: "ordinary-access" });
    const token = await new SignJWT({ ...profile, aud: clientId, nonce: "ordinary-nonce" })
      .setProtectedHeader({ alg: "HS256" }).sign(new TextEncoder().encode(clientSecret));
    const verified = await configured.idToken.verify(token, "ordinary-nonce");
    const codeTokens = await configured.validateAuthorizationCode({ code: "ordinary-code", codeVerifier, redirectURI: callbackURL, deviceId: "ordinary-device" });
    const refreshTokens = await configured.refreshAccessToken("ordinary-refresh");
    return {
      version: metadata.version, clientId, clientSecret, callbackURL, endpoints,
      codeChallenge: new URL(authorization[0].url).searchParams.get("code_challenge"),
      authorization, profiles, mappedResult, mapperInputs, verified,
      requests, grantTokens: [codeTokens, refreshTokens],
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const path = process.argv[2];
  if (!path) throw new Error("Provide the Social LINE capture output path");
  writeFileSync(path, JSON.stringify(await captureSocialLine(), null, 2) + "\n");
}
