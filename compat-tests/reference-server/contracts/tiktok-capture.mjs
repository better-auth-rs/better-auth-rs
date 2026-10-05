import { readFileSync, writeFileSync } from "node:fs";
import { tiktok } from "@better-auth/core/social-providers";

const metadata = {
  clientKey: "ordinary-tiktok-key",
  clientSecret: "ordinary-tiktok-secret",
  callbackURL: "https://app.example.test/callback/tiktok",
  codeVerifier: "ordinary-tiktok-verifier-at-least-forty-three-characters",
  authorizationEndpoint: "https://www.tiktok.com/v2/auth/authorize",
  tokenEndpoint: "https://open.tiktokapis.com/v2/oauth/token/",
  profileEndpoint: "https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_large_url,display_name,username",
};
const credentials = { clientKey: metadata.clientKey, clientSecret: metadata.clientSecret };
const tokenResponse = {
  access_token: "ordinary-access", refresh_token: "ordinary-refresh",
  token_type: "Bearer", scope: "user.info.basic,user.info.profile",
};
const complete = { data: { user: {
  open_id: "ordinary-tiktok-user", display_name: "TikTok Reader", username: "reader",
  avatar_large_url: "https://images.example.test/tiktok.png", email: "reader@example.test",
} }, error: { code: "ok", message: "", log_id: "ordinary-log" } };

function profileRequest(request) {
  const url = new URL(request.url);
  return { method: request.method, path: url.pathname, query: Object.fromEntries(url.searchParams), authorization: request.headers.get("authorization") };
}

export async function captureTikTok() {
  const core = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8"));
  if (core.version !== "1.7.6") throw new Error("TikTok capture requires @better-auth/core 1.7.6");
  const authorization = [];
  for (const input of [
    { name: "defaults", options: {} },
    { name: "merged", options: { scope: ["configured", "user.info.profile"] }, scopes: ["request", "configured"] },
    { name: "empty", options: { disableDefaultScope: true, scope: [] }, scopes: [] },
    { name: "configured callback", options: { redirectURI: "https://app.example.test/configured-callback", prompt: "consent", authorizationEndpoint: "https://unused.example.test/authorize" }, additionalParams: { request_marker: "ordinary" } },
    { name: "additional hint", options: {}, additionalParams: { login_hint: "request@example.test", prompt: "consent" } },
  ]) {
    const provider = tiktok({ ...credentials, ...input.options });
    const url = await provider.createAuthorizationURL({
      state: "ordinary-state", redirectURI: metadata.callbackURL, codeVerifier: metadata.codeVerifier,
      scopes: input.scopes, loginHint: "reader@example.test", idTokenNonce: "ordinary-nonce",
      additionalParams: input.additionalParams,
    });
    authorization.push({ ...input, url: url.href });
  }
  const grants = [];
  const profiles = [];
  const originalFetch = globalThis.fetch;
  try {
    for (const input of [
      { name: "defaults", clientKey: metadata.clientKey, clientSecret: metadata.clientSecret },
      { name: "current credentials", clientKey: "updated-tiktok-key", clientSecret: "updated-tiktok-secret", redirectURI: "https://app.example.test/configured-callback" },
    ]) {
      const options = { ...credentials };
      const provider = tiktok(options);
      Object.assign(options, input);
      const requests = [];
      globalThis.fetch = Object.assign(async (input, init) => {
        const request = new Request(input, init);
        if (request.url !== metadata.tokenEndpoint) throw new Error(`Unexpected TikTok token URL: ${request.url}`);
        requests.push({ method: request.method, contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), authorization: request.headers.get("authorization"), body: Object.fromEntries(new URLSearchParams(await request.text())) });
        return Response.json(tokenResponse);
      }, originalFetch);
      const code = await provider.validateAuthorizationCode({ code: "ordinary-code", codeVerifier: metadata.codeVerifier, deviceId: "ordinary-device", redirectURI: metadata.callbackURL });
      const refresh = await provider.refreshAccessToken("ordinary-refresh");
      grants.push({ ...input, requests, tokens: [code, refresh] });
    }
    for (const input of [
      { name: "complete", mode: "default", profile: complete },
      { name: "username fallback", mode: "default", profile: { data: { user: { open_id: "ordinary-fallback-user", display_name: "", username: "Fallback", avatar_large_url: null } }, error: { code: "ok" } } },
      { name: "empty name", mode: "default", profile: { data: { user: { open_id: "ordinary-empty-user", email: "", username: "" } } } },
      { name: "ignored mapper", mode: "mapper", profile: complete },
      { name: "custom handler", mode: "custom", profile: complete },
    ]) {
      const requests = [];
      const mapperInputs = [];
      const calls = [];
      const explicitAccepts = [];
      const inputProfile = input.profile;
      globalThis.fetch = Object.assign(async (input, init) => {
        const request = new Request(input, init);
        if (request.url !== metadata.profileEndpoint) throw new Error(`Unexpected TikTok profile URL: ${request.url}`);
        requests.push(profileRequest(request));
        explicitAccepts.push(request.headers.get("accept"));
        return Response.json(inputProfile);
      }, originalFetch);
      const provider = tiktok({
        ...credentials,
        ...(input.mode === "default" ? {} : { mapProfileToUser: async raw => {
          mapperInputs.push(raw);
          return { name: "Mapped", email: "mapped@example.test", image: null, emailVerified: true };
        } }),
        ...(input.mode === "custom" ? { getUserInfo: async () => {
          calls.push("get");
          return { user: { id: "custom-tiktok-user", name: "Custom", email: "custom@example.test", image: null, emailVerified: true }, data: { data: { user: { open_id: "custom-tiktok-user" } } } };
        } } : {}),
      });
      const result = await provider.getUserInfo({ accessToken: "ordinary-access" });
      if (!result) throw new Error("Missing ordinary TikTok profile");
      profiles.push({ ...input, result, subject: await provider.accountSubject({ profile: result.data }), mapperInputs, calls, requests, explicitAccepts });
    }
    return { version: core.version, metadata, tokenResponse, authorization, grants, profiles };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const path = process.argv[2];
  if (!path) throw new Error("Provide the TikTok capture output path");
  writeFileSync(path, JSON.stringify(await captureTikTok(), null, 2) + "\n");
}
