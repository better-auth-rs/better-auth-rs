import { wechat } from "../node_modules/@better-auth/core/dist/social-providers/wechat.mjs";
import { APIError } from "better-auth/api";

const metadata = {
  version: "1.7.6", clientId: "ordinary-client", clientSecret: "ordinary-secret",
  authorizationEndpoint: "https://open.weixin.qq.com/connect/qrconnect",
  tokenEndpoint: "https://api.weixin.qq.com/sns/oauth2/access_token",
  refreshEndpoint: "https://api.weixin.qq.com/sns/oauth2/refresh_token",
  profileEndpoint: "https://api.weixin.qq.com/sns/userinfo", now: 1_700_000_000_000,
};
type Options = Partial<Parameters<typeof wechat>[0]>;
const provider = (options: Options = {}) => wechat({ clientId: metadata.clientId, clientSecret: metadata.clientSecret, ...options });
const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
const profile = { openid: "ordinary-openid", unionid: "ordinary-unionid", nickname: "Ordinary User", headimgurl: "https://images.example/avatar.png", privilege: [] };
const token = { accessToken: "ordinary-access", openid: profile.openid, unionid: profile.unionid };
const rawTokens = { access_token: "ordinary-access", refresh_token: "ordinary-refresh", expires_in: 7200, scope: "snsapi_login,snsapi_userinfo", openid: profile.openid, unionid: profile.unionid };
const authorizationInput = { state: "ordinary-state", redirectURI: "https://app.example/api/auth/callback/wechat", codeVerifier: "ordinary-verifier", loginHint: "ordinary@example.com", nonce: "ordinary-nonce", additionalParams: { theme: "light" } };
type RequestRecord = { url: string; method: string; authorization: string | null; contentType: string | null; accept: string | null; body: string };

async function withHTTP(raw: unknown, status: number, run: (requests: RequestRecord[], events: string[]) => Promise<unknown>) {
  const requests: RequestRecord[] = [];
  const events: string[] = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url);
    requests.push({ url: `https://api.weixin.qq.com${url.pathname}${url.search}`, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), body: await request.text() });
    events.push(url.pathname.endsWith("userinfo") ? "profile" : url.pathname.endsWith("refresh_token") ? "refresh" : "code");
    return Response.json(raw, { status });
  } });
  const original = globalThis.fetch;
  const allowed = new Set([metadata.tokenEndpoint, metadata.refreshEndpoint, metadata.profileEndpoint]);
  globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (!allowed.has(`${url.origin}${url.pathname}`)) throw new Error(`Unexpected WeChat URL: ${url.origin}${url.pathname}`);
    return original(new URL(url.pathname + url.search, server.url), init);
  }, original);
  try { return { ...await run(requests, events) as object, requests, events }; }
  finally { globalThis.fetch = original; await server.stop(true); }
}

export async function captureWeChat() {
  const version = (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version;
  const scopeCases = [];
  for (const [name, options, input] of [
    ["defaults", {}, authorizationInput],
    ["configured and requested scopes", { scope: ["snsapi_userinfo"], lang: "en", prompt: "consent" }, { ...authorizationInput, scopes: ["snsapi_login"], additionalParams: { lang: "cn", theme: "dark" } }],
    ["disabled defaults", { disableDefaultScope: true }, authorizationInput],
    ["configured redirect", { redirectURI: "https://app.example/custom/wechat", lang: "en" }, authorizationInput],
    ["empty redirect", { redirectURI: "" }, authorizationInput],
  ] as const) {
    scopeCases.push({ name, options, input, url: (await provider(options).createAuthorizationURL(input)).href });
  }
  const grants = [];
  const originalNow = Date.now;
  Date.now = () => metadata.now;
  try {
    for (const name of ["code", "refresh"]) {
      const input = name === "code" ? { code: "ordinary-code", redirectURI: authorizationInput.redirectURI, codeVerifier: "ordinary-verifier", deviceId: "ordinary-device" } : "ordinary-refresh";
      const rawResponse = name === "code" ? rawTokens : { ...rawTokens, access_token: "refreshed-access", refresh_token: "rotated-refresh", scope: "refreshed-scope" };
      grants.push({ name, input, rawResponse, ...await withHTTP(rawResponse, 200, async () => {
        const configured = provider();
        return { response: normalized(name === "code" ? await configured.validateAuthorizationCode(input as never) : await configured.refreshAccessToken(input as string)) };
      }) });
    }
  } finally { Date.now = originalNow; }
  const grantFailures = [];
  for (const grant of ["code", "refresh"]) for (const mode of ["application error", "HTTP 503"]) {
    const rawResponse = mode === "application error" ? { errcode: 40029, errmsg: "Ordinary expired authorization" } : { message: "Ordinary service unavailable" };
    const status = mode === "HTTP 503" ? 503 : 200;
    grantFailures.push({ grant, mode, status, rawResponse, ...await withHTTP(rawResponse, status, async () => {
      try {
        if (grant === "code") await provider().validateAuthorizationCode({ code: "ordinary-code", redirectURI: authorizationInput.redirectURI });
        else await provider().refreshAccessToken("ordinary-refresh");
        return { result: "unexpected success" };
      } catch (error) { return { error: { name: error.name, message: error.message } }; }
    }) });
  }
  const profileCases = [];
  for (const sample of [
    { name: "unionid placeholder", profile },
    { name: "openid placeholder", profile: { ...profile, unionid: undefined } },
    { name: "profile email", profile: { ...profile, email: "profile@example.com" } },
    { name: "mapped email", profile, mapperPatch: { email: "mapped@example.com", name: "Mapped User" } },
    { name: "mapped null", profile, mapperPatch: { email: null } },
    { name: "mapped empty", profile, mapperPatch: { email: "" } },
    { name: "mapped undefined", profile, mapperEmailMode: "undefined" },
    { name: "HTTP 503", profile, status: 503 },
    { name: "application error", profile: { errcode: 40003, errmsg: "Ordinary provider unavailable" } },
    { name: "saved account token", profile, token: { accessToken: "ordinary-access" } },
  ]) {
    profileCases.push({ status: 200, mapperPatch: {}, token, ...normalized(sample), ...await withHTTP(sample.profile, sample.status ?? 200, async (_, events) => {
      let mapperProfile: unknown;
      let mapperCalls = 0;
      const configured = provider({ mapProfileToUser: async (raw) => {
        mapperCalls++; mapperProfile = normalized(raw); events.push("mapper");
        return sample.mapperEmailMode === "undefined" ? { email: undefined } : sample.mapperPatch ?? {};
      } });
      const result = await configured.getUserInfo(sample.token ?? token);
      events.push("returned");
      return { result: normalized(result), mapperCalls, mapperProfile, emailOwn: result === null ? null : Object.hasOwn(result.user, "email"), emailUndefined: result === null ? null : result.user.email === undefined };
    }) });
  }
  const specialCases = [];
  for (const mode of ["custom success", "custom null", "custom error", "custom API error", "mapper error", "refresh custom"]) {
    specialCases.push({ mode, ...await withHTTP(profile, 200, async (_, events) => {
      const original = mode === "custom API error" ? new APIError("TOO_MANY_REQUESTS", { code: "ORDINARY_CALLBACK_LIMIT", message: "Ordinary callback limit" }) : new Error("Ordinary callback failure");
      const custom = { user: { id: profile.unionid, name: "Custom User", email: "custom@example.com", emailVerified: false }, data: { source: "custom" } };
      const options: Options = { mapProfileToUser: async () => { events.push("mapper"); throw original; } };
      if (mode.startsWith("custom")) options.getUserInfo = async () => {
        events.push("custom");
        if (mode.endsWith("error")) throw original;
        return mode === "custom null" ? null : custom;
      };
      if (mode === "refresh custom") options.refreshAccessToken = async (refreshToken) => { events.push(`custom:${refreshToken}`); return { accessToken: "custom-access" }; };
      try {
        const result = mode === "refresh custom" ? await provider(options).refreshAccessToken("ordinary-refresh") : await provider(options).getUserInfo(token);
        return { result: normalized(result) };
      } catch (error) { return { sameError: error === original, error: { message: error.message, status: error.status, body: error.body } }; }
    }) });
  }
  return normalized({ metadata: { ...metadata, version }, scopeCases, grants, grantFailures, profileCases, specialCases });
}

if (import.meta.main) console.log(JSON.stringify(await captureWeChat(), null, 2));
