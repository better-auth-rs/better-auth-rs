import { expect, spyOn, test } from "bun:test";
import { salesforce } from "../node_modules/@better-auth/core/dist/social-providers/salesforce.mjs";
import { logger } from "../node_modules/@better-auth/core/dist/env/logger.mjs";

const clientId = "ordinary-client";
const clientSecret = "ordinary-client-secret";
const redirectURI = "http://app.example.test/api/auth/callback/salesforce";
const codeVerifier = "ordinary-salesforce-verifier-with-at-least-43-characters";
const profile = {
  sub: "https://login.salesforce.com/id/ordinary-org/salesforce-owner",
  user_id: "salesforce-owner", organization_id: "ordinary-org",
  name: "Salesforce Owner", email: "salesforce-owner@example.test", email_verified: true,
  photos: { picture: "https://images.example.test/salesforce.png", thumbnail: "https://images.example.test/salesforce-small.png" },
};
const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
type Options = Partial<Parameters<typeof salesforce>[0]>;
const provider = (options: Options = {}) => salesforce({ clientId, clientSecret, ...options });
const authInput = { state: "ordinary-state", codeVerifier, redirectURI };
const endpoints = [
  { options: {}, host: "login.salesforce.com" },
  { options: { environment: "sandbox" }, host: "test.salesforce.com" },
  { options: { environment: "sandbox", loginUrl: "ordinary.my.salesforce.com" }, host: "ordinary.my.salesforce.com" },
] satisfies { options: Options; host: string }[];

async function withHTTP(
  data: unknown, status: number,
  run: (requests: { path: string; method: string; authorization: string | null; contentType: string | null; body: string }[], sourceURLs: string[]) => Promise<void>,
) {
  const requests: Parameters<typeof run>[0] = [];
  const sourceURLs: string[] = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const path = new URL(request.url).pathname;
    const body = await request.text();
    requests.push({ path, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), body });
    if (path.endsWith("/token")) {
      const refresh = new URLSearchParams(body).get("grant_type") === "refresh_token";
      return Response.json({ access_token: refresh ? "rotated-access" : "ordinary-access", refresh_token: refresh ? "rotated-refresh" : "ordinary-refresh", token_type: "Bearer", scope: refresh ? "refreshed-scope" : "ordinary-scope" });
    }
    return Response.json(data, { status });
  } });
  const original = globalThis.fetch;
  globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    expect(endpoints.map((item) => item.host)).toContain(url.hostname);
    expect(["/services/oauth2/token", "/services/oauth2/userinfo"]).toContain(url.pathname);
    sourceURLs.push(url.href);
    return original(new URL(url.pathname, server.url), init);
  }, original);
  try { await run(requests, sourceURLs); } finally { globalThis.fetch = original; await server.stop(true); }
}

test("uses pinned Better Auth core 1.7.6", async () => {
  expect((await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version).toBe("1.7.6");
});

for (const endpoint of endpoints) {
  test(`salesforce ${endpoint.host} endpoints and both client-secret-post grants`, async () => {
    const configured = provider(endpoint.options);
    const authorization = await configured.createAuthorizationURL(authInput);
    expect(authorization.origin + authorization.pathname).toBe(`https://${endpoint.host}/services/oauth2/authorize`);
    await withHTTP(profile, 200, async (requests, sourceURLs) => {
      const code = await configured.validateAuthorizationCode({ code: "ordinary-code", codeVerifier, redirectURI });
      const refresh = await configured.refreshAccessToken("ordinary-refresh");
      expect(code.accessToken).toBe("ordinary-access");
      expect(code.scopes).toEqual(["ordinary-scope"]);
      expect(refresh.accessToken).toBe("rotated-access");
      expect(refresh.refreshToken).toBe("rotated-refresh");
      expect(refresh.scopes).toEqual(["refreshed-scope"]);
      const result = await configured.getUserInfo({ accessToken: "ordinary-access" });
      expect(normalized(result)).toEqual({ user: { name: profile.name, email: profile.email, image: profile.photos.picture, emailVerified: true }, data: profile });
      expect(requests).toHaveLength(3);
      expect(sourceURLs).toEqual([`https://${endpoint.host}/services/oauth2/token`, `https://${endpoint.host}/services/oauth2/token`, `https://${endpoint.host}/services/oauth2/userinfo`]);
      for (const request of requests.slice(0, 2)) {
        expect(request.path).toBe("/services/oauth2/token");
        expect(request.method).toBe("POST");
        expect(request.authorization).toBeNull();
        expect(request.contentType).toBe("application/x-www-form-urlencoded");
      }
      expect(Object.fromEntries(new URLSearchParams(requests[0]!.body))).toEqual({ grant_type: "authorization_code", code: "ordinary-code", code_verifier: codeVerifier, redirect_uri: redirectURI, client_id: clientId, client_secret: clientSecret });
      expect(Object.fromEntries(new URLSearchParams(requests[1]!.body))).toEqual({ grant_type: "refresh_token", refresh_token: "ordinary-refresh", client_id: clientId, client_secret: clientSecret });
      expect(requests[2]).toEqual({ path: "/services/oauth2/userinfo", method: "GET", authorization: "Bearer ordinary-access", contentType: null, body: "" });
    });
  });
}

for (const sample of [
  { name: "default", options: {}, scopes: undefined, expected: "openid email profile" },
  { name: "append in order", options: { scope: ["api", "email"] }, scopes: ["refresh_token", "api"], expected: "openid email profile api email refresh_token api" },
  { name: "disabled defaults", options: { disableDefaultScope: true, scope: ["api"] }, scopes: ["refresh_token"], expected: "api refresh_token" },
  { name: "empty scopes", options: { disableDefaultScope: true }, scopes: undefined, expected: null },
]) {
  test(`salesforce ${sample.name} scopes and PKCE`, async () => {
    const configured = provider({ ...sample.options, prompt: "consent" });
    const url = await configured.createAuthorizationURL({ ...authInput, scopes: sample.scopes, loginHint: "ordinary@example.test", additionalParams: { request_marker: "ordinary" } });
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier))).toString("base64url");
    expect(Object.fromEntries(url.searchParams)).toEqual({ response_type: "code", client_id: clientId, state: authInput.state, ...(sample.expected === null ? {} : { scope: sample.expected }), redirect_uri: redirectURI, code_challenge_method: "S256", code_challenge: challenge, request_marker: "ordinary" });
  });
}

test("salesforce configured redirect wins authorization and code exchange", async () => {
  const configured = provider({ redirectURI: "http://app.example.test/configured-callback" });
  expect((await configured.createAuthorizationURL(authInput)).searchParams.get("redirect_uri")).toBe("http://app.example.test/configured-callback");
  await withHTTP(profile, 200, async (requests) => {
    await configured.validateAuthorizationCode({ code: "ordinary-code", codeVerifier, redirectURI });
    expect(new URLSearchParams(requests[0]!.body).get("redirect_uri")).toBe("http://app.example.test/configured-callback");
  });
});

for (const field of ["clientId", "clientSecret", "codeVerifier"] as const) {
  test(`salesforce authorization requires ${field}`, async () => {
    const errors: unknown[][] = [];
    const spy = spyOn(logger, "error").mockImplementation((...args) => { errors.push(args); });
    try {
      const configured = provider(field === "codeVerifier" ? {} : { [field]: "" });
      await expect(configured.createAuthorizationURL({ ...authInput, ...(field === "codeVerifier" ? { codeVerifier: "" } : {}) })).rejects.toThrow(field === "codeVerifier" ? "codeVerifier is required for Salesforce" : "CLIENT_ID_AND_SECRET_REQUIRED");
      expect(errors).toEqual(field === "codeVerifier" ? [] : [["Client Id and Client Secret are required for Salesforce. Make sure to provide them in the options."]]);
    } finally { spy.mockRestore(); }
  });
}

const profiles = [
  { name: "picture", photos: profile.photos, email: profile.email, image: profile.photos.picture, verified: true },
  { name: "empty picture uses thumbnail", photos: { picture: "", thumbnail: profile.photos.thumbnail }, email: null, image: profile.photos.thumbnail, verified: undefined },
  { name: "null picture uses thumbnail", photos: { picture: null, thumbnail: profile.photos.thumbnail }, email: undefined, image: profile.photos.thumbnail, verified: null },
  { name: "omitted photos", photos: undefined, email: profile.email, image: undefined, verified: false },
  { name: "empty photos", photos: {}, email: profile.email, image: undefined, verified: undefined },
  { name: "null thumbnail", photos: { thumbnail: null }, email: profile.email, image: null, verified: undefined },
  { name: "empty thumbnail", photos: { thumbnail: "" }, email: profile.email, image: "", verified: undefined },
];
for (const sample of profiles) {
  test(`salesforce profile ${sample.name}`, async () => {
    const raw = normalized({ ...profile, photos: sample.photos, email: sample.email, email_verified: sample.verified });
    await withHTTP(raw, 200, async (requests) => {
      const result = await provider().getUserInfo({ accessToken: "ordinary-access" });
      expect(normalized(result)).toEqual(normalized({ user: { name: profile.name, email: sample.email, image: sample.image, emailVerified: sample.verified ?? false }, data: raw }));
      expect(Object.hasOwn(result!.user, "id")).toBe(false);
      expect(requests).toHaveLength(1);
    });
  });
}

test("salesforce awaits the raw-profile mapper and applies its fields last", async () => {
  const events: string[] = [];
  const started = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  await withHTTP(profile, 200, async (requests) => {
    const configured = provider({ mapProfileToUser: async (raw) => {
      expect(raw).toEqual(profile); expect(requests).toHaveLength(1);
      events.push("map:start"); started.resolve(); await resume.promise; events.push("map:end");
      return { name: "Mapped Salesforce Owner", email: null, image: null, emailVerified: false };
    } });
    const result = configured.getUserInfo({ accessToken: "ordinary-access" }).then((value) => { events.push("returned"); return value; });
    await started.promise;
    expect(events).toEqual(["map:start"]);
    resume.resolve();
    expect(await result).toEqual({ user: { name: "Mapped Salesforce Owner", email: null, image: null, emailVerified: false }, data: profile });
    expect(events).toEqual(["map:start", "map:end", "returned"]);
  });
});

for (const mode of ["http503", "mapper"] as const) {
  test(`salesforce default ${mode} failure logs and returns null`, async () => {
    const error = new Error("Ordinary Salesforce mapper failed");
    const errors: unknown[][] = [];
    const events: string[] = [];
    const spy = spyOn(logger, "error").mockImplementation((...args) => { errors.push(args); });
    try {
      await withHTTP(profile, mode === "http503" ? 503 : 200, async () => {
        const configured = provider({ mapProfileToUser: async () => { events.push("mapper"); throw error; } });
        expect(await configured.getUserInfo({ accessToken: "ordinary-access" })).toBeNull();
        expect(events).toEqual(mode === "http503" ? [] : ["mapper"]);
        expect(errors).toEqual(mode === "http503" ? [["Failed to fetch user info from Salesforce"]] : [["Failed to fetch user info from Salesforce:", error]]);
      });
    } finally { spy.mockRestore(); }
  });
}

for (const mode of ["success", "null", "error"] as const) {
  test(`salesforce custom handler ${mode} runs outside the default HTTP, mapper and catch`, async () => {
    const error = new Error("Ordinary custom Salesforce profile failed");
    const events: string[] = [];
    const logs = spyOn(logger, "error").mockImplementation(() => {});
    const custom = { user: { name: "Custom Owner", email: profile.email, emailVerified: false }, data: profile };
    try {
      await withHTTP(profile, 200, async (requests) => {
        const configured = provider({ mapProfileToUser: async () => { events.push("mapper"); return {}; }, getUserInfo: async () => { events.push("custom"); if (mode === "error") throw error; return mode === "null" ? null : custom; } });
        const response = configured.getUserInfo({ accessToken: "ordinary-access" });
        if (mode === "error") await expect(response).rejects.toBe(error);
        else expect(await response).toBe(mode === "null" ? null : custom);
        expect(events).toEqual(["custom"]); expect(requests).toEqual([]); expect(logs).not.toHaveBeenCalled();
      });
    } finally { logs.mockRestore(); }
  });
}
