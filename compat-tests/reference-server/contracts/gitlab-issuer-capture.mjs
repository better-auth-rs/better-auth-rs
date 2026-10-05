import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";

const clientId = "ordinary-gitlab-client";
const clientSecret = "ordinary-gitlab-secret";
const callbackURL = "https://app.example.test/api/auth/callback/gitlab";
const codeVerifier = "ordinary-gitlab-code-verifier-at-least-forty-three-characters";
const state = "ordinary-gitlab-state";
const profile = {
  id: 12345,
  username: "gitlab-reader",
  name: "GitLab Reader",
  email: "gitlab-reader@example.test",
  avatar_url: "https://images.example.test/gitlab-reader.png",
  email_verified: true,
  state: "active",
  locked: false,
};
const tokenResponse = {
  access_token: "ordinary-access",
  refresh_token: "ordinary-refresh",
  token_type: "Bearer",
  scope: "read_user",
};

async function provider(options) {
  const context = await betterAuth({
    baseURL: "https://app.example.test",
    secret: "ordinary-gitlab-issuer-secret-at-least-32-characters",
    logger: { disabled: true },
    telemetry: { enabled: false },
    socialProviders: { gitlab: { clientId, clientSecret, ...options } },
  }).$context;
  const configured = context.socialProviders.find((value) => value.id === "gitlab");
  assert.ok(configured, "Expected the configured GitLab provider");
  return configured;
}

export async function captureGitLabIssuer() {
  const version = (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version;
  assert.equal(version, "1.7.6");
  const cases = [];
  for (const [name, options] of [
    ["omitted", {}],
    ["empty", { issuer: "" }],
    ["self-hosted", { issuer: "https://gitlab.example.test" }],
    ["trailing-slash", { issuer: "https://gitlab.example.test/" }],
    ["subpath", { issuer: "https://gitlab.example.test///forge//" }],
  ]) {
    const configured = await provider(options);
    const authorizationURL = (await configured.createAuthorizationURL({
      state, codeVerifier, redirectURI: callbackURL,
    })).href;
    const requests = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign(async (input, init) => {
      const request = new Request(input, init);
      const body = await request.text();
      requests.push({
        url: request.url,
        method: request.method,
        contentType: request.headers.get("content-type"),
        authorization: request.headers.get("authorization"),
        body: body ? Object.fromEntries(new URLSearchParams(body)) : null,
      });
      const path = new URL(request.url).pathname;
      if (request.method === "POST" && path.endsWith("/oauth/token")) return Response.json(tokenResponse);
      if (request.method === "GET" && path.endsWith("/api/v4/user")) return Response.json(profile);
      throw new Error(`Unexpected GitLab fixture request: ${request.method} ${request.url}`);
    }, originalFetch);
    try {
      const codeTokens = await configured.validateAuthorizationCode({
        code: "ordinary-code", codeVerifier, redirectURI: callbackURL,
      });
      const refreshTokens = await configured.refreshAccessToken("ordinary-refresh");
      const userInfo = await configured.getUserInfo({ accessToken: "ordinary-access" });
      assert.ok(userInfo, "Expected the ordinary active GitLab profile");
      assert.equal(requests.length, 3, "Expected code, refresh, and profile requests");
      cases.push({ name, options, authorizationURL, requests, codeTokens, refreshTokens, userInfo });
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
  // Compare complete JSON-visible results; token helpers also own undefined-valued fields.
  return JSON.parse(JSON.stringify({ version, clientId, clientSecret, callbackURL, codeVerifier, state, profile, tokenResponse, cases }));
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the GitLab issuer fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureGitLabIssuer(), null, 2)}\n`);
}
