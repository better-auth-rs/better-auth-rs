import { expect, test } from "bun:test";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { captureRoblox } from "./roblox-provider-capture.mjs";
import { captureNotion } from "./notion-provider-capture.mjs";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json";

type ProviderId = keyof typeof fixture.providers;
const tokens = { accessToken: "ordinary-local-profile-token" };

async function captureRailway() {
  const endpoints = {
    authorizationEndpoint: "https://backboard.railway.com/oauth/auth",
    tokenEndpoint: "https://backboard.railway.com/oauth/token",
    userinfoEndpoint: "https://backboard.railway.com/oauth/me",
  };
  const profile = {
    sub: "railway-owner", name: "Railway Owner", email: "railway-owner@example.test",
    picture: "https://images.example.test/railway.png", email_verified: true,
  };
  const mapperPatch = { name: "Mapped Railway Owner", image: null, emailVerified: true, locale: "zh-TW" };
  const customUser = { name: "Custom Railway Owner", email: profile.email, image: "https://images.example.test/custom-railway.png", emailVerified: true };
  const scopes = [
    { name: "defaults", options: {} },
    { name: "appended", options: { scope: ["extra", "openid"] }, requestScopes: ["request", "extra"], loginHint: "owner@example.test", additionalParams: { request_marker: "ordinary" } },
    { name: "disabled", options: { disableDefaultScope: true, scope: ["extra"] }, requestScopes: ["request"] },
    { name: "noScopes", options: { disableDefaultScope: true, scope: [] }, requestScopes: [] },
  ];
  const scopeCases = [];
  const authorizationURLs = [];
  for (const input of scopes) {
    const configured = await provider("railway", input.options);
    const url = await configured.createAuthorizationURL({
      state: fixture.state, codeVerifier: fixture.codeVerifier,
      redirectURI: "http://social-http.example.test/api/auth/callback/railway",
      scopes: input.requestScopes, loginHint: input.loginHint, additionalParams: input.additionalParams,
    });
    scopeCases.push({ ...input, scope: url.searchParams.get("scope") });
    authorizationURLs.push(url.href);
  }
  const code = { code: "ordinary-code", codeVerifier: fixture.codeVerifier, redirectURI: "http://app.example.test/api/auth/callback/railway" };
  const refresh = { refreshToken: "ordinary-refresh" };
  const response = { access_token: "railway-access-token", refresh_token: "railway-refresh-token", token_type: "Bearer", scope: "openid railway:read" };
  let activeProfile: unknown = profile;
  const requests: { url: string; method: string; authorization: string | null; contentType: string | null; body: string }[] = [];
  const mapperInputs: unknown[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const request = new Request(input, init);
    requests.push({ url: request.url, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), body: await request.text() });
    if (request.url === endpoints.userinfoEndpoint) return Response.json(activeProfile);
    if (request.url === endpoints.tokenEndpoint) return Response.json(response);
    throw new Error(`Unexpected Railway capture endpoint: ${request.url}`);
  }, originalFetch);
  try {
    const configured = await provider("railway", { clientSecret: fixture.clientSecret });
    const defaultResult = await configured.getUserInfo(tokens);
    const normalProfileCases = [];
    for (const input of [
      { name: "empty name and omitted picture retain their values", profile: { sub: profile.sub, name: "", email: profile.email, email_verified: false } },
      { name: "null picture and upstream verification keep an unverified user", profile: { ...profile, picture: null, email_verified: true } },
    ]) {
      activeProfile = input.profile;
      const result = await configured.getUserInfo(tokens);
      normalProfileCases.push({ ...input, user: JSON.parse(JSON.stringify(result?.user)) });
    }
    activeProfile = profile;
    const mapped = await provider("railway", { mapProfileToUser: async (raw: unknown) => { mapperInputs.push(raw); return mapperPatch; } });
    const mappedResult = await mapped.getUserInfo(tokens);
    const codeTokens = await configured.validateAuthorizationCode(code);
    const refreshTokens = await configured.refreshAccessToken!(refresh.refreshToken);
    const grantRequests = requests.slice(-2);
    return {
      ...endpoints, subjectField: "sub", scopeCases, profile,
      defaultUser: defaultResult?.user, mapperPatch, mappedUser: mappedResult?.user, customUser,
      normalProfileCases,
      tokenContract: { authorization: grantRequests[0].authorization, code, refresh, response },
      observations: {
        authorizationURLs, requests, mapperInputs,
        grantTokens: [codeTokens, refreshTokens],
      },
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("railway pinned ordinary capture matches the shared fixture", async () => {
  const observed = JSON.parse(JSON.stringify(await captureRailway()));
  const output = process.env.RAILWAY_SOCIAL_FIXTURE_OUTPUT;
  if (output) writeFileSync(output, JSON.stringify(observed, null, 2) + "\n");
  else expect(observed).toEqual((fixture.providers as Record<string, unknown>).railway);
});

test("roblox pinned ordinary capture matches the shared fixture", async () => {
  const observed = JSON.parse(JSON.stringify(await captureRoblox()));
  expect(observed).toStrictEqual(fixture.providers.roblox);
});

test("notion pinned ordinary capture matches the shared fixture", async () => {
  const observed = JSON.parse(JSON.stringify(await captureNotion()));
  expect(observed).toStrictEqual(fixture.providers.notion);
});

function localUserInfoPath(id: ProviderId) {
  return `/${id}${new URL(fixture.providers[id].userinfoEndpoint).pathname}`;
}

async function provider(id: string, options: Record<string, unknown> = {}) {
  const context = await betterAuth({
    secret: "social-http-provider-contract-secret-at-least-32-characters",
    baseURL: "http://social-http.example.test",
    logger: { disabled: true },
    telemetry: { enabled: false },
    socialProviders: {
      [id]: { clientId: fixture.clientId, clientSecret: "local-client-secret", ...options },
    },
  }).$context;
  const configured = context.socialProviders.find((value) => value.id === id);
  if (!configured) throw new Error(`Missing configured ${id} provider`);
  return configured;
}

async function withUserInfo(
  id: ProviderId,
  profile: unknown,
  run: (local: {
    options: Record<string, unknown>;
    events: string[];
    requests: { path: string; method: string; authorization: string | null; body?: string }[];
  }) => Promise<void>,
  responseBody: unknown = id === "kick" ? { data: [profile] }
    : id === "linear" ? { data: { viewer: profile } }
    : id === "cloudflare" ? { success: true, result: profile }
    : id === "notion" ? { bot: { owner: { user: profile } } } : profile,
  status = 200,
) {
  const events: string[] = [];
  const requests: { path: string; method: string; authorization: string | null; body?: string }[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      events.push("http");
      if (id === "reddit") expect(request.headers.get("user-agent")).toBe("better-auth");
      if (id === "notion") expect(request.headers.get("notion-version")).toBe("2022-06-28");
      let body = request.method === "POST" ? await request.text() : undefined;
      if (id === "linear") {
        expect(request.headers.get("content-type")).toBe("application/json");
        const parsed = JSON.parse(body!);
        // Compare GraphQL tokens without indentation differences.
        parsed.query = parsed.query.replace(/\s+/g, " ").trim();
        body = JSON.stringify(parsed);
      }
      requests.push({
        path: new URL(request.url).pathname,
        method: request.method,
        authorization: request.headers.get("authorization"),
        ...(body === undefined ? {} : { body }),
      });
      return Response.json(responseBody, { status });
    },
  });
  const originalFetch = globalThis.fetch;
  if (id !== "gitlab") {
    // These pinned providers do not pass customFetchImpl to their userinfo requests.
    globalThis.fetch = Object.assign(
      (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input);
        return originalFetch(
          url === fixture.providers[id].userinfoEndpoint
            ? new URL(localUserInfoPath(id), server.url)
            : input,
          init,
        );
      },
      originalFetch,
    );
  }
  try {
    await run({
      options: id === "gitlab" ? { issuer: new URL("/gitlab//", server.url).href } : {},
      events,
      requests,
    });
  } finally {
    globalThis.fetch = originalFetch;
    await server.stop(true);
  }
}

function expectedRequest(id: ProviderId) {
  const data = fixture.providers[id];
  return [{
    path: localUserInfoPath(id),
    method: "profileMethod" in data ? data.profileMethod : "GET",
    authorization: `Bearer ${tokens.accessToken}`,
    ...("profileMethod" in data && data.profileMethod === "POST" ? { body: "profileBody" in data ? JSON.stringify(data.profileBody) : "" } : {}),
  }];
}

for (const [index, response] of fixture.providers.linear.missingViewerResponses.entries()) {
  test(`linear missing viewer response ${index} skips the mapper`, async () => {
    await withUserInfo("linear", null, async ({ options, events, requests }) => {
      const configured = await provider("linear", {
        ...options,
        mapProfileToUser: async () => { events.push("map"); return {}; },
      });
      expect(await configured.getUserInfo(tokens)).toBeNull();
      expect(events).toEqual(["http"]);
      expect(requests).toEqual(expectedRequest("linear"));
    }, response);
  });
}

test("linear retains additional authorization parameters and custom refresh precedence", async () => {
  const events: string[] = [];
  const configured = await provider("linear", {
    refreshAccessToken: async (token: string) => {
      events.push(token);
      return { accessToken: "custom-linear-access" };
    },
  });
  const url = await configured.createAuthorizationURL({
    state: fixture.state, codeVerifier: fixture.codeVerifier,
    redirectURI: "http://app.example.test/api/auth/callback/linear",
    loginHint: "owner@example.test", additionalParams: { ordinary: "value" },
  });
  expect(url.searchParams.get("ordinary")).toBe("value");
  expect(url.searchParams.get("login_hint")).toBe("owner@example.test");
  expect(await configured.refreshAccessToken!("ordinary-refresh")).toEqual({ accessToken: "custom-linear-access" });
  expect(events).toEqual(["ordinary-refresh"]);
});

test("uses pinned Better Auth core 1.7.6", async () => {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe(fixture.version);
});

for (const id of ["gitlab", "spotify", "huggingface", "polar", "vercel", "figma", "dropbox", "kick", "linkedin", "slack", "naver", "linear", "atlassian", "reddit", "kakao", "zoom", "cloudflare", "railway", "roblox", "notion"] as const) {
  const data = fixture.providers[id];
  for (const scopeCase of data.scopeCases) {
    test(`${id} ${scopeCase.name} scopes preserve order and PKCE`, async () => {
      const configured = await provider(id, scopeCase.options);
      const redirectURI = `http://social-http.example.test/api/auth/callback/${id}`;
      const url = await configured.createAuthorizationURL({
        state: fixture.state,
        codeVerifier: fixture.codeVerifier,
        redirectURI,
        scopes: "requestScopes" in scopeCase ? scopeCase.requestScopes : undefined,
        additionalParams: "additionalParams" in scopeCase ? scopeCase.additionalParams : undefined,
        loginHint: "loginHint" in scopeCase ? scopeCase.loginHint : undefined,
        idTokenNonce: "idTokenNonce" in scopeCase ? scopeCase.idTokenNonce : undefined,
      });
      expect(`${url.origin}${url.pathname}`).toBe(data.authorizationEndpoint);
      expect(Object.fromEntries(url.searchParams)).toEqual({
        response_type: "code",
        client_id: fixture.clientId,
        state: fixture.state,
        redirect_uri: redirectURI,
        ...(["linkedin", "slack", "naver", "linear", "reddit", "kakao", "roblox", "notion"].includes(id) || ("pkce" in scopeCase.options && scopeCase.options.pkce === false) ? {} : {
          code_challenge_method: "S256",
          code_challenge: fixture.codeChallenge,
        }),
        ...("loginHint" in scopeCase && !["slack", "naver", "atlassian", "reddit", "kakao", "zoom", "railway", "roblox"].includes(id) ? { login_hint: scopeCase.loginHint } : {}),
        ...("additionalParams" in scopeCase ? scopeCase.additionalParams : {}),
        ...("duration" in scopeCase ? { duration: scopeCase.duration } : {}),
        ...(scopeCase.scope === null ? {} : { scope: scopeCase.scope }),
        ...(id === "atlassian" ? { audience: "api.atlassian.com" } : {}),
        ...(id === "notion" ? { owner: "user" } : {}),
        ...("tokenAccessType" in scopeCase ? { token_access_type: scopeCase.tokenAccessType } : {}),
        ...(id === "notion"
          ? {}
          : id === "roblox" && "prompt" in scopeCase
          ? { prompt: scopeCase.prompt }
          : "prompt" in scopeCase.options && scopeCase.options.prompt
            ? { prompt: scopeCase.options.prompt }
            : {}),
      });
    });
  }

  test(`${id} maps a real localhost profile to its default user`, async () => {
    await withUserInfo(id, data.profile, async ({ options, events, requests }) => {
      const configured = await provider(id, options);
      const result = await configured.getUserInfo(tokens);
      expect(result).toEqual({ user: data.defaultUser, data: data.profile });
      expect(events).toEqual(["http"]);
      expect(requests).toEqual(expectedRequest(id));
    });
  });

  for (const profileCase of data.normalProfileCases) {
    test(`${id} ${profileCase.name}`, async () => {
      await withUserInfo(id, profileCase.profile, async ({ options, events, requests }) => {
        const configured = await provider(id, options);
        const result = await configured.getUserInfo(tokens);
        // JSON omits undefined fields but retains explicit nulls for the shared Rust fixture.
        expect(JSON.parse(JSON.stringify(result))).toStrictEqual({
          user: profileCase.user,
          data: profileCase.profile,
        });
        if (!Object.hasOwn(profileCase.user, "image")) {
          expect(result?.user.image).toBeUndefined();
        }
        expect(events).toEqual(["http"]);
        expect(requests).toEqual(expectedRequest(id));
      });
    });
  }

  test(`${id} awaits its async raw-profile mapper before returning the user`, async () => {
    await withUserInfo(id, data.profile, async ({ options, events, requests }) => {
      const started = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      let mappedProfile: unknown;
      const configured = await provider(id, {
        ...options,
        mapProfileToUser: async (raw: unknown) => {
          mappedProfile = raw;
          events.push("map:start");
          started.resolve();
          await release.promise;
          events.push("map:end");
          return data.mapperPatch;
        },
      });
      expect(events).toEqual([]);
      const pending = configured.getUserInfo(tokens).then((result) => {
        events.push("returned");
        return result;
      });
      await started.promise;
      try {
        expect(mappedProfile).toEqual(data.profile);
        expect(events).toEqual(["http", "map:start"]);
      } finally {
        release.resolve();
      }
      expect(await pending).toEqual({ user: data.mappedUser, data: data.profile });
      expect(events).toEqual(["http", "map:start", "map:end", "returned"]);
      expect(requests).toEqual(expectedRequest(id));
    });
  });

  test(`${id} custom getUserInfo skips HTTP and the mapper`, async () => {
    await withUserInfo(id, data.profile, async ({ options, events, requests }) => {
      const result = { user: data.customUser, data: data.profile };
      let receivedTokens: unknown;
      const configured = await provider(id, {
        ...options,
        getUserInfo: async (received: unknown) => {
          receivedTokens = received;
          events.push("custom");
          return result;
        },
        mapProfileToUser: async () => {
          throw new Error("Custom getUserInfo must skip the mapper");
        },
      });
      expect(await configured.getUserInfo(tokens)).toBe(result);
      expect(receivedTokens).toEqual(tokens);
      expect(events).toEqual(["custom"]);
      expect(requests).toEqual([]);
    });
  });
}

for (const rejected of fixture.providers.gitlab.rejectedStates) {
  test(`gitlab ${rejected.name} account state returns null before mapping`, async () => {
    const profile = { ...fixture.providers.gitlab.profile, ...rejected.patch };
    await withUserInfo("gitlab", profile, async ({ options, events, requests }) => {
      const configured = await provider("gitlab", {
        ...options,
        mapProfileToUser: async () => {
          events.push("map");
          return {};
        },
      });
      expect(await configured.getUserInfo(tokens)).toBeNull();
      expect(events).toEqual(["http"]);
      expect(requests).toEqual(expectedRequest("gitlab"));
    });
  });
}

for (const promptCase of fixture.promptCases) {
  test(`${promptCase.provider} handles configured consent prompt`, async () => {
    const configured = await provider(promptCase.provider, { prompt: promptCase.configured });
    const url = await configured.createAuthorizationURL({
      state: fixture.state,
      codeVerifier: fixture.codeVerifier,
      redirectURI: `http://social-http.example.test/api/auth/callback/${promptCase.provider}`,
    });
    expect(url.searchParams.get("prompt")).toBe(promptCase.expected);
  });
}

test("vercel leaves expired access tokens unchanged and reports unsupported refresh", async () => {
  let refreshCalls = 0;
  const auth = betterAuth({
    secret: "vercel-refresh-contract-secret-at-least-32-characters",
    baseURL: "http://vercel-refresh.example.test",
    logger: { disabled: true },
    telemetry: { enabled: false },
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    emailAndPassword: { enabled: true },
    socialProviders: {
      vercel: {
        clientId: fixture.clientId,
        clientSecret: "local-client-secret",
        refreshAccessToken: async () => {
          refreshCalls++;
          throw new Error("Vercel has no refresh method");
        },
      },
    },
  });
  const signup = await auth.api.signUpEmail({
    body: { name: "Owner", email: "owner@vercel-refresh.example.test", password: "Ordinary-password-1234" },
    asResponse: true,
  });
  expect(signup.status).toBe(200);
  const { user } = await signup.json();
  const headers = new Headers({
    cookie: signup.headers.getSetCookie().map(value => value.split(";")[0]).join("; "),
  });
  const context = await auth.$context;
  const configured = context.socialProviders.find(value => value.id === "vercel");
  expect(configured?.refreshAccessToken).toBeUndefined();
  const account = await context.adapter.create({
    model: "account",
    data: {
      userId: user.id, providerId: "vercel", accountId: "ordinary-vercel-owner",
      accessToken: "ordinary-access", refreshToken: "ordinary-refresh", scope: "ordinary-scope",
      accessTokenExpiresAt: new Date(Date.now() - 30_000), createdAt: new Date(), updatedAt: new Date(),
    },
  });
  const input = { headers, body: { accountId: account.id }, asResponse: true as const };
  const access = await auth.api.getAccessToken(input);
  expect(access.status).toBe(200);
  expect((await access.json()).accessToken).toBe("ordinary-access");
  const refresh = await auth.api.refreshToken(input);
  expect(refresh.status).toBe(400);
  expect(await refresh.json()).toStrictEqual({
    code: "TOKEN_REFRESH_NOT_SUPPORTED",
    message: "Provider vercel does not support token refreshing.",
  });
  const stored = await context.adapter.findOne({ model: "account", where: [{ field: "id", value: account.id }] });
  expect(stored).toStrictEqual(account);
  expect(refreshCalls).toBe(0);
});

test("figma returns null when its default userinfo mapper rejects", async () => {
  const data = fixture.providers.figma;
  await withUserInfo("figma", data.profile, async ({ options, events, requests }) => {
    const configured = await provider("figma", {
      ...options,
      mapProfileToUser: async () => {
        events.push("map");
        throw new Error("Ordinary profile mapper failed");
      },
    });
    expect(await configured.getUserInfo(tokens)).toBeNull();
    expect(events).toEqual(["http", "map"]);
    expect(requests).toEqual(expectedRequest("figma"));
  });
});

for (const id of ["figma", "kick", "linkedin", "slack", "naver", "linear", "atlassian", "reddit", "kakao", "zoom", "railway", "roblox", "notion"] as const) {
  for (const pkce of id === "zoom" ? [true, false] : [true]) {
    for (const grant of ["code", "refresh"] as const) {
      test(`${id} ${grant} grant${pkce ? "" : " without authorization PKCE"} sends configured client authentication and the original parameters over HTTP`, async () => {
        const data = fixture.providers[id];
        const contract = data.tokenContract;
        const requests: unknown[] = [];
        const server = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          async fetch(request) {
            if (id === "reddit") {
              expect(request.headers.get("accept")).toBe(fixture.providers.reddit.tokenContract.headers[grant].accept);
              if (grant === "code") expect(request.headers.get("user-agent")).toBe("better-auth");
              else expect(request.headers.get("user-agent")).not.toBe("better-auth");
            }
            requests.push({
              path: new URL(request.url).pathname,
              method: request.method,
              authorization: request.headers.get("authorization"),
              contentType: request.headers.get("content-type"),
              body: Object.fromEntries(new URLSearchParams(await request.text())),
            });
            return Response.json(contract.response);
          },
        });
        const originalFetch = globalThis.fetch;
        const tokenPath = new URL(data.tokenEndpoint).pathname;
        globalThis.fetch = Object.assign(
          (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
            const url = input instanceof Request ? input.url : String(input);
            return originalFetch(
              url === data.tokenEndpoint ? new URL(tokenPath, server.url) : input,
              init,
            );
          },
          originalFetch,
        );
        try {
          const configured = await provider(id, { clientSecret: fixture.clientSecret, ...(id === "zoom" ? { pkce } : {}) });
          const result = grant === "code"
            ? await configured.validateAuthorizationCode(contract.code)
            : await configured.refreshAccessToken!(contract.refresh.refreshToken);
          expect(requests).toEqual([{
            path: tokenPath,
            method: "POST",
            authorization: id === "notion" && grant === "refresh" && "refreshAuthorization" in contract
              ? contract.refreshAuthorization : contract.authorization,
            contentType: "application/x-www-form-urlencoded",
            body: {
              ...(!(["figma", "reddit", "railway"].includes(id) || (id === "notion" && grant === "code")) ? { client_id: fixture.clientId, client_secret: fixture.clientSecret } : {}),
              ...(grant === "code" ? {
                grant_type: "authorization_code",
                code: contract.code.code,
                ...(["linkedin", "slack", "naver", "linear", "reddit", "kakao", "roblox", "notion"].includes(id) ? {} : { code_verifier: contract.code.codeVerifier }),
                redirect_uri: contract.code.redirectURI,
              } : {
                grant_type: "refresh_token",
                refresh_token: contract.refresh.refreshToken,
              }),
            },
          }]);
          expect(result).toMatchObject({
            accessToken: contract.response.access_token,
            refreshToken: contract.response.refresh_token,
            tokenType: contract.response.token_type,
            scopes: contract.response.scope.split(" "),
          });
        } finally {
          globalThis.fetch = originalFetch;
          await server.stop(true);
        }
      });
    }
  }

}

for (const authCase of fixture.providers.cloudflare.tokenAuthCases) {
  for (const grant of ["code", "refresh"] as const) {
    test(`cloudflare ${authCase.name} ${grant} uses the configured token endpoint authentication`, async () => {
      const expected = authCase.requests[grant === "code" ? 0 : 1];
      const requests: unknown[] = [];
      const server = Bun.serve({
        hostname: "127.0.0.1", port: 0,
        async fetch(request) {
          requests.push({
            path: new URL(request.url).pathname, method: request.method,
            authorization: request.headers.get("authorization"),
            contentType: request.headers.get("content-type"),
            body: Object.fromEntries(new URLSearchParams(await request.text())),
          });
          return Response.json({access_token: "ordinary-access", refresh_token: "ordinary-refresh", expires_in: 3600, token_type: "Bearer", scope: "user-details.read"});
        },
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input);
        return originalFetch(url === fixture.providers.cloudflare.tokenEndpoint
          ? new URL("/oauth2/token", server.url) : input, init);
      }, originalFetch);
      try {
        const configured = await provider("cloudflare", {
          ...authCase.options,
          clientSecret: "clientSecret" in authCase.options ? authCase.options.clientSecret : undefined,
        });
        const result = grant === "code"
          ? await configured.validateAuthorizationCode({code: "ordinary-code", codeVerifier: "ordinary-verifier", redirectURI: "http://app.example.test/api/auth/callback/cloudflare", deviceId: "ordinary-device"})
          : await configured.refreshAccessToken!("ordinary-refresh");
        expect(requests).toEqual([expected]);
        expect(result).toMatchObject({accessToken: "ordinary-access", refreshToken: "ordinary-refresh", tokenType: "Bearer", scopes: ["user-details.read"]});
      } finally {
        globalThis.fetch = originalFetch;
        await server.stop(true);
      }
    });
  }
}

for (const [index, rejected] of fixture.providers.cloudflare.rejectedResponses.entries()) {
  test(`cloudflare ordinary API response ${index} returns null without mapping`, async () => {
    await withUserInfo("cloudflare", null, async ({ options, events }) => {
      const configured = await provider("cloudflare", {
        ...options,
        mapProfileToUser: async () => { events.push("map"); return {}; },
      });
      expect(await configured.getUserInfo(tokens)).toBeNull();
      expect(events).toEqual(["http"]);
    }, rejected.response);
  });
}

test("cloudflare custom refresh callback skips its default token request", async () => {
  const calls: string[] = [];
  const result = {accessToken: "custom-access", scopes: ["custom-scope"]};
  const configured = await provider("cloudflare", {
    refreshAccessToken: async (token: string) => { calls.push(token); return result; },
  });
  expect(await configured.refreshAccessToken!("ordinary-refresh")).toBe(result);
  expect(calls).toEqual(["ordinary-refresh"]);
});

test("cloudflare profile mapper errors propagate unchanged", async () => {
  const error = new Error("Ordinary Cloudflare mapper failed");
  await withUserInfo("cloudflare", fixture.providers.cloudflare.profile, async ({ options, events }) => {
    const configured = await provider("cloudflare", {
      ...options,
      mapProfileToUser: async () => { events.push("map"); throw error; },
    });
    await expect(configured.getUserInfo(tokens)).rejects.toBe(error);
    expect(events).toEqual(["http", "map"]);
  });
});

test("cloudflare custom profile errors bypass HTTP and the mapper", async () => {
  const error = new Error("Ordinary custom userinfo failed");
  await withUserInfo("cloudflare", fixture.providers.cloudflare.profile, async ({ options, events }) => {
    const configured = await provider("cloudflare", {
      ...options,
      getUserInfo: async () => { events.push("custom"); throw error; },
      mapProfileToUser: async () => { events.push("map"); return {}; },
    });
    await expect(configured.getUserInfo(tokens)).rejects.toBe(error);
    expect(events).toEqual(["custom"]);
  });
});


test("cloudflare ignores request hints and parameters while preserving configured URL options", async () => {
  const data = fixture.providers.cloudflare.requestParameters;
  const configured = await provider("cloudflare", data.options);
  const url = await configured.createAuthorizationURL(data.input);
  expect(Object.fromEntries(url.searchParams)).toEqual(data.authorization);
});


test("atlassian ignores an absent access token and a null profile before mapping", async () => {
  await withUserInfo("atlassian", null, async ({ options, events, requests }) => {
    const configured = await provider("atlassian", {
      ...options,
      mapProfileToUser: async () => { events.push("map"); return {}; },
    });
    expect(await configured.getUserInfo({})).toBeNull();
    expect(await configured.getUserInfo({ accessToken: "" })).toBeNull();
    expect(events).toEqual([]);
    expect(requests).toEqual([]);
    expect(await configured.getUserInfo(tokens)).toBeNull();
    expect(events).toEqual(["http"]);
    expect(requests).toEqual(expectedRequest("atlassian"));
  });
});

test("atlassian custom userinfo and refresh callbacks retain precedence", async () => {
  const events: string[] = [];
  const configured = await provider("atlassian", {
    getUserInfo: async (request: unknown) => { expect(request).toEqual({}); events.push("custom"); return null; },
    mapProfileToUser: async () => { throw new Error("Custom userinfo must skip mapping"); },
    refreshAccessToken: async (token: string) => { events.push(token); return { accessToken: "custom-atlassian-access" }; },
  });
  expect(await configured.getUserInfo({})).toBeNull();
  expect(await configured.refreshAccessToken!("ordinary-refresh")).toEqual({ accessToken: "custom-atlassian-access" });
  expect(events).toEqual(["custom", "ordinary-refresh"]);
});

for (const options of [{ clientId: "", clientSecret: "secret" }, { clientId: "client", clientSecret: "" }]) {
  test(`atlassian requires both credentials before authorization: ${JSON.stringify(options)}`, async () => {
    const configured = await provider("atlassian", options);
    await expect(configured.createAuthorizationURL({ state: fixture.state, codeVerifier: fixture.codeVerifier, redirectURI: "http://app.example.test/api/auth/callback/atlassian" })).rejects.toThrow("CLIENT_ID_AND_SECRET_REQUIRED");
  });
}

for (const emailCase of fixture.providers.reddit.emailCases) {
  test(`reddit ${emailCase.name} applies placeholder after the awaited mapper`, async () => {
    const data = fixture.providers.reddit;
    await withUserInfo("reddit", data.profile, async ({ options, events }) => {
      const configured = await provider("reddit", {
        ...options,
        mapProfileToUser: async (raw: unknown) => {
          expect(raw).toEqual(data.profile);
          events.push("map");
          return { ...emailCase.patch, ...("undefinedEmail" in emailCase ? { email: undefined } : {}) };
        },
      });
      expect(await configured.getUserInfo(tokens)).toEqual({
        user: { ...data.defaultUser, email: emailCase.email }, data: data.profile,
      });
      expect(events).toEqual(["http", "map"]);
    });
  });
}

test("reddit preserves an ordinary mapper error", async () => {
  const failure = new Error("Ordinary Reddit mapper failed");
  await withUserInfo("reddit", fixture.providers.reddit.profile, async ({ options, events }) => {
    const configured = await provider("reddit", {
      ...options,
      mapProfileToUser: async () => { events.push("map"); throw failure; },
    });
    await expect(configured.getUserInfo(tokens)).rejects.toBe(failure);
    expect(events).toEqual(["http", "map"]);
  });
});

test("reddit HTTP 503 returns no profile before mapping", async () => {
  await withUserInfo("reddit", fixture.providers.reddit.profile, async ({ options, events }) => {
    const configured = await provider("reddit", {
      ...options,
      mapProfileToUser: async () => { events.push("map"); return {}; },
    });
    expect(await configured.getUserInfo(tokens)).toBeNull();
    expect(events).toEqual(["http"]);
  }, { message: "Ordinary unavailable response" }, 503);
});

test("kakao custom refresh callback retains precedence", async () => {
  const events: string[] = [];
  const configured = await provider("kakao", {
    refreshAccessToken: async (token: string) => {
      events.push(token);
      return { accessToken: "custom-kakao-access" };
    },
  });
  expect(await configured.refreshAccessToken!("ordinary-refresh")).toEqual({ accessToken: "custom-kakao-access" });
  expect(events).toEqual(["ordinary-refresh"]);
});

for (const status of [200, 503]) {
  test(`zoom ordinary mapper failure and HTTP ${status} retain the shared profile boundary`, async () => {
    const failure = new Error("Ordinary Zoom mapper failed");
    await withUserInfo("zoom", fixture.providers.zoom.profile, async ({ options, events }) => {
      const configured = await provider("zoom", {
        ...options,
        mapProfileToUser: async () => { events.push("map"); throw failure; },
      });
      if (status === 503) {
        expect(await configured.getUserInfo(tokens)).toBeNull();
        expect(events).toEqual(["http"]);
      } else {
        await expect(configured.getUserInfo(tokens)).rejects.toBe(failure);
        expect(events).toEqual(["http", "map"]);
      }
    }, status === 503 ? { message: "Ordinary unavailable response" } : fixture.providers.zoom.profile, status);
  });
}
