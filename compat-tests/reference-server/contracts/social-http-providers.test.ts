import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json";

type ProviderId = keyof typeof fixture.providers;
const tokens = { accessToken: "ordinary-local-profile-token" };

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
    : id === "cloudflare" ? { success: true, result: profile } : profile,
) {
  const events: string[] = [];
  const requests: { path: string; method: string; authorization: string | null; body?: string }[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      events.push("http");
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
      return Response.json(responseBody);
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

for (const id of ["gitlab", "spotify", "huggingface", "polar", "vercel", "figma", "dropbox", "kick", "linkedin", "slack", "naver", "linear", "cloudflare"] as const) {
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
      });
      expect(`${url.origin}${url.pathname}`).toBe(data.authorizationEndpoint);
      expect(Object.fromEntries(url.searchParams)).toEqual({
        response_type: "code",
        client_id: fixture.clientId,
        state: fixture.state,
        redirect_uri: redirectURI,
        ...(["linkedin", "slack", "naver", "linear"].includes(id) ? {} : {
          code_challenge_method: "S256",
          code_challenge: fixture.codeChallenge,
        }),
        ...("loginHint" in scopeCase && !["slack", "naver"].includes(id) ? { login_hint: scopeCase.loginHint } : {}),
        ...("additionalParams" in scopeCase ? scopeCase.additionalParams : {}),
        ...(scopeCase.scope === null ? {} : { scope: scopeCase.scope }),
        ...("tokenAccessType" in scopeCase ? { token_access_type: scopeCase.tokenAccessType } : {}),
        ...("prompt" in scopeCase.options && scopeCase.options.prompt
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

for (const id of ["figma", "kick", "linkedin", "slack", "naver", "linear"] as const) {
  for (const grant of ["code", "refresh"] as const) {
    test(`${id} ${grant} grant sends configured client authentication and the original parameters over HTTP`, async () => {
      const data = fixture.providers[id];
      const contract = data.tokenContract;
      const requests: unknown[] = [];
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(request) {
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
        const configured = await provider(id, { clientSecret: fixture.clientSecret });
        const result = grant === "code"
          ? await configured.validateAuthorizationCode(contract.code)
          : await configured.refreshAccessToken!(contract.refresh.refreshToken);
        expect(requests).toEqual([{
          path: tokenPath,
          method: "POST",
          authorization: contract.authorization,
          contentType: "application/x-www-form-urlencoded",
          body: {
            ...(id !== "figma" ? { client_id: fixture.clientId, client_secret: fixture.clientSecret } : {}),
            ...(grant === "code" ? {
              grant_type: "authorization_code",
              code: contract.code.code,
              ...(["linkedin", "slack", "naver", "linear"].includes(id) ? {} : { code_verifier: contract.code.codeVerifier }),
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
