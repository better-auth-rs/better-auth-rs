import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
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
    requests: { path: string; method: string; authorization: string | null }[];
  }) => Promise<void>,
) {
  const events: string[] = [];
  const requests: { path: string; method: string; authorization: string | null }[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      events.push("http");
      requests.push({
        path: new URL(request.url).pathname,
        method: request.method,
        authorization: request.headers.get("authorization"),
      });
      return Response.json(profile);
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
  return [{
    path: localUserInfoPath(id),
    method: "GET",
    authorization: `Bearer ${tokens.accessToken}`,
  }];
}

test("uses pinned Better Auth core 1.7.6", async () => {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe(fixture.version);
});

for (const id of ["gitlab", "spotify", "huggingface", "polar"] as const) {
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
      });
      expect(`${url.origin}${url.pathname}`).toBe(data.authorizationEndpoint);
      expect(Object.fromEntries(url.searchParams)).toEqual({
        response_type: "code",
        client_id: fixture.clientId,
        state: fixture.state,
        redirect_uri: redirectURI,
        code_challenge_method: "S256",
        code_challenge: fixture.codeChallenge,
        ...(scopeCase.scope === null ? {} : { scope: scopeCase.scope }),
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
