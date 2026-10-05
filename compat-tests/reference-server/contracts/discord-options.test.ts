import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";

async function discord(options: Record<string, unknown> = {}) {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe("1.7.6");
  const context = await betterAuth({
    secret: "discord-options-contract-secret-at-least-32-characters",
    baseURL: "https://app.example.test",
    logger: { disabled: true },
    telemetry: { enabled: false },
    socialProviders: {
      discord: { clientId: "client", clientSecret: "secret", ...options },
    },
  }).$context;
  const provider = context.socialProviders.find(value => value.id === "discord");
  if (!provider) throw new Error("Missing Discord provider");
  return provider;
}

test("discord authorization omits standalone hints and gates configured permissions", async () => {
  const cases: {
    configuredBot: boolean;
    requestedBot: boolean;
    permissions?: number;
    requestPermissions?: string;
    expectedPermissions?: string;
    requestHints?: boolean;
  }[] = [
    { configuredBot: false, requestedBot: false },
    { configuredBot: false, requestedBot: false, permissions: 8 },
    { configuredBot: true, requestedBot: false, permissions: 0, expectedPermissions: "0" },
    { configuredBot: false, requestedBot: true, permissions: 8, expectedPermissions: "8" },
    { configuredBot: true, requestedBot: false, permissions: 8, requestPermissions: "16", expectedPermissions: "16" },
    { configuredBot: false, requestedBot: false, permissions: 8, requestPermissions: "16", expectedPermissions: "16" },
    { configuredBot: true, requestedBot: false },
    { configuredBot: false, requestedBot: false, requestHints: true },
  ];
  for (const sample of cases) {
    const provider = await discord({
      scope: sample.configuredBot ? ["bot"] : undefined,
      permissions: sample.permissions,
    });
    const url = await provider.createAuthorizationURL({
      state: "ordinary-state",
      codeVerifier: "ordinary-code-verifier-at-least-forty-three-characters",
      redirectURI: "https://app.example.test/callback/discord",
      scopes: sample.requestedBot ? ["bot"] : undefined,
      loginHint: "reader@example.test",
      idTokenNonce: "ordinary-nonce",
      additionalParams: {
        ...(sample.requestPermissions === undefined ? {} : { permissions: sample.requestPermissions }),
        ...(sample.requestHints ? { login_hint: "request@example.test", prompt: "consent" } : {}),
        request_marker: "ordinary",
      },
    });
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: "code",
      client_id: "client",
      state: "ordinary-state",
      scope: sample.configuredBot || sample.requestedBot ? "identify email bot" : "identify email",
      redirect_uri: "https://app.example.test/callback/discord",
      prompt: sample.requestHints ? "consent" : "none",
      ...(sample.requestHints ? { login_hint: "request@example.test" } : {}),
      request_marker: "ordinary",
      ...(sample.expectedPermissions === undefined ? {} : { permissions: sample.expectedPermissions }),
    });
  }
});

test("discord code and refresh use client-secret-post without verifier or device ID", async () => {
  const provider = await discord({ redirectURI: "https://app.example.test/configured-callback" });
  const originalFetch = globalThis.fetch;
  const requests: unknown[] = [];
  globalThis.fetch = Object.assign(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const request = new Request(input, init);
    requests.push({
      url: request.url,
      method: request.method,
      authorization: request.headers.get("authorization"),
      contentType: request.headers.get("content-type"),
      accept: request.headers.get("accept"),
      body: Object.fromEntries(new URLSearchParams(await request.text())),
    });
    return Response.json({ access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer" });
  }, originalFetch);
  try {
    const code = await provider.validateAuthorizationCode({
      code: "ordinary-code",
      redirectURI: "https://app.example.test/callback/discord",
      codeVerifier: "ordinary-code-verifier-at-least-forty-three-characters",
      deviceId: "ordinary-device",
    });
    const refresh = await provider.refreshAccessToken!("ordinary-refresh");
    expect(code.accessToken).toBe("ordinary-access");
    expect(refresh.accessToken).toBe("ordinary-access");
    const common = {
      url: "https://discord.com/api/oauth2/token",
      method: "POST",
      authorization: null,
      contentType: "application/x-www-form-urlencoded",
      accept: "application/json",
    };
    expect(requests).toEqual([
      {
        ...common,
        body: {
          grant_type: "authorization_code",
          code: "ordinary-code",
          redirect_uri: "https://app.example.test/configured-callback",
          client_id: "client",
          client_secret: "secret",
        },
      },
      {
        ...common,
        body: {
          grant_type: "refresh_token",
          refresh_token: "ordinary-refresh",
          client_id: "client",
          client_secret: "secret",
        },
      },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
