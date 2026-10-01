import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json";

test("figma public refresh rotates tokens with Basic authentication and preserves the stored scope", async () => {
  const figma = fixture.providers.figma;
  const baseURL = "http://figma-refresh.example.test";
  const redirectURI = `${baseURL}/api/auth/callback/figma`;
  const initial = { ...figma.tokenContract.response, scope: "ordinary-scope" };
  const refreshed = {
    access_token: "figma-rotated-access",
    refresh_token: "figma-rotated-refresh",
    token_type: "Bearer",
    scope: "refreshed-scope",
  };
  const database: Record<string, Record<string, unknown>[]> = {
    user: [], account: [], session: [], verification: [],
  };
  const events: string[] = [];
  const requests: {
    path: string;
    method: string;
    authorization: string | null;
    body: Record<string, string>;
  }[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (path === new URL(figma.tokenEndpoint).pathname) {
        const body = Object.fromEntries(new URLSearchParams(await request.text()));
        events.push(body.grant_type);
        requests.push({ path, method: request.method, authorization: request.headers.get("authorization"), body });
        return Response.json(body.grant_type === "refresh_token" ? refreshed : initial);
      }
      events.push("profile");
      expect(path).toBe(new URL(figma.userinfoEndpoint).pathname);
      expect(request.headers.get("authorization")).toBe(`Bearer ${initial.access_token}`);
      return Response.json(figma.profile);
    },
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(
    (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      return originalFetch(
        url === figma.tokenEndpoint || url === figma.userinfoEndpoint
          ? new URL(new URL(url).pathname, server.url)
          : input,
        init,
      );
    },
    originalFetch,
  );
  const cookie = (response: Response) => response.headers.getSetCookie()
    .map((value) => value.split(";", 1)[0]).join("; ");
  try {
    const auth = betterAuth({
      secret: "figma-refresh-contract-secret-at-least-32-characters",
      baseURL,
      database: memoryAdapter(database),
      logger: { disabled: true },
      telemetry: { enabled: false },
      socialProviders: { figma: { clientId: fixture.clientId, clientSecret: fixture.clientSecret } },
    });
    const start = await auth.handler(new Request(`${baseURL}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: baseURL },
      body: JSON.stringify({ provider: "figma", callbackURL: `${baseURL}/welcome`, disableRedirect: true }),
    }));
    expect(start.status).toBe(200);
    const authorization = new URL((await start.json()).url);
    const state = authorization.searchParams.get("state");
    expect(state).toBeTruthy();
    expect(cookie(start)).not.toBe("");
    const callbackQuery = new URLSearchParams({ code: "ordinary-code", state: state! });
    const callback = await auth.handler(new Request(`${redirectURI}?${callbackQuery}`, {
      headers: { cookie: cookie(start) },
    }));
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe(`${baseURL}/welcome`);
    expect(database.user).toHaveLength(1);
    expect(database.account).toHaveLength(1);
    expect(database.session).toHaveLength(1);
    expect(database.account[0]!.scope).toBe("ordinary-scope");
    const accountId = String(database.account[0]!.id);
    const response = await auth.handler(new Request(`${baseURL}/api/auth/refresh-token`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: baseURL, cookie: cookie(callback) },
      body: JSON.stringify({ accountId }),
    }));
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      accessToken: refreshed.access_token,
      refreshToken: refreshed.refresh_token,
      scope: "ordinary-scope",
      providerId: "figma",
      accountId,
    });
    expect(database.account[0]).toMatchObject({
      id: accountId,
      accessToken: refreshed.access_token,
      refreshToken: refreshed.refresh_token,
      scope: "ordinary-scope",
    });
    expect(database.user).toHaveLength(1);
    expect(database.account).toHaveLength(1);
    expect(database.session).toHaveLength(1);
    expect(events).toEqual(["authorization_code", "profile", "refresh_token"]);
    expect(requests).toHaveLength(2);
    const verifier = requests[0]!.body.code_verifier;
    expect(verifier).toBeTruthy();
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    expect(challenge).toBe(authorization.searchParams.get("code_challenge"));
    const common = {
      path: new URL(figma.tokenEndpoint).pathname,
      method: "POST",
      authorization: figma.tokenContract.authorization,
    };
    expect(requests).toEqual([
      { ...common, body: { grant_type: "authorization_code", code: "ordinary-code", code_verifier: verifier, redirect_uri: redirectURI } },
      { ...common, body: { grant_type: "refresh_token", refresh_token: initial.refresh_token } },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
    await server.stop(true);
  }
});
