import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json";

test("dropbox signs in with POST profile and refreshes using client_secret_post while retaining scope", async () => {
  const dropbox = fixture.providers.dropbox;
  const baseURL = "http://dropbox-refresh.example.test";
  const redirectURI = `${baseURL}/api/auth/callback/dropbox`;
  const initial = dropbox.tokenContract.response;
  const refreshed = {
    access_token: "dropbox-rotated-access",
    refresh_token: "dropbox-rotated-refresh",
    token_type: "Bearer",
    scope: "refreshed-scope",
  };
  const database: Record<string, Record<string, unknown>[]> = {
    user: [], account: [], session: [], verification: [],
  };
  const events: string[] = [];
  const tokenRequests: {
    path: string;
    method: string;
    authorization: string | null;
    contentType: string | null;
    body: Record<string, string>;
  }[] = [];
  const profileRequests: unknown[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      const text = await request.text();
      if (path === new URL(dropbox.tokenEndpoint).pathname) {
        const body = Object.fromEntries(new URLSearchParams(text));
        events.push(body.grant_type);
        tokenRequests.push({
          path, method: request.method,
          authorization: request.headers.get("authorization"),
          contentType: request.headers.get("content-type"), body,
        });
        return Response.json(body.grant_type === "refresh_token" ? refreshed : initial);
      }
      events.push("profile");
      profileRequests.push({ path, method: request.method, authorization: request.headers.get("authorization"), body: text });
      return Response.json(dropbox.profile);
    },
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(
    (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      return originalFetch(
        url === dropbox.tokenEndpoint || url === dropbox.userinfoEndpoint
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
      secret: "dropbox-refresh-contract-secret-at-least-32-characters",
      baseURL,
      database: memoryAdapter(database),
      logger: { disabled: true },
      telemetry: { enabled: false },
      socialProviders: {
        dropbox: { clientId: fixture.clientId, clientSecret: fixture.clientSecret, accessType: "offline" },
      },
    });
    const start = await auth.handler(new Request(`${baseURL}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: baseURL },
      body: JSON.stringify({ provider: "dropbox", callbackURL: `${baseURL}/welcome`, disableRedirect: true }),
    }));
    expect(start.status).toBe(200);
    const authorization = new URL((await start.json()).url);
    const state = authorization.searchParams.get("state");
    expect(state).toBeTruthy();
    expect(authorization.searchParams.get("token_access_type")).toBe("offline");
    expect(cookie(start)).not.toBe("");
    const callbackQuery = new URLSearchParams({ code: dropbox.tokenContract.code.code, state: state! });
    const callback = await auth.handler(new Request(`${redirectURI}?${callbackQuery}`, {
      headers: { cookie: cookie(start) },
    }));
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe(`${baseURL}/welcome`);
    expect(database.user).toHaveLength(1);
    expect(database.account).toHaveLength(1);
    expect(database.session).toHaveLength(1);
    expect(database.user[0]).toMatchObject(dropbox.defaultUser);
    const accountId = String(database.account[0]!.id);
    const storedAccount = {
      id: accountId,
      userId: database.user[0]!.id,
      providerId: "dropbox",
      accountId: dropbox.profile.account_id,
      scope: "ordinary-scope",
    };
    expect(database.account[0]).toMatchObject({
      ...storedAccount, accessToken: initial.access_token, refreshToken: initial.refresh_token,
    });
    const response = await auth.handler(new Request(`${baseURL}/api/auth/refresh-token`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: baseURL, cookie: cookie(callback) },
      body: JSON.stringify({ accountId }),
    }));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      accessToken: refreshed.access_token,
      refreshToken: refreshed.refresh_token,
      scope: "ordinary-scope",
      providerId: "dropbox",
      accountId,
    });
    expect(database.account[0]).toMatchObject({
      ...storedAccount, accessToken: refreshed.access_token, refreshToken: refreshed.refresh_token,
    });
    expect(database.user).toHaveLength(1);
    expect(database.account).toHaveLength(1);
    expect(database.session).toHaveLength(1);
    expect(events).toEqual(["authorization_code", "profile", "refresh_token"]);
    expect(profileRequests).toEqual([{
      path: new URL(dropbox.userinfoEndpoint).pathname,
      method: "POST",
      authorization: `Bearer ${initial.access_token}`,
      body: "",
    }]);
    expect(tokenRequests).toHaveLength(2);
    const verifier = tokenRequests[0]!.body.code_verifier;
    expect(verifier).toBeTruthy();
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    expect(challenge).toBe(authorization.searchParams.get("code_challenge"));
    const common = {
      path: new URL(dropbox.tokenEndpoint).pathname,
      method: "POST",
      authorization: null,
      contentType: "application/x-www-form-urlencoded",
    };
    const credentials = { client_id: fixture.clientId, client_secret: fixture.clientSecret };
    expect(tokenRequests).toEqual([
      { ...common, body: {
        grant_type: "authorization_code", code: dropbox.tokenContract.code.code,
        code_verifier: verifier, redirect_uri: redirectURI, ...credentials,
      } },
      { ...common, body: { grant_type: "refresh_token", refresh_token: initial.refresh_token, ...credentials } },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
    await server.stop(true);
  }
});
