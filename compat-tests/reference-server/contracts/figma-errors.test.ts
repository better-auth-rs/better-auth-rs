import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json";

const baseURL = "http://figma-errors.example.test";
const figma = fixture.providers.figma;
type Failure = "http503" | "mapper";

function cookieHeader(response: Response) {
  return response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
}

function setup(options: Record<string, unknown> = {}) {
  const database: Record<string, Record<string, unknown>[]> = {
    user: [], account: [], session: [], verification: [],
  };
  const events: string[] = [];
  let failure: Failure | undefined;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      if (new URL(request.url).pathname === new URL(figma.tokenEndpoint).pathname) {
        events.push("token");
        return Response.json(figma.tokenContract.response);
      }
      events.push("profile");
      return failure === "http503"
        ? Response.json({ error: "temporarily_unavailable" }, { status: 503 })
        : Response.json(figma.profile);
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
  const auth = betterAuth({
    secret: "figma-public-error-contract-secret-at-least-32-characters",
    baseURL,
    database: memoryAdapter(database),
    logger: { disabled: true },
    telemetry: { enabled: false },
    socialProviders: {
      figma: {
        clientId: fixture.clientId,
        clientSecret: fixture.clientSecret,
        mapProfileToUser: async () => {
          events.push("map");
          if (failure === "mapper") throw new Error("Ordinary profile mapper failed");
          return {};
        },
        ...options,
      },
    },
  });
  return {
    auth, database, events,
    setFailure(value: Failure) { failure = value; },
    async login() {
      const start = await auth.handler(new Request(`${baseURL}/api/auth/sign-in/social`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: baseURL },
        body: JSON.stringify({
          provider: "figma",
          callbackURL: `${baseURL}/welcome`,
          disableRedirect: true,
        }),
      }));
      expect(start.status).toBe(200);
      const authorization = new URL((await start.json()).url);
      const state = authorization.searchParams.get("state");
      expect(state).toBeTruthy();
      const cookie = cookieHeader(start);
      expect(cookie).not.toBe("");
      const query = new URLSearchParams({ code: figma.tokenContract.code.code, state: state! });
      return auth.handler(new Request(`${baseURL}/api/auth/callback/figma?${query}`, {
        headers: { cookie },
      }));
    },
    async close() {
      globalThis.fetch = originalFetch;
      await server.stop(true);
    },
  };
}

for (const failure of ["http503", "mapper"] as const) {
  test(`figma callback maps default ${failure} failure to unable_to_get_user_info without creating rows`, async () => {
    const sample = setup();
    try {
      sample.setFailure(failure);
      const response = await sample.login();
      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toBe(`${baseURL}/api/auth/error?error=unable_to_get_user_info`);
      expect(sample.database.user).toEqual([]);
      expect(sample.database.account).toEqual([]);
      expect(sample.database.session).toEqual([]);
      expect(sample.events).toEqual(failure === "mapper" ? ["token", "profile", "map"] : ["token", "profile"]);
    } finally {
      await sample.close();
    }
  });

  test(`figma account-info maps default ${failure} failure to FAILED_TO_GET_USER_INFO`, async () => {
    const sample = setup();
    try {
      const login = await sample.login();
      expect(login.status).toBe(302);
      expect(login.headers.get("location")).toBe(`${baseURL}/welcome`);
      expect(sample.database.user).toHaveLength(1);
      expect(sample.database.account).toHaveLength(1);
      expect(sample.events).toEqual(["token", "profile", "map"]);
      const accountId = String(sample.database.account[0]!.id);
      sample.events.length = 0;
      sample.setFailure(failure);
      const response = await sample.auth.handler(new Request(
        `${baseURL}/api/auth/account-info?${new URLSearchParams({ accountId })}`,
        { headers: { cookie: cookieHeader(login) } },
      ));
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
      });
      expect(sample.database.user).toHaveLength(1);
      expect(sample.database.account).toHaveLength(1);
      expect(sample.events).toEqual(failure === "mapper" ? ["profile", "map"] : ["profile"]);
    } finally {
      await sample.close();
    }
  });
}

test("figma custom getUserInfo preserves the original rejection outside the default catch", async () => {
  const error = new Error("Ordinary custom userinfo failed");
  const sample = setup({ getUserInfo: async () => { sample.events.push("custom"); throw error; } });
  try {
    const configured = (await sample.auth.$context).socialProviders.find((value) => value.id === "figma")!;
    await expect(configured.getUserInfo({ accessToken: figma.tokenContract.response.access_token })).rejects.toBe(error);
    expect(sample.events).toEqual(["custom"]);
  } finally {
    await sample.close();
  }
});

for (const endpoint of ["callback", "account-info"] as const) {
  test(`figma ${endpoint} returns 500 for an ordinary custom getUserInfo rejection`, async () => {
    let rejecting = endpoint === "callback";
    const sample = setup({
      getUserInfo: async () => {
        sample.events.push("custom");
        if (rejecting) throw new Error("Ordinary custom userinfo failed");
        return { user: figma.defaultUser, data: figma.profile };
      },
    });
    try {
      let response = await sample.login();
      if (endpoint === "account-info") {
        expect(response.status).toBe(302);
        expect(response.headers.get("location")).toBe(`${baseURL}/welcome`);
        expect(sample.events).toEqual(["token", "custom"]);
        expect(sample.database.user).toHaveLength(1);
        expect(sample.database.account).toHaveLength(1);
        expect(sample.database.session).toHaveLength(1);
        const accountId = String(sample.database.account[0]!.id);
        rejecting = true;
        sample.events.length = 0;
        response = await sample.auth.handler(new Request(
          `${baseURL}/api/auth/account-info?${new URLSearchParams({ accountId })}`,
          { headers: { cookie: cookieHeader(response) } },
        ));
      }
      expect(response.status).toBe(500);
      expect(response.headers.get("location")).toBeNull();
      expect(await response.text()).toBe("");
      const rows = endpoint === "callback" ? 0 : 1;
      expect(sample.database.user).toHaveLength(rows);
      expect(sample.database.account).toHaveLength(rows);
      expect(sample.database.session).toHaveLength(rows);
      expect(sample.events).toEqual(endpoint === "callback" ? ["token", "custom"] : ["custom"]);
    } finally {
      await sample.close();
    }
  });
}

test("figma authorization requires a nonempty client secret", async () => {
  const sample = setup({ clientSecret: "" });
  try {
    const configured = (await sample.auth.$context).socialProviders.find((value) => value.id === "figma")!;
    await expect(configured.createAuthorizationURL({
      state: fixture.state,
      codeVerifier: fixture.codeVerifier,
      redirectURI: figma.tokenContract.code.redirectURI,
    })).rejects.toThrow("CLIENT_ID_AND_SECRET_REQUIRED");
    expect(sample.events).toEqual([]);
  } finally {
    await sample.close();
  }
});
