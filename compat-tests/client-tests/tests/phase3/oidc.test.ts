import { expect } from "bun:test";
import { control, issuer } from "../../support/oidc";
import { compatScenario } from "../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
async function configure(ctx: Context, mode = "valid", overrides = {}) {
  const identity = {
    email: ctx.uniqueEmail("oidc"),
    sub: ctx.uniqueToken("oidc-subject"),
  };
  await control("configure", { ...identity, mode, ...overrides });
  return identity;
}

async function login(ctx: Context, provider = "oidc") {
  const signIn = await ctx.actor().client.signIn.social({
    provider,
    callbackURL: "/oidc/done",
    errorCallbackURL: "/oidc/error",
  });
  expect(signIn.error).toBeNull();
  expect(signIn.data?.redirect).toBe(true);
  const authorization = new URL(signIn.data!.url);
  expect(authorization.origin).toBe(issuer);
  expect(authorization.pathname).toBe("/authorize");
  expect(authorization.searchParams.get("scope")).toBe(
    provider === "oauth-fallback" ? "email profile" : "openid email profile",
  );
  expect(authorization.searchParams.get("client_id")).toBe("oidc-client");
  expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
  expect(authorization.searchParams.get("code_challenge")).toBeTruthy();
  expect(Boolean(authorization.searchParams.get("nonce"))).toBe(
    !["oidc-no-nonce", "oauth-fallback"].includes(provider),
  );
  return finishAuthorization(ctx, authorization);
}

async function finishAuthorization(ctx: Context, authorization: URL) {
  const authorizationResponse = await fetch(authorization, {
    redirect: "manual",
  });
  expect(authorizationResponse.status).toBe(302);
  const callbackURL = authorizationResponse.headers.get("location");
  expect(callbackURL).toBeTruthy();
  return ctx.rawRequest({ path: callbackURL!, redirect: "manual" });
}

async function successfulSession(
  ctx: Context,
  identity: { email: string; sub: string; emailVerified?: boolean },
  provider = "oidc",
) {
  const session = await ctx.actor().client.getSession();
  expect(session.error).toBeNull();
  expect(session.data?.user.email).toBe(identity.email);
  expect(session.data?.user.emailVerified).toBe(identity.emailVerified ?? true);
  const accounts = await ctx.actor().client.listAccounts();
  expect(accounts.error).toBeNull();
  expect(accounts.data).toHaveLength(1);
  expect(accounts.data![0]!.providerId).toBe(provider);
  expect(accounts.data![0]!.accountId).toBe(identity.sub);
  return { session: ctx.snapshot(session), accounts: ctx.snapshot(accounts) };
}

compatScenario(
  "OIDC discovery verifies signed ID tokens and preserves subject identity across login",
  async (ctx) => {
    const identity = await configure(ctx);
    const first = await login(ctx);
    expect(first.status).toBe(302);
    expect(first.location).toBe("/oidc/done");
    const original = await successfulSession(ctx, identity);
    const before = await ctx.actor().client.getSession();
    await ctx.actor().client.signOut();
    const second = await login(ctx);
    expect(second.location).toBe("/oidc/done");
    const current = await ctx.actor().client.getSession();
    expect(current.data!.user.id).toBe(before.data!.user.id);
    expect(current.data!.session.id).not.toBe(before.data!.session.id);
    expect((await control("requests")).userinfo).toBe(0);
    return { first, original, second, current: ctx.snapshot(current) };
  },
);

compatScenario(
  "OIDC userinfo fallback selects sub instead of the profile id",
  async (ctx) => {
    const identity = await configure(ctx, "userinfo");
    const callback = await login(ctx);
    expect(callback.location).toBe("/oidc/done");
    const authenticated = await successfulSession(ctx, identity);
    expect((await control("requests")).userinfo).toBe(1);
    return { callback, authenticated };
  },
);

compatScenario(
  "OIDC verification configuration still permits userinfo when no ID token is returned",
  async (ctx) => {
    const identity = await configure(ctx, "no-id-token");
    const callback = await login(ctx);
    expect(callback.location).toBe("/oidc/done");
    const authenticated = await successfulSession(ctx, identity);
    expect((await control("requests")).userinfo).toBe(1);
    return { callback, authenticated };
  },
);

compatScenario(
  "OIDC rejects invalid signed claims, signatures, and missing userinfo subjects",
  async (ctx) => {
    const observations = [];
    for (const mode of [
      "wrong-issuer",
      "wrong-audience",
      "expired",
      "future-not-before",
      "wrong-signature",
      "wrong-nonce",
      "missing-nonce",
      "missing-subject",
      "callback-issuer",
    ]) {
      await configure(ctx, mode);
      const callback = await login(ctx);
      expect(callback.status).toBe(302);
      expect(callback.location).toBe(
        `/oidc/error?error=${mode === "callback-issuer" ? "issuer_mismatch" : "unable_to_get_user_info"}`,
      );
      const session = await ctx.actor().client.getSession();
      expect(session.error).toBeNull();
      expect(session.data).toBeNull();
      const requests = await control("requests");
      expect(requests.userinfo).toBe(mode === "missing-subject" ? 1 : 0);
      expect(requests.token).toBe(mode === "callback-issuer" ? 0 : 1);
      observations.push({ mode, callback, session: ctx.snapshot(session) });
    }
    return observations;
  },
);

compatScenario(
  "OIDC can explicitly disable nonce binding while retaining signature validation",
  async (ctx) => {
    const identity = await configure(ctx, "missing-nonce");
    const callback = await login(ctx, "oidc-no-nonce");
    expect(callback.location).toBe("/oidc/done");
    return {
      callback,
      authenticated: await successfulSession(ctx, identity, "oidc-no-nonce"),
    };
  },
);

compatScenario(
  "OIDC direct ID token sign-in verifies the supplied nonce and rejects forged signatures",
  async (ctx) => {
    const identity = await configure(ctx);
    const nonce = "client-provided-oidc-nonce";
    const { token } = await control("id-token", { nonce });
    const good = await ctx
      .actor()
      .client.signIn.social({ provider: "oidc", idToken: { token, nonce } });
    expect(good.error).toBeNull();
    const authenticated = await successfulSession(ctx, identity);
    await ctx.actor().client.signOut();
    const wrongNonce = await ctx.actor().client.signIn.social({
      provider: "oidc",
      idToken: { token, nonce: "other" },
    });
    expect(wrongNonce.error?.status).toBe(401);
    expect(wrongNonce.error?.code).toBe("INVALID_TOKEN");
    await configure(ctx, "wrong-signature");
    const forged = await control("id-token", { nonce });
    const wrongSignature = await ctx.actor().client.signIn.social({
      provider: "oidc",
      idToken: { token: forged.token, nonce },
    });
    expect(wrongSignature.error?.status).toBe(401);
    expect(wrongSignature.error?.code).toBe("INVALID_TOKEN");
    expect((await ctx.actor().client.getSession()).data).toBeNull();
    return {
      good: ctx.snapshot(good),
      authenticated,
      wrongNonce: ctx.snapshot(wrongNonce),
      wrongSignature: ctx.snapshot(wrongSignature),
    };
  },
);

compatScenario(
  "OIDC discovery failures leave no usable provider",
  async (ctx) => {
    const observations = [];
    for (const provider of [
      "oidc-unavailable",
      "oidc-missing-jwks",
      "oidc-invalid-issuer",
    ]) {
      const result = await ctx
        .actor()
        .client.signIn.social({ provider, callbackURL: "/oidc/done" });
      expect(result.error?.status).toBe(404);
      expect(result.error?.code).toBe("PROVIDER_NOT_FOUND");
      observations.push(ctx.snapshot(result));
    }
    return observations;
  },
);

compatScenario(
  "Generic OAuth keeps explicit endpoints when optional discovery fails",
  async (ctx) => {
    const identity = await configure(ctx, "userinfo");
    const callback = await login(ctx, "oauth-fallback");
    expect(callback.location).toBe("/oidc/done");
    const authenticated = await successfulSession(
      ctx,
      { ...identity, sub: "untrusted-profile-id" },
      "oauth-fallback",
    );
    expect((await control("requests")).userinfo).toBe(1);
    return { callback, authenticated };
  },
);

compatScenario(
  "OIDC resolves the account subject independently of mapped local profile fields",
  async (ctx) => {
    const identity = await configure(ctx, "mapped-image");
    const callback = await login(ctx, "oidc-mapped");
    expect(callback.location).toBe("/oidc/done");
    const authenticated = await successfulSession(
      ctx,
      {
        ...identity,
        sub: `external-${identity.sub}`,
        emailVerified: false,
      },
      "oidc-mapped",
    );
    const session = await ctx.actor().client.getSession();
    expect(session.data?.user.name).toBe("Mapped OIDC User");
    expect(session.data?.user.image).toBeNull();
    return { callback, authenticated, session: ctx.snapshot(session) };
  },
);

compatScenario(
  "Generic OAuth configuration and request parameters preserve reserved authorization fields",
  async (ctx) => {
    const identity = await configure(ctx);
    const signIn = await ctx.actor().client.signIn.social({
      provider: "oidc-parameters",
      callbackURL: "/oidc/done",
      errorCallbackURL: "/oidc/error",
      scopes: ["extra"],
      loginHint: identity.email,
      additionalParams: {
        tenant: "requested",
        prompt: "select_account",
        z_custom: "first",
        a_custom: "second",
      },
    });
    expect(signIn.error).toBeNull();
    const authorization = new URL(signIn.data!.url);
    expect(authorization.searchParams.get("scope")).toBe(
      "openid extra email profile",
    );
    expect(authorization.searchParams.get("tenant")).toBe("requested");
    expect(authorization.searchParams.get("z_custom")).toBe("first");
    expect(authorization.searchParams.get("a_custom")).toBe("second");
    expect(authorization.searchParams.get("prompt")).toBe("select_account");
    expect(authorization.searchParams.get("login_hint")).toBe(identity.email);
    expect(authorization.searchParams.get("access_type")).toBe("offline");
    expect(authorization.searchParams.get("response_mode")).toBe("query");
    expect(authorization.searchParams.get("state")).toBeTruthy();
    expect(authorization.searchParams.get("state")).not.toBe("ignored");
    expect(authorization.searchParams.get("nonce")).toBeTruthy();
    expect(authorization.searchParams.get("nonce")).not.toBe("ignored");
    expect(authorization.searchParams.has("code_challenge")).toBe(false);
    expect(authorization.searchParams.has("code_challenge_method")).toBe(false);
    const callback = await finishAuthorization(ctx, authorization);
    expect(callback.location).toBe("/oidc/done");
    const authenticated = await successfulSession(
      ctx,
      identity,
      "oidc-parameters",
    );
    const link = await ctx.actor().client.linkSocial({
      provider: "oidc-parameters",
      callbackURL: "/oidc/done",
      loginHint: identity.email,
      additionalParams: { tenant: "link-tenant" },
    });
    expect(link.error).toBeNull();
    const linkURL = new URL(link.data!.url);
    expect(linkURL.searchParams.get("login_hint")).toBe(identity.email);
    expect(linkURL.searchParams.get("tenant")).toBe("link-tenant");
    expect(linkURL.searchParams.get("nonce")).toBeTruthy();
    const linkCallback = await finishAuthorization(ctx, linkURL);
    expect(linkCallback.location).toBe("/oidc/done");
    expect((await ctx.actor().client.listAccounts()).data).toHaveLength(1);
    const rejected = [];
    for (const key of [
      "state",
      "client_id",
      "redirect_uri",
      "response_type",
      "code_challenge",
      "code_challenge_method",
      "nonce",
      "scope",
    ]) {
      const request = {
        provider: "oidc-parameters",
        callbackURL: "/oidc/done",
        additionalParams: { [key]: "attacker" },
      };
      const signInFailure = await ctx.actor().client.signIn.social(request);
      expect(signInFailure.error?.status).toBe(400);
      expect(signInFailure.error?.code).toBe("VALIDATION_ERROR");
      const linkFailure = await ctx.actor().client.linkSocial(request);
      expect(linkFailure.error?.status).toBe(400);
      expect(linkFailure.error?.code).toBe("VALIDATION_ERROR");
      rejected.push({
        key,
        signInFailure: ctx.snapshot(signInFailure),
        linkFailure: ctx.snapshot(linkFailure),
      });
    }
    return { callback, authenticated, linkCallback, rejected };
  },
);

compatScenario(
  "OIDC IdP initiated callbacks restart authorization with fresh state and nonce",
  async (ctx) => {
    const identity = await configure(ctx);
    const rejected = await ctx.rawRequest({
      path: "/api/auth/callback/oidc?code=unsolicited",
      redirect: "manual",
    });
    expect(rejected.status).toBe(302);
    expect(new URL(rejected.location!).searchParams.get("error")).toBe(
      "state_not_found",
    );
    const bounce = await ctx.rawRequest({
      path: "/api/auth/callback/oidc-idp?code=unsolicited",
      redirect: "manual",
    });
    expect(bounce.status).toBe(302);
    const authorization = new URL(bounce.location!);
    expect(authorization.origin).toBe(issuer);
    expect(authorization.searchParams.get("state")).toBeTruthy();
    expect(authorization.searchParams.get("nonce")).toBeTruthy();
    expect((await control("requests")).token).toBe(0);
    const callback = await finishAuthorization(ctx, authorization);
    expect(callback.status).toBe(302);
    expect(callback.location).toBe(ctx.baseURL);
    const authenticated = await successfulSession(ctx, identity, "oidc-idp");
    return { rejected, bounce, callback, authenticated };
  },
);

compatScenario(
  "Generic OAuth authenticates Basic and public clients during code exchange and token refresh",
  async (ctx) => {
    const observations = [];
    for (const provider of ["oidc-basic", "oidc-public"]) {
      const identity = await configure(ctx);
      const callback = await login(ctx, provider);
      expect(callback.location).toBe("/oidc/done");
      const { idToken } = await control("issued-token");
      expect(typeof idToken).toBe("string");
      const session = await ctx.actor().client.getSession();
      expect(session.data?.user.email).toBe(identity.email);
      const accounts = await ctx.actor().client.listAccounts();
      const account = accounts.data?.find(
        (entry) => entry.providerId === provider,
      );
      expect(account?.accountId).toBe(identity.sub);
      const refreshed = await ctx
        .actor()
        .client.refreshToken({ accountId: account!.id });
      expect(refreshed.error).toBeNull();
      expect(refreshed.data?.accessToken).toBe("oidc-refreshed-access-token");
      expect(refreshed.data?.accountId).toBe(account!.id);
      expect(refreshed.data?.idToken).toBe(idToken);
      const persisted = await ctx
        .actor()
        .client.getAccessToken({ accountId: account!.id });
      expect(persisted.error).toBeNull();
      expect(persisted.data?.accessToken).toBe("oidc-refreshed-access-token");
      expect(persisted.data?.idToken).toBe(idToken);
      expect((await control("requests")).token).toBe(2);
      await ctx.actor().client.signOut();
      observations.push({
        provider,
        callback,
        refreshed: ctx.snapshot({
          ...refreshed,
          data: {
            ...refreshed.data,
            accountId: "<stored-account>",
            idToken: "<issued-id-token>",
          },
        }),
        persisted: ctx.snapshot({
          ...persisted,
          data: { ...persisted.data, idToken: "<issued-id-token>" },
        }),
      });
    }
    return observations;
  },
);

compatScenario(
  "OIDC refreshes JWKS for a newly rotated signing key after the upstream cooldown",
  async (ctx) => {
    const identity = await configure(ctx);
    const first = await login(ctx, "oidc-rotation");
    expect(first.location).toBe("/oidc/done");
    const before = await ctx.actor().client.getSession();
    expect(before.data?.user.email).toBe(identity.email);
    await ctx.actor().client.signOut();
    const warmRequests = await control("requests");
    expect(warmRequests.jwks).toBe(1);
    await control("rotate", {});
    const duringCooldown = await login(ctx, "oidc-rotation");
    expect(duringCooldown.location).toBe(
      "/oidc/error?error=unable_to_get_user_info",
    );
    expect((await ctx.actor().client.getSession()).data).toBeNull();
    expect((await control("requests")).jwks).toBe(1);
    // jose's remote JWKS resolver waits 30 seconds before retrying an unknown kid.
    await Bun.sleep(30_100);
    const second = await login(ctx, "oidc-rotation");
    expect(second.location).toBe("/oidc/done");
    const after = await ctx.actor().client.getSession();
    expect(after.data!.user.id).toBe(before.data!.user.id);
    expect(after.data!.session.id).not.toBe(before.data!.session.id);
    expect((await control("requests")).jwks).toBe(2);
    return {
      first,
      duringCooldown,
      second,
      userId: after.data!.user.id,
      email: after.data!.user.email,
    };
  },
  90_000,
);
