import { expect } from "bun:test";
import { control } from "../../support/oidc";
import { compatScenario } from "../../support/scenario";

compatScenario(
  "OIDC required email verification rejects callback and direct ID token sign-in",
  async (ctx) => {
    await control("configure", {
      email: ctx.uniqueEmail("oidc-unverified"),
      sub: ctx.uniqueToken("oidc-unverified"),
    });
    const start = await ctx.actor().client.signIn.social({
      provider: "oidc-email-required",
      callbackURL: "/oidc/done",
      errorCallbackURL: "/oidc/error",
    });
    expect(start.error).toBeNull();
    const authorization = await fetch(start.data!.url, { redirect: "manual" });
    expect(authorization.status).toBe(302);
    const callback = await ctx.rawRequest({
      path: authorization.headers.get("location")!,
      redirect: "manual",
    });
    expect(callback.status).toBe(302);
    expect(callback.location).toBe("/oidc/error?error=email_not_verified");
    expect((await ctx.actor().client.getSession()).data).toBeNull();
    const nonce = "email-verification-nonce";
    const { token } = await control("id-token", { nonce });
    const direct = await ctx
      .actor()
      .client.signIn.social({
        provider: "oidc-email-required",
        idToken: { token, nonce },
      });
    expect(direct.error?.status).toBe(403);
    expect(direct.error?.code).toBe("EMAIL_NOT_VERIFIED");
    expect((await ctx.actor().client.getSession()).data).toBeNull();
    return { callback, direct: ctx.snapshot(direct) };
  },
);

compatScenario(
  "OIDC disabled signup rejects a new direct ID token identity",
  async (ctx) => {
    await control("configure", {
      email: ctx.uniqueEmail("oidc-no-signup"),
      sub: ctx.uniqueToken("oidc-no-signup"),
    });
    const nonce = "disabled-signup-nonce";
    const { token } = await control("id-token", { nonce });
    const result = await ctx
      .actor()
      .client.signIn.social({
        provider: "oidc-no-signup",
        idToken: { token, nonce },
      });
    expect(result.error?.status).toBe(401);
    expect(result.error?.code).toBe("OAUTH_LINK_ERROR");
    expect(result.error?.message).toBe("signup disabled");
    expect((await ctx.actor().client.getSession()).data).toBeNull();
    return ctx.snapshot(result);
  },
);

compatScenario(
  "Unknown OAuth callbacks validate state and callback errors before resolving the provider",
  async (ctx) => {
    const observations = [];
    for (const query of ["code=unsolicited", "code=unsolicited&state="]) {
      const result = await ctx.rawRequest({
        path: `/api/auth/callback/unknown?${query}`,
        redirect: "manual",
      });
      expect(result.status).toBe(302);
      expect(result.location).toBe(
        `${ctx.baseURL}/api/auth/error?error=state_not_found`,
      );
      observations.push(result);
    }
    for (const [query, error] of [
      ["error=access_denied", "access_denied"],
      ["", "no_code"],
      ["code=unredeemable", "oauth_provider_not_found"],
    ]) {
      const start = await ctx
        .actor()
        .client.signIn.social({
          provider: "oidc",
          callbackURL: "/oidc/done",
          errorCallbackURL: "/oidc/error",
        });
      expect(start.error).toBeNull();
      const state = new URL(start.data!.url).searchParams.get("state");
      expect(state).toBeTruthy();
      const result = await ctx.rawRequest({
        path: `/api/auth/callback/unknown?state=${encodeURIComponent(state!)}&${query}`,
        redirect: "manual",
      });
      expect(result.status).toBe(302);
      expect(result.location).toBe(`/oidc/error?error=${error}`);
      observations.push(result);
    }
    return observations;
  },
);
