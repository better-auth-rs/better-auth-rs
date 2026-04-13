import { compatScenario } from "../../support/scenario";

compatScenario("get access token returns stored unexpired token", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase1-oauth-valid");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "OAuth Access User",
  });
  await ctx.seedOAuthAccount({
    email,
    accessToken: "still-valid-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2099-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const accessToken = await primary.client.getAccessToken({
    providerId: "mock",
  });

  return {
    signup: ctx.snapshot(signup),
    accessToken: ctx.snapshot(accessToken),
  };
});

compatScenario("get access token refreshes expired token", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase1-oauth-refresh");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "OAuth Refresh User",
  });
  await ctx.seedOAuthAccount({
    email,
    accessToken: "stale-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const accessToken = await primary.client.getAccessToken({
    providerId: "mock",
  });

  return {
    signup: ctx.snapshot(signup),
    accessToken: ctx.snapshot(accessToken),
  };
});

compatScenario("refresh token returns a fresh token set", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase1-refresh-token");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Refresh Token User",
  });
  await ctx.seedOAuthAccount({
    email,
    accessToken: "stale-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const refresh = await primary.client.refreshToken({
    providerId: "mock",
  });

  return {
    signup: ctx.snapshot(signup),
    refresh: ctx.snapshot(refresh),
  };
});

compatScenario("refresh token surfaces provider refresh failure", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase1-refresh-fail");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Refresh Failure User",
  });
  await ctx.seedOAuthAccount({
    email,
    accessToken: "stale-access-token",
    refreshToken: "seed-refresh-token",
    accessTokenExpiresAt: "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });
  await ctx.setOAuthRefreshMode("error");

  const refresh = await primary.client.refreshToken({
    providerId: "mock",
  });

  return {
    signup: ctx.snapshot(signup),
    refresh: ctx.snapshot(refresh),
  };
});
