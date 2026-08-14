import { compatScenario } from "../../support/scenario";

compatScenario("account info returns provider user info for a linked account", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase7-account-info");
  const accountId = ctx.uniqueToken("phase7-account-id");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Account Info User",
  });
  await ctx.seedOAuthAccount({
    email,
    providerId: "mock",
    accountId,
    accessToken: "stored-access-token",
    refreshToken: "stored-refresh-token",
    accessTokenExpiresAt: "2099-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const accountInfo = await ctx.rawRequest({
    path: `/api/auth/account-info?accountId=${encodeURIComponent(accountId)}`,
  });

  return {
    signup: ctx.snapshot(signup),
    accountInfo: ctx.snapshot(accountInfo),
  };
});

compatScenario("account info without an account cookie returns account not found", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase7-account-info-no-cookie");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "No Cookie User",
  });
  await ctx.seedOAuthAccount({
    email,
    providerId: "mock",
    accountId: ctx.uniqueToken("phase7-no-cookie-account-id"),
    accessToken: "stored-access-token",
    refreshToken: "stored-refresh-token",
    accessTokenExpiresAt: "2099-01-01T00:00:00Z",
    refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
  });

  const accountInfo = await ctx.rawRequest({
    path: "/api/auth/account-info",
  });

  return {
    signup: ctx.snapshot(signup),
    accountInfo: ctx.snapshot(accountInfo),
  };
});

compatScenario("verify password succeeds with the current credential password", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase7-verify-password");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify Password User",
  });
  const verifyPassword = await ctx.rawRequest({
    path: "/api/auth/verify-password",
    method: "POST",
    json: {
      password: "password123",
    },
  });

  return {
    signup: ctx.snapshot(signup),
    verifyPassword: ctx.snapshot(verifyPassword),
  };
});

compatScenario("verify password returns invalid password for a bad credential", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase7-verify-password-wrong");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify Password Wrong User",
  });
  const verifyPassword = await ctx.rawRequest({
    path: "/api/auth/verify-password",
    method: "POST",
    json: {
      password: "wrong-password",
    },
  });

  return {
    signup: ctx.snapshot(signup),
    verifyPassword: ctx.snapshot(verifyPassword),
  };
});

compatScenario("verify password returns invalid password for oauth-only users", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase7-verify-password-oauth-only");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify Password OAuth User",
  });
  await ctx.removeCredentialAccount({ email });

  const verifyPassword = await ctx.rawRequest({
    path: "/api/auth/verify-password",
    method: "POST",
    json: {
      password: "password123",
    },
  });

  return {
    signup: ctx.snapshot(signup),
    verifyPassword: ctx.snapshot(verifyPassword),
  };
});

compatScenario("verify password requires a session", async (ctx) => {
  const verifyPassword = await ctx.rawRequest({
    actor: "anonymous",
    path: "/api/auth/verify-password",
    method: "POST",
    json: {
      password: "password123",
    },
  });

  return {
    verifyPassword: ctx.snapshot(verifyPassword),
  };
});
