import { compatScenario } from "../../support/scenario";

compatScenario("request password reset then reset password updates credentials", async (ctx) => {
  const primary = ctx.actor();
  const fresh = ctx.actor("fresh");
  const email = ctx.uniqueEmail("phase1-reset");
  const token = ctx.uniqueToken("phase1-reset-token");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Reset User",
  });
  const requestReset = await primary.client.requestPasswordReset({
    email,
    redirectTo: "/reset",
  });
  await ctx.seedResetPasswordToken({
    email,
    token,
    expiresAt: "2099-01-01T00:00:00Z",
  });
  const reset = await primary.client.resetPassword({
    newPassword: "newPassword123!",
    token,
  });
  const signin = await fresh.client.signIn.email({
    email,
    password: "newPassword123!",
  });

  return {
    signup: ctx.snapshot(signup),
    requestReset: ctx.snapshot(requestReset),
    reset: ctx.snapshot(reset),
    signin: ctx.snapshot(signin),
  };
});

compatScenario("request password reset masks nonexistent email", async (ctx) => {
  const primary = ctx.actor();
  const result = await primary.client.requestPasswordReset({
    email: ctx.uniqueEmail("phase1-missing"),
    redirectTo: "/reset",
  });

  return {
    requestReset: ctx.snapshot(result),
  };
});

compatScenario("request password reset masks sender failure", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase1-sender-failure");

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Sender Failure User",
  });
  await ctx.setResetPasswordMode("throw");

  const result = await primary.client.requestPasswordReset({
    email,
    redirectTo: "/reset",
  });

  return {
    requestReset: ctx.snapshot(result),
  };
});

compatScenario("reset password rejects invalid token", async (ctx) => {
  const primary = ctx.actor();
  const result = await primary.client.resetPassword({
    newPassword: "newPassword123!",
    token: "invalid-reset-token",
  });

  return {
    reset: ctx.snapshot(result),
  };
});

compatScenario("reset password token cannot be reused", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase1-reuse");
  const token = ctx.uniqueToken("phase1-reuse-token");

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Reuse Token User",
  });
  await primary.client.requestPasswordReset({
    email,
    redirectTo: "/reset",
  });
  await ctx.seedResetPasswordToken({
    email,
    token,
    expiresAt: "2099-01-01T00:00:00Z",
  });

  const first = await primary.client.resetPassword({
    newPassword: "newPassword123!",
    token,
  });
  const second = await primary.client.resetPassword({
    newPassword: "anotherPassword123!",
    token,
  });

  return {
    first: ctx.snapshot(first),
    second: ctx.snapshot(second),
  };
});

compatScenario("reset password callback redirects with token and preserves callbackURL query params", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase1-reset-callback");
  const token = ctx.uniqueToken("phase1-reset-callback-token");
  const callbackURL = "/callback?foo=bar&baz=qux";

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Reset Callback User",
  });
  await ctx.seedResetPasswordToken({
    email,
    token,
    expiresAt: "2099-01-01T00:00:00Z",
  });

  const callback = await ctx.rawRequest({
    path: `/api/auth/reset-password/${encodeURIComponent(token)}?callbackURL=${encodeURIComponent(callbackURL)}`,
    redirect: "manual",
  });

  return {
    callback: ctx.snapshot(callback),
  };
});

compatScenario("reset password callback redirects invalid token to error callback", async (ctx) => {
  const callbackURL = "/callback?foo=bar&baz=qux";

  const callback = await ctx.rawRequest({
    path: `/api/auth/reset-password/invalid-reset-token?callbackURL=${encodeURIComponent(callbackURL)}`,
    redirect: "manual",
  });

  return {
    callback: ctx.snapshot(callback),
  };
});
