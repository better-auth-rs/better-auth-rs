import { compatScenario } from "../../support/scenario";

compatScenario("list sessions and revoke a session through the SDK", async (ctx) => {
  const first = ctx.actor("first");
  const second = ctx.actor("second");
  const email = ctx.uniqueEmail("phase1-sessions");

  const signup = await first.client.signUp.email({
    email,
    password: "password123",
    name: "Sessions User",
  });
  const secondSignin = await second.client.signIn.email({
    email,
    password: "password123",
  });
  const sessions = await first.client.listSessions();
  const current = await first.client.getSession();
  const revoke = await first.client.revokeSession({
    token: current.data?.session?.token ?? "",
  });
  const firstAfter = await first.client.getSession();
  const secondAfter = await second.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    secondSignin: ctx.snapshot(secondSignin),
    sessions: ctx.snapshot(sessions),
    current: ctx.snapshot(current),
    revoke: ctx.snapshot(revoke),
    firstAfter: ctx.snapshot(firstAfter),
    secondAfter: ctx.snapshot(secondAfter),
  };
});

compatScenario("revoke sessions logs out all active clients", async (ctx) => {
  const first = ctx.actor("first");
  const second = ctx.actor("second");
  const email = ctx.uniqueEmail("phase1-revoke-all");

  const signup = await first.client.signUp.email({
    email,
    password: "password123",
    name: "Revoke All User",
  });
  const secondSignin = await second.client.signIn.email({
    email,
    password: "password123",
  });
  const revoke = await first.client.revokeSessions();
  const firstAfter = await first.client.getSession();
  const secondAfter = await second.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    secondSignin: ctx.snapshot(secondSignin),
    revoke: ctx.snapshot(revoke),
    firstAfter: ctx.snapshot(firstAfter),
    secondAfter: ctx.snapshot(secondAfter),
  };
});

compatScenario("change password with revokeOtherSessions invalidates the other client", async (ctx) => {
  const primary = ctx.actor("primary");
  const secondary = ctx.actor("secondary");
  const email = ctx.uniqueEmail("phase1-change");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Change Password User",
  });
  const secondarySignin = await secondary.client.signIn.email({
    email,
    password: "password123",
  });
  const change = await primary.client.changePassword({
    currentPassword: "password123",
    newPassword: "newPassword123!",
    revokeOtherSessions: true,
  });
  const primaryAfter = await primary.client.getSession();
  const secondaryAfter = await secondary.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    secondarySignin: ctx.snapshot(secondarySignin),
    change: ctx.snapshot(change),
    primaryAfter: ctx.snapshot(primaryAfter),
    secondaryAfter: ctx.snapshot(secondaryAfter),
  };
});

compatScenario("revoke other sessions keeps the caller alive", async (ctx) => {
  const primary = ctx.actor("primary");
  const secondary = ctx.actor("secondary");
  const email = ctx.uniqueEmail("phase1-other-sessions");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Revoke Other Sessions User",
  });
  const secondarySignin = await secondary.client.signIn.email({
    email,
    password: "password123",
  });
  const revoke = await primary.client.revokeOtherSessions();
  const primaryAfter = await primary.client.getSession();
  const secondaryAfter = await secondary.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    secondarySignin: ctx.snapshot(secondarySignin),
    revoke: ctx.snapshot(revoke),
    primaryAfter: ctx.snapshot(primaryAfter),
    secondaryAfter: ctx.snapshot(secondaryAfter),
  };
});
