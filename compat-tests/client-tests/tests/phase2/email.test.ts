import { compatScenario } from "../../support/scenario";

compatScenario("send verification email then verify marks the user verified", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase2-verify");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify User",
  });
  const send = await primary.client.sendVerificationEmail({
    email,
  });
  const record = await ctx.readVerificationEmail({ email }) as { token: string };
  const verify = await primary.client.verifyEmail({
    query: {
      token: record.token,
    },
  });
  const session = await primary.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    send: ctx.snapshot(send),
    verify: ctx.snapshot(verify),
    session: ctx.snapshot(session),
  };
});

compatScenario("send verification email rejects email mismatch for authenticated user", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase2-verify-mismatch");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Mismatch Verify User",
  });
  const send = await primary.client.sendVerificationEmail({
    email: ctx.uniqueEmail("phase2-verify-mismatch-other"),
  });

  return {
    signup: ctx.snapshot(signup),
    send: ctx.snapshot(send),
  };
});

compatScenario("send verification email rejects already verified user", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase2-verify-already");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Already Verified User",
  });
  await primary.client.sendVerificationEmail({
    email,
  });
  const record = await ctx.readVerificationEmail({ email }) as { token: string };
  const verify = await primary.client.verifyEmail({
    query: {
      token: record.token,
    },
  });
  const sendAgain = await primary.client.sendVerificationEmail({
    email,
  });

  return {
    signup: ctx.snapshot(signup),
    verify: ctx.snapshot(verify),
    sendAgain: ctx.snapshot(sendAgain),
  };
});

compatScenario("verify email callback redirects to callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase2-verify-callback");
  const callbackURL = "/callback?foo=bar&baz=qux";

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify Callback User",
  });
  await primary.client.sendVerificationEmail({
    email,
  });
  const record = await ctx.readVerificationEmail({ email }) as { token: string };
  const verify = await ctx.rawRequest({
    path: `/api/auth/verify-email?token=${encodeURIComponent(record.token)}&callbackURL=${encodeURIComponent(callbackURL)}`,
    redirect: "manual",
  });

  return {
    signup: ctx.snapshot(signup),
    verify: ctx.snapshot(verify),
  };
});

compatScenario("verify email rejects untrusted callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase2-verify-evil-redirect");

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Redirect Guard User",
  });
  await primary.client.sendVerificationEmail({ email });
  const record = await ctx.readVerificationEmail({ email }) as { token: string };

  const verify = await ctx.rawRequest({
    path: `/api/auth/verify-email?token=${encodeURIComponent(record.token)}&callbackURL=${encodeURIComponent("https://evil.com/phish")}`,
    redirect: "manual",
  });

  return {
    verify: ctx.snapshot(verify),
  };
});
