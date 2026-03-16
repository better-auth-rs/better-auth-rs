import { compatScenario } from "../../support/scenario";

function extractState(url: string | undefined) {
  if (!url) {
    throw new Error("missing OAuth URL");
  }
  const state = new URL(url).searchParams.get("state");
  if (!state) {
    throw new Error("missing OAuth state");
  }
  return state;
}

compatScenario("link social creates an account that listAccounts returns", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-link-social");
  const sub = ctx.uniqueToken("phase3-link-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Linked Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "google",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const accounts = await primary.client.listAccounts();

  return {
    signup: ctx.snapshot(signup),
    link: {
      redirect: link.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    accounts: ctx.snapshot(accounts),
  };
});

compatScenario("unlink account removes the linked google account", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-unlink-social");
  const sub = ctx.uniqueToken("phase3-unlink-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Unlink Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "google",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });

  const before = await primary.client.listAccounts();
  const googleAccount = before.data?.find((account) => account.providerId === "google");
  if (!googleAccount?.accountId) {
    throw new Error("missing google account after link");
  }
  const unlink = await primary.client.unlinkAccount({
    providerId: "google",
    accountId: googleAccount.accountId,
  });
  const after = await primary.client.listAccounts();

  return {
    before: ctx.snapshot(before),
    unlink: ctx.snapshot(unlink),
    after: ctx.snapshot(after),
  };
});

compatScenario("link social with idToken adds a google account", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-link-id-token");
  const sub = ctx.uniqueToken("phase3-link-id-token-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Link ID Token User",
    emailVerified: true,
    idTokenValid: true,
  });

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });

  const link = await primary.client.linkSocial({
    provider: "google",
    callbackURL: "/settings",
    idToken: {
      token: "compat-google-id-token",
    },
  });
  const accounts = await primary.client.listAccounts();

  return {
    link: ctx.snapshot(link),
    accounts: ctx.snapshot(accounts),
  };
});
