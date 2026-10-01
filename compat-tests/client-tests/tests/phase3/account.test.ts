import { expect } from "bun:test";
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

function expectAccounts(
  accounts: Array<{ providerId: string; accountId: string }> | null | undefined,
  userId: string | undefined,
  linked?: { providerId: string; accountId: string },
) {
  expect(userId).toBeString();
  expect(accounts).toHaveLength(linked ? 2 : 1);
  expect(accounts?.find((account) => account.providerId === "credential")?.accountId).toBe(userId);
  if (linked) {
    expect(accounts?.find((account) => account.providerId === linked.providerId)?.accountId).toBe(linked.accountId);
  }
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
  expectAccounts(accounts.data, signup.data?.user.id, { providerId: "google", accountId: sub });

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
  await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });

  const before = await primary.client.listAccounts();
  expectAccounts(before.data, signup.data?.user.id, { providerId: "google", accountId: sub });
  const googleAccount = before.data?.find((account) => account.providerId === "google");
  if (!googleAccount?.id) {
    throw new Error("missing google account after link");
  }
  const unlink = await primary.client.unlinkAccount({
    accountId: googleAccount.id,
  });
  expect(unlink.error).toBeNull();
  expect(unlink.data?.status).toBe(true);
  const after = await primary.client.listAccounts();
  expectAccounts(after.data, signup.data?.user.id);

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

  const signup = await primary.client.signUp.email({
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
  expect(link.error).toBeNull();
  expectAccounts(accounts.data, signup.data?.user.id, { providerId: "google", accountId: sub });

  return {
    link: ctx.snapshot(link),
    accounts: ctx.snapshot(accounts),
  };
});

compatScenario("github link social creates an account that listAccounts returns", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-github-link-social");
  const accountId = ctx.uniqueToken("phase3-github-link-id");
  await ctx.setGitHubProfile({
    id: accountId,
    login: ctx.uniqueToken("phase3-github-link-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "github",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const accounts = await primary.client.listAccounts();
  expectAccounts(accounts.data, signup.data?.user.id, { providerId: "github", accountId });

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

compatScenario("github unlink account removes the linked github account", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-github-unlink-social");
  const accountId = ctx.uniqueToken("phase3-github-unlink-id");
  await ctx.setGitHubProfile({
    id: accountId,
    login: ctx.uniqueToken("phase3-github-unlink-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  const link = await primary.client.linkSocial({
    provider: "github",
    callbackURL: "/settings",
  });
  const state = extractState(link.data?.url);
  await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });

  const before = await primary.client.listAccounts();
  expectAccounts(before.data, signup.data?.user.id, { providerId: "github", accountId });
  const githubAccount = before.data?.find((account) => account.providerId === "github");
  if (!githubAccount?.id) {
    throw new Error("missing github account after link");
  }
  const unlink = await primary.client.unlinkAccount({
    accountId: githubAccount.id,
  });
  expect(unlink.error).toBeNull();
  expect(unlink.data?.status).toBe(true);
  const after = await primary.client.listAccounts();
  expectAccounts(after.data, signup.data?.user.id);

  return {
    before: ctx.snapshot(before),
    unlink: ctx.snapshot(unlink),
    after: ctx.snapshot(after),
  };
});

compatScenario("OAuth callback linking merges stored scopes without dropping prior grants", async (ctx) => {
  const stored = "\ufefflegacy\ufeff, email, legacy, ,\u0085legacy";
  const cases = [
    { name: "union", code: "compat-code", stored, scopes: ["legacy", "email", "\u0085legacy", "openid", "profile"] },
    { name: "missing", code: "compat-scope-missing", stored, scopes: ["legacy", "email", "\u0085legacy"] },
    { name: "empty", code: "compat-scope-empty", stored: "", scopes: [] },
    { name: "array", code: "compat-scope-array", stored, scopes: ["legacy", "email", "\u0085legacy", "audit"] },
    { name: "new-empty", code: "compat-scope-missing", scopes: [] },
    { name: "failed", code: "compat-code", stored, scopes: ["legacy", "email", "legacy", "\u0085legacy"] },
  ];
  const results = [];
  for (const row of cases) {
    const actor = ctx.actor(row.name);
    const email = ctx.uniqueEmail(`scope-${row.name}`);
    const sub = ctx.uniqueToken(`scope-${row.name}`);
    await ctx.setOAuthRefreshMode(row.name === "failed" ? "error" : "success");
    await ctx.setSocialProfile({ email, sub, name: "Scope User", emailVerified: true, idTokenValid: true });
    const signup = await actor.client.signUp.email({ email, password: "password123", name: "Scope User" });
    expect(signup.error).toBeNull();
    if ("stored" in row) await ctx.seedOAuthAccount({ email, providerId: "google", accountId: sub, scope: row.stored });
    const link = await actor.client.linkSocial({ provider: "google", callbackURL: "/settings", errorCallbackURL: "/failed" });
    expect(link.error).toBeNull();
    const state = extractState(link.data?.url);
    const callback = await ctx.rawRequest({
      actor: row.name,
      path: `/api/auth/callback/google?code=${row.code}&state=${encodeURIComponent(state)}`,
      redirect: "manual",
    });
    expect(callback.status).toBe(302);
    const location = new URL(callback.location!, ctx.baseURL);
    expect(location.pathname).toBe(row.name === "failed" ? "/failed" : "/settings");
    expect(location.searchParams.get("error")).toBe(row.name === "failed" ? "invalid_code" : null);
    const accounts = await actor.client.listAccounts();
    expect(accounts.error).toBeNull();
    const google = accounts.data?.filter((account) => account.providerId === "google");
    expect(google).toHaveLength(1);
    expect(google![0].scopes).toEqual(row.scopes);
    results.push({ name: row.name, scopes: google![0].scopes, location: callback.location });
  }
  return results;
});
