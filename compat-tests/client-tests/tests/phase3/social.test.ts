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

compatScenario("social sign-in rejects invalid callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const signIn = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "http://malicious.com",
  });

  return {
    signIn: ctx.snapshot(signIn),
  };
});

compatScenario("social sign-in redirects new users to newUserCallbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-social-new-user");
  const sub = ctx.uniqueToken("phase3-google-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Phase 3 Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  const signIn = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const state = extractState(signIn.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    signIn: {
      redirect: signIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    session: ctx.snapshot(session),
  };
});

compatScenario("social sign-in redirects existing users to callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-social-existing");
  const sub = ctx.uniqueToken("phase3-google-existing-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Existing Google User",
    emailVerified: true,
    idTokenValid: true,
  });

  const first = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const firstState = extractState(first.data?.url);
  const firstCallback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(firstState)}`,
    redirect: "manual",
  });
  await primary.client.signOut();

  const second = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const secondState = extractState(second.data?.url);
  const secondCallback = await ctx.rawRequest({
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(secondState)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    firstCallback: ctx.snapshot(firstCallback),
    secondCallback: ctx.snapshot(secondCallback),
    session: ctx.snapshot(session),
  };
});

compatScenario("social sign-in with idToken returns token and session", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-social-id-token");
  const sub = ctx.uniqueToken("phase3-google-id-token-sub");
  await ctx.setSocialProfile({
    email,
    sub,
    name: "Google ID Token User",
    emailVerified: true,
    idTokenValid: true,
  });

  const signIn = await primary.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
    idToken: {
      token: "compat-google-id-token",
    },
  });
  const session = await primary.client.getSession();

  return {
    signIn: ctx.snapshot(signIn),
    session: ctx.snapshot(session),
  };
});

compatScenario("github social sign-in redirects new users to newUserCallbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-github-social-new-user");
  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("phase3-github-id"),
    login: ctx.uniqueToken("phase3-github-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const signIn = await primary.client.signIn.social({
    provider: "github",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const state = extractState(signIn.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    signIn: {
      redirect: signIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    session: ctx.snapshot(session),
  };
});

compatScenario("github social sign-in redirects existing users to callbackURL", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-github-social-existing");
  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("phase3-github-existing-id"),
    login: ctx.uniqueToken("phase3-github-existing-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const first = await primary.client.signIn.social({
    provider: "github",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const firstState = extractState(first.data?.url);
  const firstCallback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(firstState)}`,
    redirect: "manual",
  });
  await primary.client.signOut();

  const second = await primary.client.signIn.social({
    provider: "github",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
  });
  const secondState = extractState(second.data?.url);
  const secondCallback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(secondState)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    firstCallback: ctx.snapshot(firstCallback),
    secondCallback: ctx.snapshot(secondCallback),
    session: ctx.snapshot(session),
  };
});

compatScenario("github social sign-in with unverified fallback email does not link existing user", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-github-unverified");

  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Credential User",
  });
  await primary.client.signOut();

  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("phase3-github-unverified-id"),
    login: ctx.uniqueToken("phase3-github-unverified-login"),
    emails: [
      {
        email,
        primary: true,
        verified: false,
        visibility: "private",
      },
    ],
  });

  const signIn = await primary.client.signIn.social({
    provider: "github",
    callbackURL: "/dashboard",
  });
  const state = extractState(signIn.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    signIn: {
      redirect: signIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    session: ctx.snapshot(session),
  };
});

compatScenario("github social sign-in without callbackURL redirects back to app root", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase3-github-default-callback");
  await ctx.setGitHubProfile({
    id: ctx.uniqueToken("phase3-github-default-id"),
    login: ctx.uniqueToken("phase3-github-default-login"),
    emails: [
      {
        email,
        primary: true,
        verified: true,
        visibility: "private",
      },
    ],
  });

  const signIn = await primary.client.signIn.social({
    provider: "github",
  });
  const state = extractState(signIn.data?.url);
  const callback = await ctx.rawRequest({
    path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const session = await primary.client.getSession();

  return {
    signIn: {
      redirect: signIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: ctx.snapshot(callback),
    session: ctx.snapshot(session),
  };
});
