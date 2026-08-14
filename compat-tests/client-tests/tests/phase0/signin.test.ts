import { createAuthClient } from "better-auth/client";
import { usernameClient } from "better-auth/client/plugins";
import { compatScenario } from "../../support/scenario";

function usernameActor(ctx: Parameters<Parameters<typeof compatScenario>[1]>[0], name = "primary") {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [usernameClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

compatScenario("sign in with valid credentials returns user and token", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase0-signin");
  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Signin User",
  });

  const signin = await primary.client.signIn.email({
    email,
    password: "password123",
  });

  return {
    signin: ctx.snapshot(signin),
  };
});

compatScenario("sign in with wrong password returns error", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase0-signin-wrong");
  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Signin User",
  });

  const signin = await primary.client.signIn.email({
    email,
    password: "wrong-password",
  });

  return {
    signin: ctx.snapshot(signin),
  };
});

compatScenario("sign in with nonexistent email returns error", async (ctx) => {
  const primary = ctx.actor();
  const signin = await primary.client.signIn.email({
    email: "nonexistent@test.com",
    password: "password123",
  });

  return {
    signin: ctx.snapshot(signin),
  };
});

compatScenario("sign in with invalid email returns error", async (ctx) => {
  const primary = ctx.actor();
  const signin = await primary.client.signIn.email({
    email: "invalid-email",
    password: "password123",
  });

  return {
    signin: ctx.snapshot(signin),
  };
});

compatScenario("sign in with valid username returns user and token", async (ctx) => {
  const primary = ctx.actor();
  const username = usernameActor(ctx);
  const email = ctx.uniqueEmail("phase0-signin-username");
  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Username User",
    username: "phase0_user",
    displayUsername: "Phase0 User",
  });

  const signin = await username.signIn.username({
    username: "phase0_user",
    password: "password123",
  });

  return {
    signup: ctx.snapshot(signup),
    signin: ctx.snapshot(signin),
  };
});

compatScenario("sign in with wrong username password returns error", async (ctx) => {
  const primary = ctx.actor();
  const username = usernameActor(ctx);
  const email = ctx.uniqueEmail("phase0-signin-username-wrong");
  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Username User",
    username: "phase0_wrongpw",
  });

  const signin = await username.signIn.username({
    username: "phase0_wrongpw",
    password: "wrong-password",
  });

  return {
    signup: ctx.snapshot(signup),
    signin: ctx.snapshot(signin),
  };
});

compatScenario("sign in with nonexistent username returns error", async (ctx) => {
  const username = usernameActor(ctx);
  const signin = await username.signIn.username({
    username: "missing_user",
    password: "password123",
  });

  return {
    signin: ctx.snapshot(signin),
  };
});

compatScenario("sign in with differently cased username returns user and token", async (ctx) => {
  const primary = ctx.actor();
  const username = usernameActor(ctx);
  const email = ctx.uniqueEmail("phase0-signin-username-case");
  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Username User",
    username: "Phase0_Case_User",
  });

  const signin = await username.signIn.username({
    username: "PHASE0_CASE_USER",
    password: "password123",
  });

  return {
    signup: ctx.snapshot(signup),
    signin: ctx.snapshot(signin),
  };
});
