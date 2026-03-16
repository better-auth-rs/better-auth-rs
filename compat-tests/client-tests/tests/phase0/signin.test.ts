import { compatScenario } from "../../support/scenario";

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
