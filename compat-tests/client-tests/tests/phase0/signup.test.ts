import { compatScenario } from "../../support/scenario";

compatScenario("sign up with valid credentials returns user and token", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase0-signup");
  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Test User",
  });

  return {
    signup: ctx.snapshot(signup),
  };
});

compatScenario("sign up with duplicate email returns error", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase0-signup-duplicate");
  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "First User",
  });

  const duplicate = await primary.client.signUp.email({
    email,
    password: "password456",
    name: "Second User",
  });

  return {
    duplicate: ctx.snapshot(duplicate),
  };
});

compatScenario("sign up with short password returns error", async (ctx) => {
  const primary = ctx.actor();
  const signup = await primary.client.signUp.email({
    email: ctx.uniqueEmail("phase0-signup-short"),
    password: "123",
    name: "Weak User",
  });

  return {
    signup: ctx.snapshot(signup),
  };
});

compatScenario("sign up with invalid email returns error", async (ctx) => {
  const primary = ctx.actor();
  const signup = await primary.client.signUp.email({
    email: "invalid-email",
    password: "password123",
    name: "Invalid Email User",
  });

  return {
    signup: ctx.snapshot(signup),
  };
});
