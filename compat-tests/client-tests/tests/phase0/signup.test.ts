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

compatScenario("sign up with invalid username returns error", async (ctx) => {
  const primary = ctx.actor();
  const signup = await primary.client.signUp.email({
    email: ctx.uniqueEmail("phase0-signup-invalid-username"),
    password: "password123",
    name: "Invalid Username User",
    username: "invalid username!",
  });

  return {
    signup: ctx.snapshot(signup),
  };
});

compatScenario("sign up with duplicate username returns error", async (ctx) => {
  const primary = ctx.actor();
  const firstEmail = ctx.uniqueEmail("phase0-signup-username-first");
  const secondEmail = ctx.uniqueEmail("phase0-signup-username-second");

  const first = await primary.client.signUp.email({
    email: firstEmail,
    password: "password123",
    name: "First Username User",
    username: "phase0_duplicate_user",
  });

  const duplicate = await primary.client.signUp.email({
    email: secondEmail,
    password: "password123",
    name: "Second Username User",
    username: "PHASE0_DUPLICATE_USER",
  });

  return {
    first: ctx.snapshot(first),
    duplicate: ctx.snapshot(duplicate),
  };
});
