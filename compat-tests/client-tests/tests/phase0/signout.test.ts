import { compatScenario } from "../../support/scenario";

compatScenario("sign out after sign-in invalidates session", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase0-signout");
  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Signout User",
  });

  const before = await primary.client.getSession();
  const signout = await primary.client.signOut();
  const after = await primary.client.getSession();

  return {
    before: ctx.snapshot(before),
    signout: ctx.snapshot(signout),
    after: ctx.snapshot(after),
  };
});

compatScenario("sign out without auth still succeeds", async (ctx) => {
  const primary = ctx.actor();
  const signout = await primary.client.signOut();

  return {
    signout: ctx.snapshot(signout),
  };
});
