import { compatScenario } from "../../support/scenario";

compatScenario("get session after sign-in returns session and user", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase0-session");
  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Session User",
  });

  const session = await primary.client.getSession();

  return {
    session: ctx.snapshot(session),
  };
});

compatScenario("get session without auth returns null", async (ctx) => {
  const primary = ctx.actor();
  const session = await primary.client.getSession();

  return {
    session: ctx.snapshot(session),
  };
});
