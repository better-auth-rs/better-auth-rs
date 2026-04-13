import { compatScenario } from "../../support/scenario";

compatScenario("error page sanitizes script injection in error code", async (ctx) => {
  const response = await ctx.rawRequest({
    path: `/api/auth/error?error=${encodeURIComponent("<script>alert(1)</script>")}`,
  });

  return {
    response: ctx.snapshot(response),
  };
});

compatScenario("error page renders valid error code", async (ctx) => {
  const response = await ctx.rawRequest({
    path: `/api/auth/error?error=SOME_ERROR`,
  });

  return {
    response: ctx.snapshot(response),
  };
});
