import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { compatScenario } from "../../support/scenario";

export type CompatContext = Parameters<Parameters<typeof compatScenario>[1]>[0];

export function adminActor(ctx: CompatContext, name = "primary") {
  const actor = ctx.actor(name);

  return {
    ...actor,
    adminClient: createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [adminClient()],
      fetchOptions: {
        customFetchImpl: actor.fetch,
      },
    }),
  };
}

export async function signUpAndPromoteAdmin(
  ctx: CompatContext,
  name = "primary",
  prefix = "phase9-admin",
  displayName = "Phase 9 Admin",
) {
  const actor = adminActor(ctx, name);
  const email = ctx.uniqueEmail(prefix);
  const signup = await actor.client.signUp.email({
    email,
    password: "password123",
    name: displayName,
  });

  await ctx.promoteAdmin({ email });

  return {
    ...actor,
    email,
    signup,
  };
}
