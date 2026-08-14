import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";
import { compatScenario } from "../../support/scenario";

export type CompatContext = Parameters<Parameters<typeof compatScenario>[1]>[0];

export function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected object response body");
  }
  return value as Record<string, unknown>;
}

export function asArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error("expected array response body");
  }
  return value;
}

export function organizationActor(ctx: CompatContext, name = "primary") {
  const actor = ctx.actor(name);

  return {
    ...actor,
    orgClient: createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [organizationClient()],
      fetchOptions: {
        customFetchImpl: actor.fetch,
      },
    }),
  };
}

export async function signUpUser(
  ctx: CompatContext,
  name: string,
  prefix: string,
  displayName: string,
) {
  const actor = organizationActor(ctx, name);
  const email = ctx.uniqueEmail(prefix);
  const signup = await actor.client.signUp.email({
    email,
    password: "password123",
    name: displayName,
  });

  return {
    ...actor,
    email,
    signup,
  };
}
