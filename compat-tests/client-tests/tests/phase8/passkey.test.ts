import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { compatScenario } from "../../support/scenario";

function redactChallenge<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const copy = structuredClone(value as object) as Record<string, unknown>;
  if (
    copy.data &&
    typeof copy.data === "object" &&
    !Array.isArray(copy.data) &&
    "challenge" in (copy.data as Record<string, unknown>)
  ) {
    (copy.data as Record<string, unknown>).challenge = "<challenge>";
  }
  return copy as T;
}

function passkeyActor(ctx: Parameters<Parameters<typeof compatScenario>[1]>[0], name = "primary") {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [passkeyClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

compatScenario("passkey client surface matches TS for options and management errors", async (ctx) => {
  const actor = ctx.actor("primary");
  const passkey = passkeyActor(ctx, "primary");
  const email = ctx.uniqueEmail("phase8-passkey");

  const signup = await actor.client.signUp.email({
    email,
    password: "password123",
    name: "Phase 8 Passkey",
  });

  const registerOptions = await passkey.$fetch("/passkey/generate-register-options", {
    method: "GET",
    query: {
      name: "Laptop Passkey",
      authenticatorAttachment: "cross-platform",
    },
    throw: false,
  });

  const authenticateOptions = await passkey.$fetch("/passkey/generate-authenticate-options", {
    method: "GET",
    throw: false,
  });

  const listPasskeys = await passkey.$fetch("/passkey/list-user-passkeys", {
    method: "GET",
    throw: false,
  });

  const deleteMissing = await passkey.$fetch("/passkey/delete-passkey", {
    method: "POST",
    body: {
      id: "missing-passkey-id",
    },
    throw: false,
  });

  const updateMissing = await passkey.$fetch("/passkey/update-passkey", {
    method: "POST",
    body: {
      id: "missing-passkey-id",
      name: "Renamed Passkey",
    },
    throw: false,
  });

  return {
    signup: ctx.snapshot(signup),
    registerOptions: redactChallenge(ctx.snapshot(registerOptions)),
    authenticateOptions: redactChallenge(ctx.snapshot(authenticateOptions)),
    listPasskeys: ctx.snapshot(listPasskeys),
    deleteMissing: ctx.snapshot(deleteMissing),
    updateMissing: ctx.snapshot(updateMissing),
  };
});
