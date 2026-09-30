import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("hashed magic links deny signup but authenticate existing users", async (ctx) => {
  const email = ctx.uniqueEmail("magic-disabled");
  const send = () => ctx.rawRequest({ path: "/api/auth/sign-in/magic-link", method: "POST", json: { email } });
  expect((await send()).status).toBe(200);
  const first = await ctx.readVerificationEmail({ email }) as { token: string };
  const denied = await ctx.rawRequest({ path: `/api/auth/magic-link/verify?token=${first.token}`, redirect: "manual" });
  expect(denied.status).toBe(302);
  expect(new URL(denied.location!).searchParams.get("error")).toBe("new_user_signup_disabled");
  const owner = await ctx.actor("existing").client.signUp.email({ email, password: "password123", name: "Owner" });
  expect(owner.error).toBeNull();
  const replay = await ctx.rawRequest({ path: `/api/auth/magic-link/verify?token=${first.token}`, redirect: "manual" });
  expect(replay.status).toBe(302);
  expect(new URL(replay.location!).searchParams.get("error")).toBe("INVALID_TOKEN");
  expect((await send()).status).toBe(200);
  const next = await ctx.readVerificationEmail({ email }) as { token: string };
  const verified = await ctx.rawRequest({ path: `/api/auth/magic-link/verify?token=${next.token}`, redirect: "manual" });
  expect(verified.status).toBe(200);
  expect((verified.body as { user: { id: string } }).user.id).toBe(owner.data!.user.id);
  return { denied, replay, verified };
});
