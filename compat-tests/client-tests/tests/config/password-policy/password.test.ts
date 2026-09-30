import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
const initial = "Password123!";
const changed = "ChangedPassword123!";
const reset = "ResetPassword123!";
async function post(ctx: Context, path: string, json: object) {
  return ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json });
}

compatScenario("password changes and resets use the email-password hasher and password limits", async ctx => {
  const email = ctx.uniqueEmail("password-policy");
  const signup = await ctx.actor().client.signUp.email({ email, name: "Password Policy", password: initial });
  expect(signup.error).toBeNull();
  const longLogin = await ctx.actor("long").client.signIn.email({ email, password: "X".repeat(25) });
  expect(longLogin.error?.status).toBe(400);
  expect(longLogin.error?.code).toBe("PASSWORD_TOO_LONG");
  const tooShort = await post(ctx, "/change-password", { currentPassword: "wrong", newPassword: "Short123!" });
  expect(tooShort.status).toBe(400);
  expect(tooShort.body).toMatchObject({ code: "PASSWORD_TOO_SHORT" });
  const tooLong = await post(ctx, "/change-password", { currentPassword: initial, newPassword: "X".repeat(25) });
  expect(tooLong.status).toBe(400);
  expect(tooLong.body).toMatchObject({ code: "PASSWORD_TOO_LONG" });
  const longCurrent = await post(ctx, "/change-password", { currentPassword: "X".repeat(25), newPassword: changed });
  expect(longCurrent.status).toBe(400);
  expect(longCurrent.body).toMatchObject({ code: "PASSWORD_TOO_LONG" });
  const update = await post(ctx, "/change-password", { currentPassword: initial, newPassword: changed });
  expect(update.status).toBe(200);
  const login = await ctx.actor("changed").client.signIn.email({ email, password: changed });
  expect(login.error).toBeNull();
  const previous = await ctx.actor("previous").client.signIn.email({ email, password: initial });
  expect(previous.error?.status).toBe(401);
  const requested = await post(ctx, "/request-password-reset", { email });
  expect(requested.status).toBe(200);
  const sent = await fetch(`${ctx.baseURL}/__test/reset-password-token?email=${encodeURIComponent(email)}`).then(response => response.json());
  const shortReset = await post(ctx, "/reset-password", { token: sent.token, newPassword: "Short123!" });
  expect(shortReset.status).toBe(400);
  expect(shortReset.body).toMatchObject({ code: "PASSWORD_TOO_SHORT" });
  const longReset = await post(ctx, "/reset-password", { token: sent.token, newPassword: "X".repeat(25) });
  expect(longReset.status).toBe(400);
  expect(longReset.body).toMatchObject({ code: "PASSWORD_TOO_LONG" });
  const updated = await post(ctx, "/reset-password", { token: sent.token, newPassword: reset });
  expect(updated.status).toBe(200);
  const resetLogin = await ctx.actor("reset").client.signIn.email({ email, password: reset });
  expect(resetLogin.error).toBeNull();
  const replay = await post(ctx, "/reset-password", { token: sent.token, newPassword: changed });
  expect(replay.status).toBe(400);
  return { longLogin: ctx.snapshot(longLogin), tooShort, tooLong, longCurrent, update, login: ctx.snapshot(login), previous: ctx.snapshot(previous), shortReset, longReset, updated, resetLogin: ctx.snapshot(resetLogin), replay };
});
