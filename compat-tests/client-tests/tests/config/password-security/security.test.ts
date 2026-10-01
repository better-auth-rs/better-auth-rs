import { expect } from "bun:test";
import { createHash } from "node:crypto";
import { compatScenario } from "../../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
const profile = process.env.COMPAT_PROFILE;
if (!profile?.startsWith("password-security")) throw new Error("Password security profile must be explicit");
const defaultPaths = profile === "password-security" || profile === "password-security-after";
const changeChecked = defaultPaths || profile === "password-security-custom";
const unsafe = "Compromised123!";
const initial = "OriginalPassword123!";
const digest = (password: string) => createHash("sha1").update(password).digest("hex").toUpperCase();
async function control(ctx: Context, body: object) {
  const response = await fetch(`${ctx.baseURL}/__test/password-security`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}
const configure = (ctx: Context, password = unsafe, count = "1") => control(ctx, { action: "configure", body: `${digest(password).slice(5)}:${count}\r\n${"0".repeat(35)}:0` });
const post = (ctx: Context, path: string, json: object) => ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json });

compatScenario("HIBP helper uses real range HTTP, raw Unicode SHA1, strict counts, and fail-closed errors", async ctx => {
  const password = "Ｆｕｌｌ123!😀";
  await configure(ctx, password);
  const hit = await control(ctx, { action: "check", password });
  expect(hit).toEqual({ status: 200, body: { compromised: true } });
  const trace = (await control(ctx, {})).body;
  expect(trace).toEqual({ hashes: [], requests: [{ prefix: digest(password).slice(0, 5), padding: "true", agent: "BetterAuth Password Checker" }] });
  expect(digest(password)).not.toBe(digest(password.normalize("NFKC")));
  await configure(ctx, password, "0");
  expect((await control(ctx, { action: "check", password })).body).toEqual({ compromised: false });
  const failures = [];
  for (const count of ["01", "1.0", "-1", "9007199254740992"]) {
    await configure(ctx, password, count);
    const response = await control(ctx, { action: "check", password });
    expect(response).toEqual({ status: 500, body: { message: "Failed to check password. Please try again later." } });
    failures.push(response);
  }
  for (const count of ["0\r", "1\r"]) {
    await control(ctx, { action: "configure", body: `${digest(password).slice(5)}:${count}` });
    const response = await control(ctx, { action: "check", password });
    expect(response).toEqual({ status: 500, body: { message: "Failed to check password. Please try again later." } });
    failures.push(response);
  }
  await control(ctx, { action: "configure", status: 503 });
  const unavailable = await control(ctx, { action: "check", password });
  expect(unavailable).toEqual({ status: 500, body: { message: "Failed to check password. Status: 503" } });
  await control(ctx, { action: "configure", drop: true });
  const network = await control(ctx, { action: "check", password });
  expect(network).toEqual({ status: 500, body: { message: "Failed to check password. Please try again later." } });
  return { hit, trace, failures, unavailable, network };
});

compatScenario("HIBP wraps the selected hasher independent of plugin order and keeps password operation ordering", async ctx => {
  await control(ctx, { action: "configure" });
  const email = ctx.uniqueEmail("hibp");
  expect((await ctx.actor().client.signUp.email({ email, password: initial, name: "HIBP" })).error).toBeNull();
  await configure(ctx);
  const newEmail = ctx.uniqueEmail("compromised");
  const signup = await post(ctx, "/sign-up/email", { email: newEmail, password: unsafe, name: "Compromised" });
  expect(signup.status).toBe(defaultPaths ? 400 : 200);
  const signupState = (await control(ctx, {})).body;
  expect(signupState.hashes).toEqual(defaultPaths ? [] : [unsafe]);
  expect(signupState.requests).toHaveLength(defaultPaths ? 1 : 0);
  expect((await control(ctx, { action: "read", email: newEmail })).body.user).toBe(!defaultPaths);
  if (defaultPaths) expect(signup.body).toMatchObject({ code: "PASSWORD_COMPROMISED" });

  // Restore the original actor after profiles that accept the second signup.
  await ctx.actor().client.signIn.email({ email, password: initial });
  await configure(ctx);
  const changed = await post(ctx, "/change-password", { currentPassword: "WrongPassword123!", newPassword: unsafe });
  expect(changed.status).toBe(400);
  expect(changed.body).toMatchObject({ code: changeChecked ? "PASSWORD_COMPROMISED" : "INVALID_PASSWORD" });
  if (profile === "password-security-custom") expect(changed.body).toEqual({ code: "PASSWORD_COMPROMISED", message: "Choose another password" });
  const changedState = (await control(ctx, {})).body;
  expect(changedState.hashes).toEqual(changeChecked ? [] : [unsafe]);
  expect(changedState.requests).toHaveLength(changeChecked ? 1 : 0);

  await configure(ctx);
  const token = ctx.uniqueToken("hibp-reset");
  await ctx.seedResetPasswordToken({ email, token, expiresAt: new Date(Date.now() + 60_000).toISOString() });
  const reset = await post(ctx, "/reset-password", { token, newPassword: unsafe });
  expect(reset.status).toBe(defaultPaths ? 400 : 200);
  if (defaultPaths) expect(reset.body).toMatchObject({ code: "PASSWORD_COMPROMISED" });
  const resetState = (await control(ctx, {})).body;
  expect(resetState.hashes).toEqual(defaultPaths ? [] : [unsafe]);
  expect(resetState.requests).toHaveLength(defaultPaths ? 1 : 0);
  const replay = await post(ctx, "/reset-password", { token, newPassword: initial });
  expect(replay.status).toBe(400);
  expect(replay.body).toMatchObject({ code: "INVALID_TOKEN" });
  const login = await ctx.actor("proof").client.signIn.email({ email, password: defaultPaths ? initial : unsafe });
  expect(login.error).toBeNull();
  await configure(ctx);
  const missing = await ctx.actor("missing").client.signIn.email({ email: ctx.uniqueEmail("missing"), password: unsafe });
  expect(missing.error?.status).toBe(profile === "password-security-custom" ? 400 : 401);
  const missingState = (await control(ctx, {})).body;
  expect(missingState.hashes).toEqual(profile === "password-security-custom" ? [] : [unsafe]);
  expect(missingState.requests).toHaveLength(profile === "password-security-custom" ? 1 : 0);
  return { signup, signupState, changed, changedState, reset, resetState, replay, login: ctx.snapshot(login), missing: ctx.snapshot(missing), missingState };
}, 30_000);

compatScenario("admin creation preserves upstream user insertion before compromised-password rejection", async ctx => {
  await control(ctx, { action: "configure" });
  const email = ctx.uniqueEmail("admin");
  expect((await ctx.actor().client.signUp.email({ email, name: "Admin", password: initial })).error).toBeNull();
  await ctx.promoteAdmin({ email });
  await configure(ctx);
  const target = ctx.uniqueEmail("admin-created");
  const created = await post(ctx, "/admin/create-user", { email: target, name: "Target", password: unsafe });
  expect(created.status).toBe(defaultPaths ? 400 : 200);
  const state = (await control(ctx, {})).body;
  expect(state.hashes).toEqual(defaultPaths ? [] : [unsafe]);
  const account = (await control(ctx, { action: "read", email: target })).body;
  expect(account.user).toBe(true);
  expect(account.hash === null).toBe(defaultPaths);
  return { created, state, credentialPresent: account.hash !== null };
}, 30_000);
