import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { control, error, post, send, signup } from "./helpers";

compatScenario("email OTP creates an account once and authenticates its cookie", async (ctx) => {
  const email = ctx.uniqueEmail("otp-signin");
  const otp = await send(ctx, email.toUpperCase(), "sign-in");
  const first = await post(ctx, "/sign-in/email-otp", { email, otp, name: "OTP New User", image: "https://example.com/avatar.png" });
  expect(first.status).toBe(200);
  expect(first.body).toMatchObject({ user: { email, emailVerified: true, name: "OTP New User" } });
  const session = await ctx.actor().client.getSession();
  expect(session.data?.user.id).toBe((first.body as any).user.id);
  const replay = await post(ctx, "/sign-in/email-otp", { email, otp });
  error(replay, 400, "INVALID_OTP");
  return { first, session, replay };
});

compatScenario("email OTP applies enabled plugin input fields and user creation constraints", async (ctx) => {
  const email = ctx.uniqueEmail("otp-fields");
  const otp = await send(ctx, email, "sign-in");
  const created = await post(ctx, "/sign-in/email-otp", { email, otp, username: "OTP_USERNAME", displayUsername: "Visible Name", phoneNumber: "+15550000001", banned: true });
  expect(created.status, JSON.stringify(created.body)).toBe(200);
  expect((created.body as any).user).toMatchObject({ username: "otp_username", displayUsername: "Visible Name", banned: false, role: "user" });
  expect((created.body as any).user).not.toHaveProperty("phoneNumber");
  const displayEmail = ctx.uniqueEmail("otp-display");
  const displayOtp = await send(ctx, displayEmail, "sign-in");
  const display = await post(ctx, "/sign-in/email-otp", { email: displayEmail, otp: displayOtp, displayUsername: "Display Only" });
  expect(display.status).toBe(200);
  expect((display.body as any).user).toMatchObject({ username: null, displayUsername: "Display Only" });
  const protectedEmail = ctx.uniqueEmail("otp-protected");
  const protectedOtp = await send(ctx, protectedEmail, "sign-in");
  const denied = await post(ctx, "/sign-in/email-otp", { email: protectedEmail, otp: protectedOtp, role: "admin" });
  expect(denied.status).toBe(400);
  expect(denied.body).toEqual({ code: "FIELD_NOT_ALLOWED", message: "role is not allowed to be set" });
  const replay = await post(ctx, "/sign-in/email-otp", { email: protectedEmail, otp: protectedOtp });
  error(replay, 400, "INVALID_OTP");
  const shortEmail = ctx.uniqueEmail("otp-short-username");
  const shortOtp = await send(ctx, shortEmail, "sign-in");
  const short = await post(ctx, "/sign-in/email-otp", { email: shortEmail, otp: shortOtp, username: "AB" });
  error(short, 400, "USERNAME_TOO_SHORT");
  const takenEmail = ctx.uniqueEmail("otp-taken-username");
  const takenOtp = await send(ctx, takenEmail, "sign-in");
  const taken = await post(ctx, "/sign-in/email-otp", { email: takenEmail, otp: takenOtp, username: "OTP_USERNAME" });
  error(taken, 400, "USERNAME_IS_ALREADY_TAKEN");
  return { created, display, denied, replay, short, taken };
});

compatScenario("email OTP removes unproven password links and standing sessions", async (ctx) => {
  const email = ctx.uniqueEmail("otp-takeover");
  const original = await signup(ctx, email, "attacker");
  const otp = await send(ctx, email, "sign-in");
  const signin = await post(ctx, "/sign-in/email-otp", { email, otp });
  expect(signin.status).toBe(200);
  expect((signin.body as any).user.id).toBe(original.user.id);
  const stale = await ctx.actor("attacker").client.getSession();
  expect(stale.data).toBeNull();
  const password = await ctx.actor("password").client.signIn.email({ email, password: "Password123!" });
  expect(password.error?.status).toBe(401);
  const session = await ctx.actor().client.getSession();
  expect(session.data?.user.emailVerified).toBe(true);
  return { signin, stale, password, session };
});

compatScenario("email OTP verification checks are reusable but successful verification consumes the code", async (ctx) => {
  const email = ctx.uniqueEmail("otp-verify");
  await signup(ctx, email);
  const otp = await send(ctx, email, "email-verification");
  const checks = [];
  for (let i = 0; i < 2; i++) {
    const check = await post(ctx, "/email-otp/check-verification-otp", { email, otp, type: "email-verification" });
    expect(check.status).toBe(200); checks.push(check);
  }
  const verified = await post(ctx, "/email-otp/verify-email", { email: email.toUpperCase(), otp });
  expect(verified.status).toBe(200);
  expect(verified.body).toMatchObject({ status: true, token: null, user: { email, emailVerified: true } });
  const replay = await post(ctx, "/email-otp/verify-email", { email, otp });
  error(replay, 400, "INVALID_OTP");
  const password = await ctx.actor("password").client.signIn.email({ email, password: "Password123!" });
  expect(password.error).toBeNull();
  return { checks, verified, replay, password };
});

compatScenario("email OTP failures share the attempt budget and enforce expiry", async (ctx) => {
  const email = ctx.uniqueEmail("otp-attempt");
  await signup(ctx, email);
  const otp = await send(ctx, email, "email-verification");
  const failures = [];
  for (let i = 0; i < 3; i++) {
    const response = await post(ctx, i % 2 ? "/email-otp/verify-email" : "/email-otp/check-verification-otp", { email, otp: "invalid", type: "email-verification" });
    error(response, 400, "INVALID_OTP"); failures.push(response);
  }
  const exhausted = await post(ctx, "/email-otp/verify-email", { email, otp });
  error(exhausted, 403, "TOO_MANY_ATTEMPTS");
  const consumed = await post(ctx, "/email-otp/verify-email", { email, otp });
  error(consumed, 400, "INVALID_OTP");
  const renewed = await send(ctx, email, "email-verification");
  await control(ctx, { action: "expire", email, type: "email-verification" });
  const expired = await post(ctx, "/email-otp/verify-email", { email, otp: renewed });
  error(expired, 400, "OTP_EXPIRED");
  return { failures, exhausted, consumed, expired };
});

compatScenario("email OTP password reset supports both request routes and consumes only after validation", async (ctx) => {
  const email = ctx.uniqueEmail("otp-reset");
  await signup(ctx, email);
  const observations = [];
  for (const path of ["/forget-password/email-otp", "/email-otp/request-password-reset"]) {
    const request = await post(ctx, path, { email });
    expect(request.status).toBe(200);
    const messages = await control(ctx, { email });
    const otp = messages.at(-1).otp;
    const short = await post(ctx, "/email-otp/reset-password", { email, otp, password: "short" });
    error(short, 400, "PASSWORD_TOO_SHORT");
    const reset = await post(ctx, "/email-otp/reset-password", { email, otp, password: "NewPassword123!" });
    expect(reset.status).toBe(200);
    expect(reset.body).toEqual({ success: true });
    const replay = await post(ctx, "/email-otp/reset-password", { email, otp, password: "OtherPassword123!" });
    error(replay, 400, "INVALID_OTP");
    observations.push({ request, short, reset, replay });
  }
  const oldPassword = await ctx.actor("old").client.signIn.email({ email, password: "Password123!" });
  expect(oldPassword.error?.status).toBe(401);
  const newPassword = await ctx.actor("new").client.signIn.email({ email, password: "NewPassword123!" });
  expect(newPassword.error).toBeNull();
  expect(newPassword.data?.user.emailVerified).toBe(true);
  return { observations, oldPassword, newPassword };
});

compatScenario("email OTP change email binds both addresses and requires current mailbox proof", async (ctx) => {
  const email = ctx.uniqueEmail("otp-change");
  const newEmail = ctx.uniqueEmail("otp-new");
  await signup(ctx, email);
  const missing = await post(ctx, "/email-otp/request-email-change", { newEmail });
  expect(missing.status).toBe(400);
  expect(missing.body).toEqual({ message: "OTP is required to verify current email" });
  const currentOtp = await send(ctx, email, "email-verification");
  const request = await post(ctx, "/email-otp/request-email-change", { newEmail, otp: currentOtp });
  expect(request.status).toBe(200);
  const message = (await control(ctx, { email: newEmail })).at(-1);
  expect(message.type).toBe("change-email");
  const wrongDestination = await post(ctx, "/email-otp/change-email", { newEmail: ctx.uniqueEmail("different"), otp: message.otp });
  error(wrongDestination, 400, "INVALID_OTP");
  const outsider = await post(ctx, "/email-otp/change-email", { newEmail, otp: message.otp }, "outsider");
  error(outsider, 401, "UNAUTHORIZED");
  const changed = await post(ctx, "/email-otp/change-email", { newEmail, otp: message.otp });
  expect(changed.status).toBe(200);
  const session = await ctx.actor().client.getSession();
  expect(session.data?.user.email).toBe(newEmail);
  expect(session.data?.user.emailVerified).toBe(true);
  return { missing, request, wrongDestination, outsider, changed, session };
});

compatScenario("email OTP does not reveal unknown users or allow change-email through public send", async (ctx) => {
  const email = ctx.uniqueEmail("otp-unknown");
  const observations = [];
  for (const type of ["email-verification", "forget-password"]) {
    const response = await post(ctx, "/email-otp/send-verification-otp", { email, type });
    expect(response.status).toBe(200);
    expect(await control(ctx, { email })).toEqual([]);
    observations.push(response);
  }
  const reset = await post(ctx, "/email-otp/request-password-reset", { email });
  expect(reset.status).toBe(200);
  const prohibited = await post(ctx, "/email-otp/send-verification-otp", { email, type: "change-email" });
  expect(prohibited.status).toBe(400);
  expect(prohibited.body).toEqual({ message: "Invalid OTP type" });
  const invalidEmail = await post(ctx, "/email-otp/send-verification-otp", { email: "invalid", type: "sign-in" });
  error(invalidEmail, 400, "INVALID_EMAIL");
  const invalidBody = await post(ctx, "/email-otp/check-verification-otp", { email: 1, type: "other", otp: null });
  error(invalidBody, 400, "VALIDATION_ERROR");
  return { observations, reset, prohibited, invalidEmail, invalidBody };
});

compatScenario("one email OTP admits at most one concurrent sign-in", async (ctx) => {
  const email = ctx.uniqueEmail("otp-concurrent");
  const otp = await send(ctx, email, "sign-in");
  const attempts = await Promise.all([0, 1].map(() => fetch(`${ctx.baseURL}/api/auth/sign-in/email-otp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, otp }) })));
  const statuses = attempts.map(response => response.status).sort();
  expect(statuses).toEqual([200, 400]);
  return { statuses };
});

compatScenario("email OTP delivery failures retain the generic response and a later delivery can authenticate", async (ctx) => {
  const email = ctx.uniqueEmail("otp-delivery");
  await control(ctx, { action: "fail", fail: true });
  const failed = await post(ctx, "/email-otp/send-verification-otp", { email, type: "sign-in" });
  expect(failed.status).toBe(200);
  expect(failed.body).toEqual({ success: true });
  expect(await control(ctx, { email })).toEqual([]);
  await control(ctx, { action: "fail", fail: false });
  // Upstream orders verification records by millisecond timestamps; the retry must be later.
  await Bun.sleep(2);
  const otp = await send(ctx, email, "sign-in");
  const signedIn = await post(ctx, "/sign-in/email-otp", { email, otp });
  expect(signedIn.status).toBe(200);
  expect((signedIn.body as any).user.emailVerified).toBe(true);
  return { failed, signedIn };
});

compatScenario("email OTP verification override preserves an explicitly configured sender", async (ctx) => {
  const email = ctx.uniqueEmail("otp-explicit-sender");
  await signup(ctx, email);
  const sent = await ctx.actor().client.sendVerificationEmail({ email });
  expect(sent.error).toBeNull();
  expect(await control(ctx, { email })).toEqual([]);
  const record = await ctx.readVerificationEmail({ email }) as { token: string };
  expect(record.token).toBeString();
  const verified = await ctx.actor().client.verifyEmail({ query: { token: record.token } });
  expect(verified.error).toBeNull();
  return { sent, verified };
});
